#include "brovfs/usage.h"

#include "brovfs/path.h"
#include "src/walk.h"

#include <algorithm>
#include <condition_variable>
#include <cctype>
#include <deque>
#include <mutex>
#include <thread>

namespace bro::vfs {

namespace {

constexpr uint32_t kNone = 0xFFFFFFFFu;

// A file (or link, or other non-directory) of a directory: its name lives in the directory's
// name pool.
struct FileRec {
    uint32_t name_off = 0;
    uint32_t name_len = 0;
    uint64_t size = 0;
    int64_t mtime_ms = 0;
    FileKind kind = FileKind::Regular;
    bool hidden = false;
};

struct DirNode {
    std::string name;
    uint32_t parent = kNone;
    uint64_t bytes = 0;       // subtree
    uint64_t files = 0;       // subtree
    uint64_t directories = 0; // subtree, this one excluded
    uint64_t pending = 1;     // directories of the subtree (this one included) not yet listed
    int64_t mtime_ms = 0;
    bool hidden = false;
    bool removed = false;
    std::vector<uint32_t> subdirs;
    std::vector<FileRec> files_here;
    std::string names; // pool for files_here
};

#ifdef _WIN32
bool same_name(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        unsigned char x = static_cast<unsigned char>(a[i]), y = static_cast<unsigned char>(b[i]);
        if (x == y) continue;
        if (x < 0x80 && y < 0x80 && std::tolower(x) == std::tolower(y)) continue;
        return false;
    }
    return true;
}
#else
bool same_name(const std::string& a, const std::string& b) { return a == b; }
#endif

class Usage final : public UsageScan {
public:
    Usage(fs::path root, UsageOptions opt) : root_(strip_trailing_separators(root)), opt_(opt) {
        start_ = std::chrono::steady_clock::now();
        DirNode r;
        r.name = path_to_utf8(root_);
        nodes_.push_back(std::move(r));
        queue_.push_back(0);
        unsigned n = opt_.threads ? opt_.threads : std::min(4u, std::max(1u, std::thread::hardware_concurrency()));
        busy_ = 0;
        for (unsigned i = 0; i < n; ++i) threads_.emplace_back([this] { work(); });
    }

    ~Usage() override {
        cancel();
        for (auto& t : threads_) {
            if (t.joinable()) t.join();
        }
    }

    void cancel() override {
        token_.cancel();
        std::lock_guard<std::mutex> lock(mutex_);
        work_cv_.notify_all();
    }

    UsageProgress progress() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return progress_locked();
    }

    UsageProgress wait() override {
        std::unique_lock<std::mutex> lock(mutex_);
        done_cv_.wait(lock, [&] { return done_; });
        return progress_locked();
    }

    fs::path root() const override { return root_; }

    bool children(const fs::path& dir, std::vector<UsageItem>& out, UsageSort sort, size_t limit) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mutex_);
        uint32_t d;
        const FileRec* f;
        if (!find_locked(dir, d, f) || f) return false;
        const DirNode& n = nodes_[d];
        fs::path base = node_path_locked(d);
        out.reserve(n.subdirs.size() + n.files_here.size());
        for (uint32_t c : n.subdirs) out.push_back(dir_item_locked(c, base / path_from_utf8(nodes_[c].name)));
        for (const auto& fr : n.files_here) {
            std::string name = n.names.substr(fr.name_off, fr.name_len);
            fs::path p = base / path_from_utf8(name);
            out.push_back(file_item(fr, std::move(name), std::move(p)));
        }
        auto by_bytes = [](const UsageItem& a, const UsageItem& b) {
            if (a.bytes != b.bytes) return a.bytes > b.bytes;
            return a.name < b.name;
        };
        auto by_name = [](const UsageItem& a, const UsageItem& b) { return a.name < b.name; };
        if (limit && limit < out.size()) {
            if (sort == UsageSort::Bytes)
                std::partial_sort(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(limit), out.end(), by_bytes);
            else
                std::partial_sort(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(limit), out.end(), by_name);
            out.resize(limit);
        } else if (sort == UsageSort::Bytes) {
            std::sort(out.begin(), out.end(), by_bytes);
        } else {
            std::sort(out.begin(), out.end(), by_name);
        }
        return true;
    }

    bool entry(const fs::path& p, UsageItem& out) const override {
        std::lock_guard<std::mutex> lock(mutex_);
        uint32_t d;
        const FileRec* f;
        if (!find_locked(p, d, f)) return false;
        if (f) {
            const DirNode& n = nodes_[d];
            std::string name = n.names.substr(f->name_off, f->name_len);
            out = file_item(*f, name, node_path_locked(d) / path_from_utf8(name));
        } else {
            out = dir_item_locked(d, node_path_locked(d));
        }
        return true;
    }

    bool remove(const fs::path& p) override {
        std::lock_guard<std::mutex> lock(mutex_);
        uint32_t d;
        const FileRec* f;
        if (!find_locked(p, d, f)) return false;
        DirNode& n = nodes_[d];
        if (f) {
            for (uint32_t a = d; a != kNone; a = nodes_[a].parent) {
                nodes_[a].bytes -= f->size;
                nodes_[a].files -= 1;
            }
            n.files_here.erase(n.files_here.begin() + (f - n.files_here.data()));
            ++version_;
            return true;
        }
        if (d == 0) return false; // the root itself: cancel the scan instead
        uint64_t bytes = n.bytes, files = n.files, dirs = n.directories + 1, pending = n.pending;
        n.removed = true;
        auto& sibs = nodes_[n.parent].subdirs;
        sibs.erase(std::remove(sibs.begin(), sibs.end(), d), sibs.end());
        for (uint32_t a = n.parent; a != kNone; a = nodes_[a].parent) {
            nodes_[a].bytes -= bytes;
            nodes_[a].files -= files;
            nodes_[a].directories -= dirs;
            nodes_[a].pending -= pending;
        }
        ++version_;
        maybe_done_locked();
        return true;
    }

    std::vector<ScanError> errors() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return errors_;
    }

private:
    UsageProgress progress_locked() const {
        UsageProgress p;
        const DirNode& r = nodes_[0];
        p.files = r.files;
        p.directories = r.directories;
        p.bytes = r.bytes;
        p.errors = error_count_;
        p.version = version_;
        p.cancelled = done_ && token_.is_cancelled();
        p.finished = done_ && !p.cancelled;
        auto end = done_ ? end_ : std::chrono::steady_clock::now();
        p.elapsed_ms = std::chrono::duration<double, std::milli>(end - start_).count();
        return p;
    }

    fs::path node_path_locked(uint32_t d) const {
        std::vector<uint32_t> chain;
        for (uint32_t a = d; a != 0 && a != kNone; a = nodes_[a].parent) chain.push_back(a);
        fs::path p = root_;
        for (auto it = chain.rbegin(); it != chain.rend(); ++it) p /= path_from_utf8(nodes_[*it].name);
        return p;
    }

    UsageItem dir_item_locked(uint32_t d, fs::path p) const {
        const DirNode& n = nodes_[d];
        UsageItem it;
        it.name = d == 0 ? path_to_utf8(root_) : n.name;
        it.path = std::move(p);
        it.kind = FileKind::Directory;
        it.bytes = n.bytes;
        it.files = n.files;
        it.directories = n.directories;
        it.children = n.subdirs.size() + n.files_here.size();
        it.mtime_ms = n.mtime_ms;
        it.hidden = n.hidden;
        it.complete = n.pending == 0;
        return it;
    }

    static UsageItem file_item(const FileRec& f, std::string name, fs::path p) {
        UsageItem it;
        it.name = std::move(name);
        it.path = std::move(p);
        it.kind = f.kind;
        it.bytes = f.size;
        it.files = 1;
        it.mtime_ms = f.mtime_ms;
        it.hidden = f.hidden;
        return it;
    }

    // `p` as a directory node (f = null) or as a file record of directory `d`.
    bool find_locked(const fs::path& p, uint32_t& d, const FileRec*& f) const {
        f = nullptr;
        fs::path rel = strip_trailing_separators(p).lexically_normal().lexically_relative(root_.lexically_normal());
        if (rel.empty() && strip_trailing_separators(p).lexically_normal() != root_.lexically_normal()) return false;
        d = 0;
        std::vector<std::string> parts;
        for (const auto& c : rel) {
            std::string s = path_to_utf8(c);
            if (s.empty() || s == ".") continue;
            if (s == "..") return false;
            parts.push_back(std::move(s));
        }
        for (size_t i = 0; i < parts.size(); ++i) {
            const DirNode& n = nodes_[d];
            uint32_t next = kNone;
            for (uint32_t c : n.subdirs) {
                if (nodes_[c].name == parts[i]) { next = c; break; }
            }
            if (next == kNone) {
                for (uint32_t c : n.subdirs) {
                    if (same_name(nodes_[c].name, parts[i])) { next = c; break; }
                }
            }
            if (next != kNone) {
                d = next;
                continue;
            }
            if (i + 1 != parts.size()) return false;
            for (const auto& fr : n.files_here) {
                if (fr.name_len == parts[i].size() &&
                    same_name(n.names.substr(fr.name_off, fr.name_len), parts[i])) {
                    f = &fr;
                    return true;
                }
            }
            return false;
        }
        return true;
    }

    bool detached_locked(uint32_t d) const {
        for (uint32_t a = d; a != kNone; a = nodes_[a].parent) {
            if (nodes_[a].removed) return true;
        }
        return false;
    }

    void error_locked(const fs::path& p, const std::error_code& ec) {
        ++error_count_;
        if (errors_.size() < 100) errors_.push_back({p, ec});
    }

    void maybe_done_locked() {
        if (done_) return;
        bool drained = queue_.empty() && busy_ == 0;
        if (drained || (token_.is_cancelled() && busy_ == 0)) {
            done_ = true;
            end_ = std::chrono::steady_clock::now();
            ++version_;
            work_cv_.notify_all();
            done_cv_.notify_all();
        }
    }

    struct Listed {
        std::string name;
        sys::Stat st;
        bool hidden = false;
    };

    void work() {
        std::vector<Listed> dirs;
        for (;;) {
            uint32_t d;
            fs::path path;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                work_cv_.wait(lock, [&] { return done_ || token_.is_cancelled() || !queue_.empty(); });
                if (done_ || token_.is_cancelled()) {
                    maybe_done_locked();
                    return;
                }
                d = queue_.back(); // depth-first: the tree's left side fills in first
                queue_.pop_back();
                if (detached_locked(d)) {
                    maybe_done_locked();
                    continue;
                }
                ++busy_;
                path = node_path_locked(d);
            }

            // Everything about this listing is built before the lock is taken, so readers on
            // the UI thread only ever wait for the cheap attach below.
            dirs.clear();
            std::vector<FileRec> recs;
            std::string names;
            uint64_t bytes = 0;
            std::error_code ec;
            std::vector<std::pair<fs::path, std::error_code>> entry_errors;
            sys::list_dir(
                path,
                [&](sys::RawEntry&& e) {
                    if (token_.is_cancelled()) return false;
                    if (e.stat_error) {
                        entry_errors.emplace_back(path / e.name, e.stat_error);
                        return true;
                    }
                    bool hidden = detail::is_hidden(e.name_utf8, e.st);
                    if (hidden && !opt_.include_hidden) return true;
                    if (e.st.kind == FileKind::Directory) {
                        dirs.push_back(Listed{std::move(e.name_utf8), e.st, hidden});
                        return true;
                    }
                    // A link holds none of its target's bytes. POSIX lstat sizes a symlink
                    // by the length of the path it names, Windows sizes a reparse point 0;
                    // both count as 0 so a tree totals the same everywhere.
                    const bool link = e.st.kind == FileKind::Symlink || e.st.kind == FileKind::Junction;
                    FileRec fr;
                    fr.name_off = static_cast<uint32_t>(names.size());
                    fr.name_len = static_cast<uint32_t>(e.name_utf8.size());
                    fr.size = link ? 0 : e.st.size;
                    fr.mtime_ms = e.st.mtime_ns / 1000000;
                    fr.kind = e.st.kind;
                    fr.hidden = hidden;
                    names += e.name_utf8;
                    recs.push_back(fr);
                    bytes += fr.size;
                    return true;
                },
                ec);
            recs.shrink_to_fit();
            names.shrink_to_fit();
            uint64_t new_files = recs.size();

            std::lock_guard<std::mutex> lock(mutex_);
            --busy_;
            for (auto& [p, e] : entry_errors) error_locked(p, e);
            if (ec && !token_.is_cancelled()) error_locked(path, ec);
            if (detached_locked(d)) {
                maybe_done_locked();
                continue;
            }
            nodes_[d].files_here = std::move(recs);
            nodes_[d].names = std::move(names);
            for (auto& dl : dirs) {
                DirNode c;
                c.name = std::move(dl.name);
                c.parent = d;
                c.mtime_ms = dl.st.mtime_ns / 1000000;
                c.hidden = dl.hidden;
                auto idx = static_cast<uint32_t>(nodes_.size());
                nodes_.push_back(std::move(c));
                nodes_[d].subdirs.push_back(idx);
                queue_.push_back(idx);
            }
            // This directory is listed (pending -1); its new subdirectories are not (+each).
            uint64_t new_dirs = dirs.size();
            for (uint32_t a = d; a != kNone; a = nodes_[a].parent) {
                DirNode& an = nodes_[a];
                an.bytes += bytes;
                an.files += new_files;
                an.directories += new_dirs;
                an.pending = an.pending + new_dirs - 1;
            }
            ++version_;
            if (!dirs.empty()) work_cv_.notify_all();
            maybe_done_locked();
        }
    }

    fs::path root_;
    UsageOptions opt_;
    CancellationToken token_;
    std::chrono::steady_clock::time_point start_, end_;
    mutable std::mutex mutex_;
    std::condition_variable work_cv_, done_cv_;
    std::deque<DirNode> nodes_; // never relocated: growing a vector of 400k nodes stalls readers
    std::vector<uint32_t> queue_;
    unsigned busy_ = 0;
    bool done_ = false;
    uint64_t version_ = 0;
    uint64_t error_count_ = 0;
    std::vector<ScanError> errors_;
    std::vector<std::thread> threads_;
};

} // namespace

std::unique_ptr<UsageScan> start_usage_scan(fs::path root, UsageOptions options) {
    return std::make_unique<Usage>(std::move(root), options);
}

} // namespace bro::vfs
