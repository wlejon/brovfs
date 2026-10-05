// macOS trash: NSFileManager moves the item (trash_macos_ns.mm); restore information lives in
// xattrs on the item itself, and a journal of stored paths keeps brovfs's own items listable
// when the trash folder cannot be enumerated (no Full Disk Access). See brovfs/trash.h.
#ifdef __APPLE__

#include "brovfs/file_ops.h"
#include "brovfs/path.h"
#include "brovfs/trash.h"
#include "src/ds_store.h"
#include "src/engine.h"
#include "src/trash_macos.h"

#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <sys/file.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace bro::vfs {

namespace {

constexpr const char* kPutback = "com.bro.vfs.putback";
constexpr const char* kTrashed = "com.bro.vfs.trashed";

std::error_code errno_ec(int e) { return {e, std::system_category()}; }

bool get_x(const fs::path& p, const char* name, std::string& out) {
    ssize_t n = ::getxattr(p.c_str(), name, nullptr, 0, 0, XATTR_NOFOLLOW);
    if (n < 0) return false;
    out.assign(static_cast<size_t>(n), '\0');
    n = ::getxattr(p.c_str(), name, out.data(), out.size(), 0, XATTR_NOFOLLOW);
    if (n < 0) return false;
    out.resize(static_cast<size_t>(n));
    return true;
}

bool set_x(const fs::path& p, const char* name, const std::string& v, std::error_code& ec) {
    if (::setxattr(p.c_str(), name, v.data(), v.size(), 0, XATTR_NOFOLLOW) == 0) return true;
    ec = errno_ec(errno);
    return false;
}

void rm_x(const fs::path& p) {
    ::removexattr(p.c_str(), kPutback, XATTR_NOFOLLOW);
    ::removexattr(p.c_str(), kTrashed, XATTR_NOFOLLOW);
}

// Journal lines are stored paths with '%' and '\n' percent-encoded.
std::string encode_line(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '%') {
            out += "%25";
        } else if (c == '\n') {
            out += "%0A";
        } else {
            out += c;
        }
    }
    return out;
}

std::string decode_line(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            out += static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16));
            i += 2;
        } else {
            out += s[i];
        }
    }
    return out;
}

class MacTrash final : public Trash {
public:
    explicit MacTrash(MacTrashConfig cfg) : cfg_(std::move(cfg)), uid_(std::to_string(::getuid())) {
        home_trash_ = detail::ns_home_trash();
        if (cfg_.journal.empty()) {
            const char* home = std::getenv("HOME");
            cfg_.journal = fs::path(home ? home : "") / "Library" / "Application Support" / "brovfs" / "trash-journal";
        }
    }

    bool trash(const fs::path& path_in, std::string* out_id, std::error_code& ec) override {
        ec.clear();
        fs::path p = fs::absolute(strip_trailing_separators(path_in), ec);
        if (ec) return false;
        p = p.lexically_normal();
        if (leaf_name(p).empty()) {
            ec = make_error_code(Errc::invalid_argument);
            return false;
        }
        sys::Stat st;
        if (!sys::lstat(p, st, ec)) return false;
        if (in_a_trash(p)) {
            ec = make_error_code(Errc::invalid_argument); // never trash the trash
            return false;
        }
        bool via_finder = false;
        if (cfg_.finder != FinderTrash::Never) {
            via_finder = detail::finder_permission(cfg_.ask_finder_permission) == 0;
            if (!via_finder && cfg_.finder == FinderTrash::Require) {
                ec = std::make_error_code(std::errc::operation_not_permitted);
                return false;
            }
        }
        // Restore data first: an item is never in the trash without a way back.
        if (!set_x(p, kPutback, p.native(), ec) || !set_x(p, kTrashed, std::to_string(sys::now_unix_ms()), ec)) {
            rm_x(p);
            return false;
        }
        // Journal the name the trash will most likely give it before moving, so a crash
        // right after the move still leaves the item findable (a wrong guess is pruned).
        fs::path tdir = detail::ns_trash_for(p);
        fs::path predicted = tdir.empty() ? fs::path() : tdir / leaf_name(p);
        if (!predicted.empty()) journal_add(predicted);
        fs::path stored;
        bool moved = via_finder ? detail::finder_trash_item(p, stored, ec) : detail::ns_trash_item(p, stored, ec);
        if (!moved) {
            rm_x(p);
            return false;
        }
        if (stored.empty()) {
            // Finder did not name the result: accept the predicted name only if it is this item.
            std::string orig;
            if (predicted.empty() || !get_x(predicted, kPutback, orig) || orig != p.native()) {
                ec = make_error_code(Errc::trash_info_invalid); // moved; list() still finds it
                return false;
            }
            stored = predicted;
        }
        if (stored != predicted) journal_add(stored);
        if (out_id) *out_id = stored.native();
        return true;
    }

    std::vector<TrashItem> list(std::vector<ItemError>* errors) override {
        std::vector<TrashItem> out;
        std::set<std::string> seen;
        FinderRecords finder;
        for (const auto& dir : trash_dirs()) {
            std::error_code ec;
            bool ok = sys::list_dir(dir, [&](sys::RawEntry&& e) {
                if (e.name_utf8 == ".DS_Store" || e.name_utf8 == ".localized") return true;
                fs::path stored = dir / e.name;
                TrashItem item;
                if (make_item(stored, item, finder)) {
                    seen.insert(stored.native());
                    out.push_back(std::move(item));
                }
                return true;
            }, ec);
            if (!ok && !sys::is_not_found(ec) && errors) errors->push_back({dir, {}, ec, "list"});
            if (ok && finder.error(dir) && errors) errors->push_back({dir / ".DS_Store", {}, finder.error(dir), "read"});
        }
        // Items brovfs trashed, even where the folder could not be enumerated.
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> keep;
        bool changed = false;
        for (const auto& line : journal_read()) {
            fs::path stored(line);
            TrashItem item;
            bool ours = false;
            if (!valid_location(stored) || !make_item(stored, item, finder, &ours) || !ours) {
                changed = true; // restored, erased or emptied since
                continue;
            }
            keep.push_back(line);
            if (seen.insert(line).second) out.push_back(std::move(item));
        }
        if (changed) journal_write(keep);
        return out;
    }

    bool restore(const std::string& id, RestoreConflict on_conflict, fs::path* restored_to,
                 std::error_code& ec) override {
        ec.clear();
        fs::path stored;
        if (!valid_id(id, stored, ec)) return false;
        std::string original;
        if (!get_x(stored, kPutback, original) || original.empty() || original[0] != '/') {
            // Not trashed by brovfs: Finder's own put-back record, if there is one.
            FinderRecords finder;
            TrashItem item;
            if (!make_item(stored, item, finder) || item.original_path.empty()) {
                ec = make_error_code(Errc::trash_info_invalid);
                return false;
            }
            original = item.original_path.native();
        }
        fs::path target(original);
        if (sys::exists_nofollow(target)) {
            if (on_conflict == RestoreConflict::Fail) {
                ec = make_error_code(Errc::restore_target_exists);
                return false;
            }
            target = unique_sibling_name(target);
        }
        if (!sys::make_dirs(target.parent_path(), ec)) return false;
        if (!sys::rename_noreplace(stored, target, ec)) {
            if (!sys::is_cross_device(ec)) return false;
            ec.clear();
            OpResult r = move_to(stored, target); // trashed into the home trash from another volume
            if (!r.ok()) {
                ec = r.errors.empty() ? make_error_code(Errc::cancelled) : r.errors.front().code;
                return false;
            }
        }
        rm_x(target);
        if (restored_to) *restored_to = target;
        return true;
    }

    bool erase(const std::string& id, std::error_code& ec) override {
        ec.clear();
        fs::path stored;
        if (!valid_id(id, stored, ec)) return false;
        // Without Full Disk Access ~/.Trash cannot be opened, so the directory-relative remover
        // cannot work inside it; renaming an item out by path still can. Move it to a staging
        // name next to the journal (recognised by find_staging_leftovers if we die here), then
        // remove it there.
        fs::path target = stored;
        fs::path area = cfg_.journal.parent_path() / "erasing";
        std::error_code mec;
        if (sys::make_dirs(area, mec)) {
            fs::path staged = sys::temp_sibling(area);
            if (sys::rename_noreplace(stored, staged, mec)) target = staged;
        }
        OpResult r = vfs::remove({target});
        if (!r.ok()) {
            ec = r.errors.empty() ? make_error_code(Errc::cancelled) : r.errors.front().code;
            return false;
        }
        return true;
    }

    OpResult empty() override {
        OpResult r;
        for (auto& item : list(&r.errors)) {
            std::error_code ec;
            if (erase(item.id, ec)) {
                ++r.files_done;
            } else {
                r.errors.push_back({item.stored_path, {}, ec, "erase"});
            }
        }
        detail::finish_result(r, false);
        return r;
    }

private:
    std::vector<fs::path> trash_dirs() const {
        std::vector<fs::path> dirs{home_trash_};
        if (!cfg_.search_volumes) return dirs;
        std::error_code ec;
        sys::list_dir("/Volumes", [&](sys::RawEntry&& e) {
            fs::path t = fs::path("/Volumes") / e.name / ".Trashes" / uid_;
            sys::Stat st;
            std::error_code sec;
            if (sys::lstat(t, st, sec) && st.kind == FileKind::Directory) dirs.push_back(t);
            return true;
        }, ec);
        return dirs;
    }

    // A direct child of the home trash or of a volume's .Trashes/<uid>.
    bool valid_location(const fs::path& stored) const {
        if (!stored.is_absolute() || stored.lexically_normal() != stored || leaf_name(stored).empty()) return false;
        for (const auto& c : stored) {
            if (c == "." || c == "..") return false;
        }
        fs::path parent = stored.parent_path();
        if (parent == home_trash_) return true;
        return parent.filename() == uid_ && parent.parent_path().filename() == ".Trashes";
    }

    bool in_a_trash(const fs::path& p) const {
        for (fs::path q = p; !q.empty() && q != q.parent_path(); q = q.parent_path()) {
            if (q == home_trash_ || q.filename() == ".Trashes") return true;
        }
        return false;
    }

    bool valid_id(const std::string& id, fs::path& stored, std::error_code& ec) const {
        stored = fs::path(id);
        if (id.empty() || !valid_location(stored)) {
            ec = make_error_code(Errc::invalid_trash_id);
            return false;
        }
        if (!sys::exists_nofollow(stored)) {
            ec = make_error_code(Errc::not_found);
            return false;
        }
        return true;
    }

    // Finder's put-back records per trash folder, read once per list()/restore().
    class FinderRecords {
    public:
        const detail::FinderPutBack* find(const fs::path& stored) {
            Dir& d = load(stored.parent_path());
            auto it = d.records.find(leaf_name(stored).native());
            return it == d.records.end() ? nullptr : &it->second;
        }
        std::error_code error(const fs::path& dir) { return load(dir).error; }

    private:
        struct Dir {
            std::map<std::string, detail::FinderPutBack> records;
            std::error_code error; // unreadable (other than absent)
        };
        Dir& load(const fs::path& dir) {
            auto [it, fresh] = dirs_.try_emplace(dir.native());
            if (fresh) {
                std::error_code ec;
                if (!detail::read_finder_putback(dir / ".DS_Store", it->second.records, ec) && ec != std::errc::no_such_file_or_directory) {
                    it->second.error = ec;
                }
            }
            return it->second;
        }
        std::map<std::string, Dir> dirs_;
    };

    // The volume a trash folder belongs to: "/" for the home trash, X for X/.Trashes/<uid>.
    fs::path volume_root_of(const fs::path& trash_dir) const {
        if (trash_dir == home_trash_) return "/";
        return trash_dir.parent_path().parent_path();
    }

    bool make_item(const fs::path& stored, TrashItem& item, FinderRecords& finder, bool* ours = nullptr) const {
        sys::Stat st;
        std::error_code ec;
        if (!sys::lstat(stored, st, ec)) return false;
        std::string original, when;
        get_x(stored, kPutback, original);
        if (ours) *ours = !original.empty();
        const detail::FinderPutBack* pb = finder.find(stored);
        item.finder_put_back = pb != nullptr;
        if (original.empty() && pb) {
            fs::path loc = fs::path(pb->location).relative_path();
            bool sane = true;
            for (const auto& c : loc) sane &= c != "..";
            if (sane) original = (volume_root_of(stored.parent_path()) / loc / (pb->name.empty() ? leaf_name(stored).native() : pb->name)).native();
        }
        item.id = stored.native();
        item.stored_path = stored;
        item.original_path = fs::path(original);
        item.name = leaf_name(original.empty() ? stored : item.original_path).native();
        item.deletion_time_ms = get_x(stored, kTrashed, when) ? std::atoll(when.c_str()) : st.ctime_ns / 1000000;
        item.size = st.kind == FileKind::Regular ? st.size : 0;
        item.is_directory = st.kind == FileKind::Directory;
        return true;
    }

    void journal_add(const fs::path& stored) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::error_code ec;
        sys::make_dirs(cfg_.journal.parent_path(), ec);
        int fd = ::open(cfg_.journal.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0) return;
        ::flock(fd, LOCK_EX);
        std::string line = encode_line(stored.native()) + "\n";
        [[maybe_unused]] ssize_t n = ::write(fd, line.data(), line.size());
        ::flock(fd, LOCK_UN);
        ::close(fd);
    }

    std::vector<std::string> journal_read() const {
        std::vector<std::string> out;
        std::ifstream in(cfg_.journal);
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty()) out.push_back(decode_line(line));
        }
        return out;
    }

    void journal_write(const std::vector<std::string>& lines) {
        int fd = ::open(cfg_.journal.c_str(), O_RDWR | O_CLOEXEC);
        if (fd < 0) return;
        ::flock(fd, LOCK_EX);
        // Re-read under the lock: another process may have appended meanwhile.
        std::vector<std::string> now = journal_read();
        std::set<std::string> keep(lines.begin(), lines.end());
        std::string text;
        FinderRecords finder;
        for (const auto& l : now) {
            fs::path stored(l);
            TrashItem item;
            bool ours = false;
            if (keep.count(l) || (valid_location(stored) && make_item(stored, item, finder, &ours) && ours)) {
                text += encode_line(l) + "\n";
            }
        }
        if (::ftruncate(fd, 0) == 0) {
            [[maybe_unused]] ssize_t n = ::pwrite(fd, text.data(), text.size(), 0);
        }
        ::flock(fd, LOCK_UN);
        ::close(fd);
    }

    MacTrashConfig cfg_;
    std::string uid_;
    fs::path home_trash_;
    std::mutex mutex_;
};

} // namespace

std::shared_ptr<Trash> make_macos_trash(MacTrashConfig config) { return std::make_shared<MacTrash>(std::move(config)); }

} // namespace bro::vfs

#endif // __APPLE__
