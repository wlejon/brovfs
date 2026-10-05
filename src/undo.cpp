#include "brovfs/undo.h"

#include "brovfs/path.h"
#include "brovfs/scanner.h"
#include "src/engine.h"
#include "src/sys.h"

#include <algorithm>
#include <charconv>
#include <cinttypes>
#include <cstdio>
#include <sstream>

#if defined(__linux__)
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace bro::vfs {

bool UndoRecord::undone() const noexcept {
    return std::all_of(steps.begin(), steps.end(), [](const UndoStep& s) { return s.reversed; });
}

uint64_t tree_digest(const fs::path& root) {
    ScanOptions so;
    so.recursive = true;
    so.read_link_targets = true;
    auto r = scan_directory(root, so);
    if (r.entries.empty() && r.errors.empty()) return 0x9E3779B97F4A7C15ull; // an empty directory
    std::vector<std::string> lines;
    lines.reserve(r.entries.size());
    for (auto& e : r.entries) {
        std::string rel = path_to_utf8(e.path.lexically_relative(root));
        char tail[96];
        std::snprintf(tail, sizeof(tail), "|%d|%" PRIu64 "|%" PRId64, static_cast<int>(e.kind),
                      e.kind == FileKind::Regular ? e.size : uint64_t(0), e.mtime_ms);
        lines.push_back(rel + tail + "|" + e.link_target);
    }
    for (auto& err : r.errors) lines.push_back("!" + path_to_utf8(err.path));
    std::sort(lines.begin(), lines.end());
    uint64_t h = 0xcbf29ce484222325ull; // FNV-1a
    for (auto& l : lines) {
        for (unsigned char c : l) h = (h ^ c) * 0x100000001b3ull;
        h = (h ^ '\n') * 0x100000001b3ull;
    }
    return h;
}

namespace {

std::error_code ec_of(Errc e) { return make_error_code(e); }

// Inode generation (FS_IOC_GETVERSION): ext4, btrfs and xfs give a reused inode number a new
// one. 0 when unknown (other systems, other kinds, or the file cannot be opened).
uint32_t generation_of([[maybe_unused]] const fs::path& p, [[maybe_unused]] FileKind kind) {
#if defined(__linux__)
    if (kind != FileKind::Regular && kind != FileKind::Directory) return 0;
    int fd = ::open(p.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (kind == FileKind::Directory ? O_DIRECTORY : 0));
    if (fd < 0) return 0;
    int gen = 0;
    bool ok = ::ioctl(fd, FS_IOC_GETVERSION, &gen) == 0;
    ::close(fd);
    return ok ? static_cast<uint32_t>(gen) : 0;
#else
    return 0;
#endif
}

struct Ident {
    sys::Stat st;
    uint32_t gen = 0;
};

bool lstat_at(const fs::path& p, Ident& out) {
    std::error_code ec;
    if (!sys::lstat(p, out.st, ec)) return false;
    out.gen = generation_of(p, out.st.kind);
    return true;
}

int64_t ms_of(int64_t ns) { return ns / 1000000; }

// Same object: same id, and the same birth time and generation where both sides know them.
bool same_object(const Ident& x, const FileId& id, int64_t btime_ns, uint32_t gen) {
    return x.st.id == id && (btime_ns == 0 || x.st.btime_ns == 0 || x.st.btime_ns == btime_ns) &&
           (gen == 0 || x.gen == 0 || x.gen == gen);
}

// Destination state right after the operation (or after a redo).
void capture(UndoStep& s) {
    Ident x;
    if (s.item.action == DoneItem::Action::Trashed || !lstat_at(s.item.destination, x)) return;
    const sys::Stat& st = x.st;
    s.id = st.id;
    s.btime_ns = st.btime_ns;
    s.generation = x.gen;
    s.kind = st.kind;
    s.size = st.size;
    s.mtime_ms = ms_of(st.mtime_ns);
    s.tree_digest = s.item.action == DoneItem::Action::Copied && st.kind == FileKind::Directory
                        ? tree_digest(s.item.destination)
                        : 0;
}

// Is the destination still what the operation left there?
std::error_code check_destination(const UndoStep& s, bool deep) {
    Ident x;
    if (!lstat_at(s.item.destination, x)) return ec_of(Errc::not_found);
    const sys::Stat& st = x.st;
    if (!same_object(x, s.id, s.btime_ns, s.generation) || st.kind != s.kind) return ec_of(Errc::target_changed);
    if (!deep) return {};
    if (st.kind != FileKind::Directory && (st.size != s.size || ms_of(st.mtime_ns) != s.mtime_ms)) {
        return ec_of(Errc::target_changed);
    }
    if (st.kind == FileKind::Directory && tree_digest(s.item.destination) != s.tree_digest) {
        return ec_of(Errc::target_changed);
    }
    return {};
}

std::error_code first_error(const OpResult& r) {
    if (!r.errors.empty()) return r.errors.front().code;
    return r.outcome == Outcome::Success ? std::error_code() : ec_of(Errc::cancelled);
}

std::error_code move_exact(const fs::path& from, const fs::path& to) {
    std::error_code ec;
    if (!sys::make_dirs(to.parent_path(), ec)) return ec;
    FileOpOptions o;
    o.conflict = ConflictPolicy::Ask; // no resolver: any conflict fails
    return first_error(move_to(from, to, o));
}

} // namespace

UndoJournal::UndoJournal(std::shared_ptr<Trash> trash, size_t capacity)
    : trash_(std::move(trash)), capacity_(capacity ? capacity : 1) {}

uint64_t UndoJournal::record(UndoKind kind, const OpResult& result, std::string label) {
    if (result.done.empty()) return 0;
    UndoRecord r;
    r.id = next_id_++;
    r.kind = kind;
    r.label = std::move(label);
    r.time_ms = sys::now_unix_ms();
    for (const auto& d : result.done) {
        UndoStep s;
        s.item = d;
        capture(s);
        if (d.action == DoneItem::Action::Moved) {
            s.source_id = s.id;
            s.source_btime_ns = s.btime_ns;
            s.source_generation = s.generation;
        }
        r.steps.push_back(std::move(s));
    }
    done_.push_back(std::move(r));
    while (done_.size() > capacity_) done_.pop_front();
    undone_.clear();
    return done_.back().id;
}

const UndoRecord* UndoJournal::next_undo() const { return done_.empty() ? nullptr : &done_.back(); }
const UndoRecord* UndoJournal::next_redo() const { return undone_.empty() ? nullptr : &undone_.back(); }

OpResult UndoJournal::undo() {
    OpResult res;
    if (done_.empty()) {
        res.errors.push_back({{}, {}, ec_of(Errc::not_found), "undo"});
        detail::finish_result(res, false);
        return res;
    }
    UndoRecord& rec = done_.back();
    // Check every step first; refuse the whole record if any step cannot be reversed.
    for (const auto& s : rec.steps) {
        if (s.reversed) continue;
        const DoneItem& d = s.item;
        std::error_code why;
        switch (d.action) {
            case DoneItem::Action::Moved:
                why = check_destination(s, false);
                if (!why && sys::exists_nofollow(d.source)) why = ec_of(Errc::restore_target_exists);
                break;
            case DoneItem::Action::Copied:
                why = d.replaced ? ec_of(Errc::not_reversible) : check_destination(s, true);
                break;
            case DoneItem::Action::Trashed:
                if (!trash_) why = ec_of(Errc::no_trash_available);
                else if (sys::exists_nofollow(d.source)) why = ec_of(Errc::restore_target_exists);
                break;
        }
        if (why) res.errors.push_back({d.source, d.destination, why, "undo"});
    }
    if (!res.errors.empty()) {
        detail::finish_result(res, false);
        return res;
    }
    for (size_t i = rec.steps.size(); i-- > 0;) {
        UndoStep& s = rec.steps[i];
        if (s.reversed) continue;
        const DoneItem& d = s.item;
        std::error_code ec;
        switch (d.action) {
            case DoneItem::Action::Moved: {
                ec = move_exact(d.destination, d.source);
                Ident x;
                if (!ec && lstat_at(d.source, x)) {
                    s.source_id = x.st.id;
                    s.source_btime_ns = x.st.btime_ns;
                    s.source_generation = x.gen;
                }
                break;
            }
            case DoneItem::Action::Copied:
                if (trash_) {
                    std::string id;
                    trash_->trash(d.destination, &id, ec);
                } else {
                    ec = first_error(vfs::remove({d.destination}));
                }
                break;
            case DoneItem::Action::Trashed: {
                fs::path back;
                Ident x;
                if (trash_->restore(d.trash_id, RestoreConflict::Fail, &back, ec) && lstat_at(back, x)) {
                    s.source_id = x.st.id;
                    s.source_btime_ns = x.st.btime_ns;
                    s.source_generation = x.gen;
                }
                break;
            }
        }
        if (ec) {
            res.errors.push_back({d.source, d.destination, ec, "undo"});
            continue;
        }
        s.reversed = true;
        ++res.files_done;
    }
    if (rec.undone()) {
        undone_.push_back(std::move(rec));
        done_.pop_back();
    }
    detail::finish_result(res, false);
    return res;
}

OpResult UndoJournal::redo() {
    OpResult res;
    if (undone_.empty()) {
        res.errors.push_back({{}, {}, ec_of(Errc::not_found), "redo"});
        detail::finish_result(res, false);
        return res;
    }
    UndoRecord& rec = undone_.back();
    for (const auto& s : rec.steps) {
        if (!s.reversed) continue;
        const DoneItem& d = s.item;
        std::error_code why;
        Ident x;
        const bool src_ok = lstat_at(d.source, x);
        switch (d.action) {
            case DoneItem::Action::Moved:
            case DoneItem::Action::Trashed:
                if (!src_ok) why = ec_of(Errc::not_found);
                else if (!same_object(x, s.source_id, s.source_btime_ns, s.source_generation)) why = ec_of(Errc::target_changed);
                break;
            case DoneItem::Action::Copied:
                if (!src_ok) why = ec_of(Errc::not_found);
                break;
        }
        if (!why && d.action == DoneItem::Action::Trashed && !trash_) why = ec_of(Errc::no_trash_available);
        if (!why && d.action != DoneItem::Action::Trashed && sys::exists_nofollow(d.destination)) {
            why = ec_of(Errc::restore_target_exists);
        }
        if (why) res.errors.push_back({d.source, d.destination, why, "redo"});
    }
    if (!res.errors.empty()) {
        detail::finish_result(res, false);
        return res;
    }
    for (auto& s : rec.steps) {
        if (!s.reversed) continue;
        DoneItem& d = s.item;
        std::error_code ec;
        switch (d.action) {
            case DoneItem::Action::Moved: ec = move_exact(d.source, d.destination); break;
            case DoneItem::Action::Copied: {
                FileOpOptions o;
                o.conflict = ConflictPolicy::Ask;
                ec = first_error(copy_to(d.source, d.destination, o));
                break;
            }
            case DoneItem::Action::Trashed: {
                std::string id;
                if (trash_->trash(d.source, &id, ec)) d.trash_id = id;
                break;
            }
        }
        if (ec) {
            res.errors.push_back({d.source, d.destination, ec, "redo"});
            continue;
        }
        capture(s);
        s.reversed = false;
        ++res.files_done;
    }
    if (std::none_of(rec.steps.begin(), rec.steps.end(), [](const UndoStep& s) { return s.reversed; })) {
        done_.push_back(std::move(rec));
        undone_.pop_back();
    }
    detail::finish_result(res, false);
    return res;
}

// ---------------------------------------------------------------- persistence

namespace {

std::string enc(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (c <= ' ' || c == '%' || c == 0x7F) {
            char b[4];
            std::snprintf(b, sizeof(b), "%%%02X", c);
            out += b;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out.empty() ? "%" : out; // "%" alone: the empty string
}

bool dec(const std::string& s, std::string& out) {
    out.clear();
    if (s == "%") return true;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '%') {
            out += s[i];
            continue;
        }
        auto hex = [](char c) {
            return c >= '0' && c <= '9' ? c - '0' : c >= 'A' && c <= 'F' ? c - 'A' + 10 : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
        };
        if (i + 2 >= s.size() || hex(s[i + 1]) < 0 || hex(s[i + 2]) < 0) return false;
        out += static_cast<char>(hex(s[i + 1]) * 16 + hex(s[i + 2]));
        i += 2;
    }
    return true;
}

std::string id_text(const FileId& id) {
    char b[80];
    std::snprintf(b, sizeof(b), "%" PRIu64 ":%" PRIu64 ":%" PRIu64 ":%d", id.device, id.hi, id.lo, id.valid ? 1 : 0);
    return b;
}

bool parse_id(const std::string& s, FileId& id) {
    uint64_t v[4] = {};
    const char* p = s.data();
    const char* end = s.data() + s.size();
    for (int i = 0; i < 4; ++i) {
        auto r = std::from_chars(p, end, v[i]);
        if (r.ec != std::errc() || (i < 3 ? (r.ptr == end || *r.ptr != ':') : r.ptr != end)) return false;
        p = r.ptr + 1;
    }
    if (v[3] > 1) return false;
    id.device = v[0];
    id.hi = v[1];
    id.lo = v[2];
    id.valid = v[3] != 0;
    return true;
}

} // namespace

std::string UndoJournal::save() const {
    std::ostringstream o;
    o << "brovfs-undo 1\n";
    auto put = [&](const UndoRecord& r, bool in_redo) {
        o << "R " << r.id << ' ' << static_cast<int>(r.kind) << ' ' << r.time_ms << ' ' << (in_redo ? 1 : 0) << ' '
          << enc(r.label) << '\n';
        for (const auto& s : r.steps) {
            o << "S " << static_cast<int>(s.item.action) << ' ' << (s.reversed ? 1 : 0) << ' ' << (s.item.replaced ? 1 : 0)
              << ' ' << static_cast<int>(s.kind) << ' ' << s.size << ' ' << s.mtime_ms << ' ' << s.btime_ns << ' '
              << s.source_btime_ns << ' ' << s.generation << ' ' << s.source_generation << ' ' << s.tree_digest << ' '
              << id_text(s.id) << ' ' << id_text(s.source_id) << ' ' << enc(path_to_utf8(s.item.source)) << ' '
              << enc(path_to_utf8(s.item.destination)) << ' ' << enc(s.item.trash_id) << '\n';
        }
    };
    for (const auto& r : done_) put(r, false);
    for (const auto& r : undone_) put(r, true);
    return o.str();
}

bool UndoJournal::load(const std::string& text, std::error_code& ec) {
    std::istringstream in(text);
    std::string line;
    if (!std::getline(in, line) || line != "brovfs-undo 1") {
        ec = ec_of(Errc::invalid_argument);
        return false;
    }
    std::deque<UndoRecord> done, undone;
    std::deque<UndoRecord>* cur = nullptr;
    uint64_t max_id = 0;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::istringstream ls(line);
        std::string tag;
        ls >> tag;
        if (tag == "R") {
            UndoRecord r;
            int kind = 0, redo = 0;
            std::string label;
            if (!(ls >> r.id >> kind >> r.time_ms >> redo >> label) || !dec(label, r.label) || kind < 0 || kind > 2) {
                ec = ec_of(Errc::invalid_argument);
                return false;
            }
            r.kind = static_cast<UndoKind>(kind);
            max_id = std::max(max_id, r.id);
            cur = redo ? &undone : &done;
            cur->push_back(std::move(r));
        } else if (tag == "S" && cur) {
            UndoStep s;
            int action = 0, reversed = 0, replaced = 0, kind = 0;
            std::string id, sid, src, dst, tid, t1, t2, t3;
            if (!(ls >> action >> reversed >> replaced >> kind >> s.size >> s.mtime_ms >> s.btime_ns >> s.source_btime_ns >> s.generation >> s.source_generation >> s.tree_digest >> id >> sid >> src >>
                  dst >> tid) ||
                action < 0 || action > 2 || !parse_id(id, s.id) || !parse_id(sid, s.source_id) || !dec(src, t1) ||
                !dec(dst, t2) || !dec(tid, t3)) {
                ec = ec_of(Errc::invalid_argument);
                return false;
            }
            s.item.action = static_cast<DoneItem::Action>(action);
            s.item.replaced = replaced != 0;
            s.item.source = path_from_utf8(t1);
            s.item.destination = path_from_utf8(t2);
            s.item.trash_id = t3;
            s.kind = static_cast<FileKind>(kind);
            s.reversed = reversed != 0;
            cur->back().steps.push_back(std::move(s));
        } else {
            ec = ec_of(Errc::invalid_argument);
            return false;
        }
    }
    done_ = std::move(done);
    undone_ = std::move(undone);
    next_id_ = std::max(next_id_, max_id + 1);
    return true;
}

} // namespace bro::vfs
