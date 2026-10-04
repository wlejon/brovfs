// freedesktop.org Trash specification 1.0.
//  * Home trash $XDG_DATA_HOME/Trash for files on the same device; otherwise the top directory
//    of the file's mount: $topdir/.Trash/$uid (only if .Trash is a real sticky directory),
//    else $topdir/.Trash-$uid. If neither is usable the call fails (no silent permanent
//    delete, and no cross-device copy unless configured).
//  * The .trashinfo is created with O_EXCL first, then the file is renamed into files/ with
//    no-replace; a name collision at either step moves on to the next candidate name.
//  * Path= is percent-encoded, absolute for the home trash and relative to $topdir for
//    top-directory trashes; DeletionDate= is local time.
//  * Ids are validated against the known trash directories; a name never contains '/', so
//    restore/erase can only touch entries inside a trash.
#ifndef _WIN32

#include "brovfs/trash.h"

#include "brovfs/path.h"
#include "src/engine.h"
#include "src/walk.h"

#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <pwd.h>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace bro::vfs {

namespace {

std::error_code errno_ec(int e) { return {e, std::system_category()}; }

std::string percent_encode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        bool keep = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
                    c == '_' || c == '.' || c == '~' || c == '/';
        if (keep) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 15]);
        }
    }
    return out;
}

bool percent_decode(const std::string& s, std::string& out) {
    out.clear();
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '%') {
            out.push_back(s[i]);
            continue;
        }
        if (i + 2 >= s.size()) return false;
        int h = val(s[i + 1]), l = val(s[i + 2]);
        if (h < 0 || l < 0) return false;
        out.push_back(static_cast<char>(h * 16 + l));
        i += 2;
    }
    return true;
}

std::string local_timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    return buf;
}

int64_t parse_local_timestamp(const std::string& s) {
    std::tm tm{};
    if (std::sscanf(s.c_str(), "%d-%d-%dT%d:%d:%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min,
                    &tm.tm_sec) != 6) {
        return 0;
    }
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    tm.tm_isdst = -1;
    std::time_t t = std::mktime(&tm);
    return t == static_cast<std::time_t>(-1) ? 0 : static_cast<int64_t>(t) * 1000;
}

fs::path default_home_trash() {
    const char* xdg = std::getenv("XDG_DATA_HOME");
    if (xdg && xdg[0] == '/') return fs::path(xdg) / "Trash";
    const char* home = std::getenv("HOME");
    std::string h = home && home[0] ? home : "";
    if (h.empty()) {
        if (passwd* pw = ::getpwuid(::getuid())) h = pw->pw_dir;
    }
    return fs::path(h) / ".local" / "share" / "Trash";
}

// Top directory of the mount containing `p`: the highest ancestor on the same device.
fs::path mount_topdir(const fs::path& p, uint64_t dev) {
    fs::path cur = p.parent_path();
    for (;;) {
        fs::path parent = cur.parent_path();
        if (parent.empty() || parent == cur) return cur;
        sys::Stat st;
        std::error_code ec;
        if (!sys::stat_follow(parent, st, ec) || st.id.device != dev) return cur;
        cur = parent;
    }
}

std::vector<fs::path> mount_points() {
    static const std::set<std::string> pseudo = {
        "proc",    "sysfs",  "devtmpfs", "devpts",  "securityfs", "cgroup",   "cgroup2", "pstore", "bpf",
        "debugfs", "tracefs", "hugetlbfs", "mqueue", "autofs",    "fusectl",  "configfs", "binfmt_misc",
        "efivarfs", "rpc_pipefs", "nsfs"};
    std::vector<fs::path> out;
    std::ifstream in("/proc/self/mounts");
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::string dev, mnt, type;
        if (!(ss >> dev >> mnt >> type) || pseudo.count(type)) continue;
        std::string decoded; // octal escapes: \040 space, \011 tab, \012 newline, \134 backslash
        for (size_t i = 0; i < mnt.size(); ++i) {
            if (mnt[i] == '\\' && i + 3 < mnt.size()) {
                decoded.push_back(static_cast<char>(std::stoi(mnt.substr(i + 1, 3), nullptr, 8)));
                i += 3;
            } else {
                decoded.push_back(mnt[i]);
            }
        }
        out.emplace_back(decoded);
    }
    return out;
}

std::string encode_id(const fs::path& dir, const std::string& name) {
    const std::string& d = dir.native();
    return std::to_string(d.size()) + ":" + d + name;
}

bool decode_id(const std::string& id, fs::path& dir, std::string& name) {
    size_t colon = id.find(':');
    if (colon == std::string::npos || colon == 0 || colon > 9) return false;
    size_t len = 0;
    for (size_t i = 0; i < colon; ++i) {
        if (id[i] < '0' || id[i] > '9') return false;
        len = len * 10 + static_cast<size_t>(id[i] - '0');
    }
    if (colon + 1 + len > id.size()) return false;
    dir = fs::path(id.substr(colon + 1, len));
    name = id.substr(colon + 1 + len);
    return !name.empty() && name != "." && name != ".." && name.find('/') == std::string::npos &&
           name.find('\0') == std::string::npos;
}

struct InfoRecord {
    std::string path; // decoded
    int64_t deletion_ms = 0;
};

bool read_info(const fs::path& file, InfoRecord& rec, std::error_code& ec) {
    std::ifstream in(file, std::ios::binary);
    if (!in) {
        ec = errno_ec(errno ? errno : ENOENT);
        return false;
    }
    std::string line;
    bool in_section = false, have_path = false;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        if (line[0] == '[') {
            in_section = line == "[Trash Info]";
            continue;
        }
        if (!in_section) continue;
        if (line.rfind("Path=", 0) == 0) {
            have_path = percent_decode(line.substr(5), rec.path) && !rec.path.empty();
        } else if (line.rfind("DeletionDate=", 0) == 0) {
            rec.deletion_ms = parse_local_timestamp(line.substr(13));
        }
    }
    if (!have_path) {
        ec = make_error_code(Errc::trash_info_invalid);
        return false;
    }
    return true;
}

class FreedesktopTrash final : public Trash {
public:
    explicit FreedesktopTrash(FreedesktopTrashConfig cfg) : cfg_(std::move(cfg)) {
        home_ = cfg_.home_trash.empty() ? default_home_trash() : cfg_.home_trash;
        uid_ = ::getuid();
    }

    bool trash(const fs::path& in, std::string* out_id, std::error_code& ec) override {
        std::error_code aec;
        fs::path p = fs::absolute(strip_trailing_separators(in), aec).lexically_normal();
        p = strip_trailing_separators(p);
        if (aec || leaf_name(p).empty()) {
            ec = make_error_code(Errc::invalid_argument);
            return false;
        }
        sys::Stat st;
        if (!sys::lstat(p, st, ec)) return false;

        fs::path dir, topdir;
        bool cross = false;
        if (!choose_trash(p, st, dir, topdir, cross, ec)) return false;
        if (p == dir || is_within(p, dir) || is_within(dir, p)) {
            ec = make_error_code(Errc::invalid_argument); // refuse to trash the trash or its parents
            return false;
        }
        std::string recorded = topdir.empty() ? p.native() : p.lexically_relative(topdir).native();
        std::string body = "[Trash Info]\nPath=" + percent_encode(recorded) + "\nDeletionDate=" + local_timestamp() + "\n";

        const std::string leaf = leaf_name(p).native();
        const std::string stem = leaf_name(p).stem().native();
        const std::string ext = leaf_name(p).extension().native();
        for (unsigned n = 1; n < 100000; ++n) {
            std::string name = n == 1 ? leaf : stem + "." + std::to_string(n) + ext;
            fs::path info = dir / "info" / (name + ".trashinfo");
            fs::path stored = dir / "files" / name;
            int fd = ::open(info.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
            if (fd < 0) {
                if (errno == EEXIST) continue;
                ec = errno_ec(errno);
                return false;
            }
            bool wrote = ::write(fd, body.data(), body.size()) == static_cast<ssize_t>(body.size()) && ::fsync(fd) == 0;
            int werr = errno;
            if (::close(fd) != 0 && wrote) {
                wrote = false;
                werr = errno;
            }
            if (!wrote) {
                ::unlink(info.c_str());
                ec = errno_ec(werr);
                return false;
            }
            if (sys::exists_nofollow(stored)) { // stray payload without info: skip the name
                ::unlink(info.c_str());
                continue;
            }
            if (!cross) {
                if (!sys::rename_noreplace(p, stored, ec)) {
                    ::unlink(info.c_str());
                    if (sys::is_exists_error(ec)) {
                        ec.clear();
                        continue;
                    }
                    return false;
                }
            } else {
                FileOpOptions opt; // Ask without a resolver: never overwrite inside the trash
                detail::Progress prog(nullptr, nullptr);
                OpResult r = detail::run_transfer(detail::TransferMode::Move, {{p, stored}}, opt, prog);
                if (!r.ok()) {
                    ec = r.errors.empty() ? make_error_code(Errc::cancelled) : r.errors.front().code;
                    // A non-directory whose source is still in place left only a duplicate:
                    // drop it. Otherwise (a partially moved directory) keep the record so what
                    // arrived, possibly the only copy of some children, stays restorable.
                    sys::Stat now;
                    std::error_code sec;
                    bool source_intact = st.kind != FileKind::Directory && sys::lstat(p, now, sec) &&
                                         now.id == st.id && now.size == st.size;
                    if (source_intact && sys::exists_nofollow(stored)) {
                        std::error_code rec;
                        sys::remove_nondir(stored, rec);
                    }
                    if (!sys::exists_nofollow(stored)) ::unlink(info.c_str());
                    return false;
                }
            }
            if (st.kind == FileKind::Directory) update_dirsizes(dir, name, true);
            if (out_id) *out_id = encode_id(dir, name);
            return true;
        }
        ec = std::make_error_code(std::errc::file_exists);
        return false;
    }

    std::vector<TrashItem> list(std::vector<ItemError>* errors) override {
        std::vector<TrashItem> items;
        for (const auto& dir : known_dirs()) {
            fs::path info_dir = dir / "info";
            std::map<std::string, uint64_t> sizes = read_dirsizes(dir);
            std::error_code ec;
            bool ok = sys::list_dir(info_dir, [&](sys::RawEntry&& e) {
                const std::string& fname = e.name_utf8;
                static const std::string suffix = ".trashinfo";
                if (fname.size() <= suffix.size() || fname.compare(fname.size() - suffix.size(), suffix.size(), suffix) != 0) {
                    return true;
                }
                std::string name = fname.substr(0, fname.size() - suffix.size());
                TrashItem item;
                std::error_code iec;
                if (!fill_item(dir, name, sizes, item, iec)) {
                    if (errors && !sys::is_not_found(iec)) errors->push_back({info_dir / e.name, {}, iec, "read trashinfo"});
                    return true;
                }
                items.push_back(std::move(item));
                return true;
            }, ec);
            if (!ok && errors && !sys::is_not_found(ec)) errors->push_back({info_dir, {}, ec, "list trash"});
        }
        return items;
    }

    bool restore(const std::string& id, RestoreConflict on_conflict, fs::path* restored_to,
                 std::error_code& ec) override {
        fs::path dir;
        std::string name;
        if (!validate(id, dir, name, ec)) return false;
        std::map<std::string, uint64_t> none;
        TrashItem item;
        if (!fill_item(dir, name, none, item, ec)) return false;
        fs::path target = item.original_path;
        if (sys::exists_nofollow(target)) {
            if (on_conflict == RestoreConflict::Fail) {
                ec = make_error_code(Errc::restore_target_exists);
                return false;
            }
            target = detail::unique_sibling(target, item.is_directory);
        }
        if (!sys::make_dirs(target.parent_path(), ec)) return false;
        if (!sys::rename_noreplace(item.stored_path, target, ec)) {
            if (sys::is_exists_error(ec)) {
                ec = make_error_code(Errc::restore_target_exists);
                return false;
            }
            if (!sys::is_cross_device(ec)) return false;
            ec.clear();
            FileOpOptions opt;
            detail::Progress prog(nullptr, nullptr);
            OpResult r = detail::run_transfer(detail::TransferMode::Move, {{item.stored_path, target}}, opt, prog);
            if (!r.ok()) {
                ec = r.errors.empty() ? make_error_code(Errc::cancelled) : r.errors.front().code;
                return false;
            }
        }
        std::error_code uec;
        sys::remove_nondir(dir / "info" / (name + ".trashinfo"), uec);
        if (item.is_directory) update_dirsizes(dir, name, false);
        if (restored_to) *restored_to = target;
        return true;
    }

    bool erase(const std::string& id, std::error_code& ec) override {
        fs::path dir;
        std::string name;
        if (!validate(id, dir, name, ec)) return false;
        fs::path stored = dir / "files" / name;
        bool was_dir = false;
        sys::Stat st;
        std::error_code sec;
        if (sys::lstat(stored, st, sec)) {
            was_dir = st.kind == FileKind::Directory;
            detail::Progress prog(nullptr, nullptr);
            OpResult r = detail::run_remove({stored}, prog);
            if (!r.ok()) {
                ec = r.errors.empty() ? make_error_code(Errc::cancelled) : r.errors.front().code;
                return false;
            }
        }
        if (!sys::remove_nondir(dir / "info" / (name + ".trashinfo"), ec)) return false;
        if (was_dir) update_dirsizes(dir, name, false);
        return true;
    }

    OpResult empty() override {
        OpResult r;
        for (const auto& item : list(&r.errors)) {
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
    static bool is_within(const fs::path& p, const fs::path& dir) {
        auto rel = p.lexically_relative(dir);
        return !rel.empty() && rel.native().rfind("..", 0) != 0;
    }

    fs::path topdir_for(const fs::path& p, const sys::Stat& st) const {
        if (cfg_.topdir_of) return cfg_.topdir_of(p);
        return mount_topdir(p, st.id.device);
    }

    bool ensure_layout(const fs::path& dir, std::error_code& ec) const {
        for (const fs::path& d : {dir, dir / "files", dir / "info"}) {
            sys::Stat st;
            std::error_code sec;
            if (sys::lstat(d, st, sec)) {
                if (st.kind != FileKind::Directory) {
                    ec = std::make_error_code(std::errc::not_a_directory);
                    return false;
                }
                continue;
            }
            if (d == dir && !sys::make_dirs(d.parent_path(), ec)) return false;
            if (!sys::make_dir(d, ec) && !sys::is_exists_error(ec)) return false;
            ec.clear();
        }
        return true;
    }

    // A usable top-directory trash for `topdir`, created if allowed; empty path if none.
    fs::path topdir_trash(const fs::path& topdir, uint64_t dev, bool create) const {
        const std::string uid = std::to_string(uid_);
        sys::Stat st;
        std::error_code ec;
        fs::path shared = topdir / ".Trash";
        if (sys::lstat(shared, st, ec) && st.kind == FileKind::Directory && (st.mode & S_ISVTX)) {
            fs::path mine = shared / uid;
            sys::Stat ms;
            std::error_code mec;
            bool exists = sys::lstat(mine, ms, mec);
            if (!exists && create) exists = sys::make_dir(mine, mec) && sys::lstat(mine, ms, mec);
            if (exists && ms.kind == FileKind::Directory && ms.uid == uid_ && ms.id.device == dev) return mine;
        }
        fs::path own = topdir / (".Trash-" + uid);
        sys::Stat os;
        bool exists = sys::lstat(own, os, ec);
        if (!exists && create) exists = sys::make_dir(own, ec) && sys::lstat(own, os, ec);
        if (exists && os.kind == FileKind::Directory && os.uid == uid_ && os.id.device == dev) return own;
        return {};
    }

    bool choose_trash(const fs::path& p, const sys::Stat& st, fs::path& dir, fs::path& topdir, bool& cross,
                      std::error_code& ec) {
        // Device of the home trash (or of its nearest existing ancestor).
        uint64_t home_dev = 0;
        for (fs::path a = home_;; a = a.parent_path()) {
            sys::Stat hs;
            std::error_code hec;
            if (sys::stat_follow(a, hs, hec)) {
                home_dev = hs.id.device;
                break;
            }
            if (a.parent_path() == a || a.empty()) break;
        }
        if (st.id.device == home_dev) {
            dir = home_;
            return ensure_layout(dir, ec);
        }
        topdir = topdir_for(p, st);
        fs::path t = topdir.empty() ? fs::path() : topdir_trash(topdir, st.id.device, true);
        if (!t.empty() && ensure_layout(t, ec)) {
            dir = t;
            return true;
        }
        ec.clear();
        if (!cfg_.allow_home_trash_across_devices) {
            ec = make_error_code(Errc::no_trash_available);
            return false;
        }
        topdir.clear();
        dir = home_;
        cross = true;
        return ensure_layout(dir, ec);
    }

    std::vector<fs::path> known_dirs() const {
        std::vector<fs::path> dirs{home_};
        std::vector<fs::path> tops = cfg_.extra_topdirs;
        if (cfg_.search_mounts) {
            for (auto& m : mount_points()) tops.push_back(m);
        }
        std::set<std::string> seen{home_.native()};
        for (const auto& top : tops) {
            sys::Stat ts;
            std::error_code ec;
            if (!sys::stat_follow(top, ts, ec)) continue;
            fs::path t = topdir_trash(top, ts.id.device, false);
            if (!t.empty() && seen.insert(t.native()).second) dirs.push_back(t);
        }
        return dirs;
    }

    bool validate(const std::string& id, fs::path& dir, std::string& name, std::error_code& ec) const {
        if (!decode_id(id, dir, name)) {
            ec = make_error_code(Errc::invalid_trash_id);
            return false;
        }
        for (const auto& d : known_dirs()) {
            if (d == dir) return true;
        }
        if (!cfg_.topdir_of) {
            ec = make_error_code(Errc::invalid_trash_id);
            return false;
        }
        // A configured topdir resolver may name trashes outside the mount table: accept a
        // directory shaped like one (<topdir>/.Trash-<uid> or <topdir>/.Trash/<uid>).
        const std::string uid = std::to_string(uid_);
        bool shaped = dir.filename() == ".Trash-" + uid ||
                      (dir.filename() == uid && dir.parent_path().filename() == ".Trash");
        sys::Stat st;
        std::error_code sec;
        if (shaped && sys::lstat(dir, st, sec) && st.kind == FileKind::Directory && st.uid == uid_) return true;
        ec = make_error_code(Errc::invalid_trash_id);
        return false;
    }

    bool fill_item(const fs::path& dir, const std::string& name, const std::map<std::string, uint64_t>& sizes,
                   TrashItem& item, std::error_code& ec) const {
        InfoRecord rec;
        if (!read_info(dir / "info" / (name + ".trashinfo"), rec, ec)) return false;
        fs::path stored = dir / "files" / name;
        sys::Stat st;
        if (!sys::lstat(stored, st, ec)) return false;
        fs::path orig(rec.path);
        if (orig.is_relative()) {
            // Top-directory trash: relative to $topdir.
            fs::path top = dir.filename() == std::to_string(uid_) ? dir.parent_path().parent_path() : dir.parent_path();
            if (dir == home_) {
                ec = make_error_code(Errc::trash_info_invalid);
                return false;
            }
            orig = top / orig;
        }
        item.id = encode_id(dir, name);
        item.original_path = orig.lexically_normal();
        item.stored_path = stored;
        item.name = leaf_name(orig).native();
        item.deletion_time_ms = rec.deletion_ms;
        item.is_directory = st.kind == FileKind::Directory;
        if (item.is_directory) {
            auto it = sizes.find(name);
            item.size = it == sizes.end() ? 0 : it->second;
        } else {
            item.size = st.size;
        }
        return true;
    }

    // directorysizes: "<bytes> <info mtime seconds> <percent-encoded name>" per line.
    std::map<std::string, uint64_t> read_dirsizes(const fs::path& dir) const {
        std::map<std::string, uint64_t> out;
        std::ifstream in(dir / "directorysizes");
        std::string line;
        while (std::getline(in, line)) {
            std::istringstream ss(line);
            uint64_t size = 0;
            long long mtime = 0;
            std::string enc, name;
            if (ss >> size >> mtime >> enc && percent_decode(enc, name)) out[name] = size;
        }
        return out;
    }

    void update_dirsizes(const fs::path& dir, const std::string& name, bool add) const {
        fs::path file = dir / "directorysizes";
        std::vector<std::string> lines;
        {
            std::ifstream in(file);
            std::string line;
            while (std::getline(in, line)) {
                std::istringstream ss(line);
                uint64_t size = 0;
                long long mtime = 0;
                std::string enc, decoded;
                if (ss >> size >> mtime >> enc && percent_decode(enc, decoded) && decoded == name) continue;
                if (!line.empty()) lines.push_back(line);
            }
        }
        if (add) {
            uint64_t total = 0;
            detail::walk(dir / "files" / name, detail::WalkOptions(), nullptr,
                         [&](const detail::WalkNode& n) {
                             total += n.st.size;
                             return true;
                         },
                         [](const fs::path&, const std::error_code&) {});
            sys::Stat is;
            std::error_code ec;
            sys::lstat(dir / "info" / (name + ".trashinfo"), is, ec);
            lines.push_back(std::to_string(total) + " " + std::to_string(is.mtime_ns / 1000000000) + " " +
                            percent_encode(name));
        }
        fs::path tmp = sys::temp_sibling(dir);
        {
            std::ofstream out(tmp, std::ios::trunc);
            for (const auto& l : lines) out << l << "\n";
            if (!out) {
                std::error_code ec;
                sys::remove_nondir(tmp, ec);
                return;
            }
        }
        std::error_code ec;
        if (!sys::rename_replace(tmp, file, ec)) sys::remove_nondir(tmp, ec);
    }

    FreedesktopTrashConfig cfg_;
    fs::path home_;
    uid_t uid_;
};

} // namespace

std::shared_ptr<Trash> make_freedesktop_trash(FreedesktopTrashConfig config) {
    return std::make_shared<FreedesktopTrash>(std::move(config));
}

} // namespace bro::vfs

#endif // !_WIN32
