// POSIX platform layer: stat, listing, renames, directories, removal, links, and the
// directory-fd `Dir` used for race-free traversal and removal. Data copy and metadata live in
// sys_posix_copy.cpp.
#ifndef _WIN32

#include "src/posix_util.h"

#include "brovfs/path.h"

#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sys/types.h>

#ifdef __linux__
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#endif

namespace bro::vfs {

namespace posix {

FileKind kind_from_mode(mode_t m) {
    if (S_ISREG(m)) return FileKind::Regular;
    if (S_ISDIR(m)) return FileKind::Directory;
    if (S_ISLNK(m)) return FileKind::Symlink;
    if (S_ISFIFO(m)) return FileKind::Fifo;
    if (S_ISSOCK(m)) return FileKind::Socket;
    if (S_ISCHR(m)) return FileKind::CharDevice;
    if (S_ISBLK(m)) return FileKind::BlockDevice;
    return FileKind::Unknown;
}

namespace {

FileKind kind_from_dtype(unsigned char t) {
    switch (t) {
        case DT_REG: return FileKind::Regular;
        case DT_DIR: return FileKind::Directory;
        case DT_LNK: return FileKind::Symlink;
        case DT_FIFO: return FileKind::Fifo;
        case DT_SOCK: return FileKind::Socket;
        case DT_CHR: return FileKind::CharDevice;
        case DT_BLK: return FileKind::BlockDevice;
        default: return FileKind::Unknown;
    }
}

int64_t ns(int64_t sec, int64_t nsec) { return sec * 1000000000 + nsec; }

void fill_from_stat(const struct stat& s, sys::Stat& st) {
    st.kind = kind_from_mode(s.st_mode);
    st.size = st.kind == FileKind::Regular || st.kind == FileKind::Symlink ? static_cast<uint64_t>(s.st_size) : 0;
#if defined(__APPLE__)
    st.mtime_ns = ns(s.st_mtimespec.tv_sec, s.st_mtimespec.tv_nsec);
    st.atime_ns = ns(s.st_atimespec.tv_sec, s.st_atimespec.tv_nsec);
    st.ctime_ns = ns(s.st_ctimespec.tv_sec, s.st_ctimespec.tv_nsec);
    st.btime_ns = ns(s.st_birthtimespec.tv_sec, s.st_birthtimespec.tv_nsec);
#else
    st.mtime_ns = ns(s.st_mtim.tv_sec, s.st_mtim.tv_nsec);
    st.atime_ns = ns(s.st_atim.tv_sec, s.st_atim.tv_nsec);
    st.ctime_ns = ns(s.st_ctim.tv_sec, s.st_ctim.tv_nsec);
    st.btime_ns = 0;
#endif
    st.mode = static_cast<uint32_t>(s.st_mode);
    st.uid = static_cast<uint32_t>(s.st_uid);
    st.gid = static_cast<uint32_t>(s.st_gid);
    st.nlink = static_cast<uint64_t>(s.st_nlink);
    st.id.device = static_cast<uint64_t>(s.st_dev);
    st.id.hi = 0;
    st.id.lo = static_cast<uint64_t>(s.st_ino);
    st.id.valid = true;
}

#if defined(__linux__) && defined(STATX_BASIC_STATS)
std::atomic<bool> g_statx_available{true};

void fill_from_statx(const struct statx& s, sys::Stat& st) {
    st.kind = kind_from_mode(s.stx_mode);
    st.size = st.kind == FileKind::Regular || st.kind == FileKind::Symlink ? s.stx_size : 0;
    st.mtime_ns = ns(s.stx_mtime.tv_sec, s.stx_mtime.tv_nsec);
    st.atime_ns = ns(s.stx_atime.tv_sec, s.stx_atime.tv_nsec);
    st.ctime_ns = ns(s.stx_ctime.tv_sec, s.stx_ctime.tv_nsec);
    st.btime_ns = (s.stx_mask & STATX_BTIME) ? ns(s.stx_btime.tv_sec, s.stx_btime.tv_nsec) : 0;
    st.mode = s.stx_mode;
    st.uid = s.stx_uid;
    st.gid = s.stx_gid;
    st.nlink = s.stx_nlink;
    st.id.device = static_cast<uint64_t>(makedev(s.stx_dev_major, s.stx_dev_minor));
    st.id.hi = 0;
    st.id.lo = s.stx_ino;
    st.id.valid = true;
}
#endif

#if defined(__APPLE__)
// Read once before main(), while the process is single-threaded: umask() can only be read by
// setting it.
const mode_t g_umask = [] {
    mode_t m = ::umask(022);
    ::umask(m);
    return m;
}();
#endif

} // namespace

bool stat_at(int dirfd, const char* name, bool follow, sys::Stat& out, int& err) {
#if defined(__linux__) && defined(STATX_BASIC_STATS)
    if (g_statx_available.load(std::memory_order_relaxed)) {
        struct statx sx;
        int flags = AT_NO_AUTOMOUNT | AT_STATX_SYNC_AS_STAT | (follow ? 0 : AT_SYMLINK_NOFOLLOW);
        if (::statx(dirfd, name, flags, STATX_BASIC_STATS | STATX_BTIME, &sx) == 0) {
            fill_from_statx(sx, out);
            return true;
        }
        if (errno != ENOSYS && errno != EPERM) {
            err = errno;
            return false;
        }
        g_statx_available.store(false, std::memory_order_relaxed);
    }
#endif
    struct stat s;
    if (::fstatat(dirfd, name, &s, follow ? 0 : AT_SYMLINK_NOFOLLOW) == 0) {
        fill_from_stat(s, out);
        return true;
    }
    err = errno;
    return false;
}

bool write_all(int fd, const char* p, size_t n, int& err) {
    while (n > 0) {
        ssize_t w = ::write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            err = errno;
            return false;
        }
        p += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

mode_t current_umask() {
#if defined(__APPLE__)
    return g_umask;
#else
    static const mode_t mask = [] {
        std::ifstream in("/proc/self/status");
        std::string line;
        while (std::getline(in, line)) {
            if (line.rfind("Umask:", 0) == 0) return static_cast<mode_t>(std::stoul(line.substr(6), nullptr, 8));
        }
        return static_cast<mode_t>(022);
    }();
    return mask;
#endif
}

bool list_fd(int dirfd, const std::function<bool(sys::RawEntry&&)>& cb, std::error_code& ec) {
    // A fresh open file description: listing never disturbs (or depends on) dirfd's offset.
    Fd fd(::openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (!fd.ok()) {
        ec = errno_ec(errno);
        return false;
    }
    auto deliver = [&](const char* name, unsigned char dtype) -> bool {
        if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))) return true;
        sys::RawEntry e;
        e.name = fs::path(name);
        e.name_utf8 = name;
        int err = 0;
        if (!stat_at(fd.get(), name, false, e.st, err)) {
            if (err == ENOENT) return true; // vanished between readdir and stat
            e.stat_error = errno_ec(err);
            e.st.kind = kind_from_dtype(dtype);
        }
        return cb(std::move(e));
    };
#ifdef __linux__
    struct linux_dirent64 {
        uint64_t d_ino;
        int64_t d_off;
        unsigned short d_reclen;
        unsigned char d_type;
        char d_name[1];
    };
    alignas(8) static thread_local char buf[64 * 1024];
    for (;;) {
        long n = ::syscall(SYS_getdents64, fd.get(), buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            ec = errno_ec(errno);
            return false;
        }
        if (n == 0) break;
        // Copy out the batch: the callback may recurse and reuse the thread buffer.
        std::vector<std::pair<std::string, unsigned char>> names;
        for (long off = 0; off < n;) {
            auto* d = reinterpret_cast<linux_dirent64*>(buf + off);
            names.emplace_back(d->d_name, d->d_type);
            off += d->d_reclen;
        }
        for (auto& [name, type] : names) {
            if (!deliver(name.c_str(), type)) return true;
        }
    }
    return true;
#else
    int read_fd = ::dup(fd.get());
    DIR* d = read_fd >= 0 ? ::fdopendir(read_fd) : nullptr;
    if (!d) {
        ec = errno_ec(errno);
        if (read_fd >= 0) ::close(read_fd);
        return false;
    }
    std::vector<std::pair<std::string, unsigned char>> names;
    for (;;) {
        errno = 0;
        struct dirent* de = ::readdir(d);
        if (!de) {
            if (errno != 0) {
                ec = errno_ec(errno);
                ::closedir(d);
                return false;
            }
            break;
        }
        names.emplace_back(de->d_name, de->d_type);
    }
    ::closedir(d);
    for (auto& [name, type] : names) {
        if (!deliver(name.c_str(), type)) break;
    }
    return true;
#endif
}

} // namespace posix

namespace sys {

using namespace posix;

bool lstat(const fs::path& p, Stat& out, std::error_code& ec) {
    int err = 0;
    if (stat_at(AT_FDCWD, p.c_str(), false, out, err)) return true;
    ec = errno_ec(err);
    return false;
}

bool stat_follow(const fs::path& p, Stat& out, std::error_code& ec) {
    int err = 0;
    if (stat_at(AT_FDCWD, p.c_str(), true, out, err)) return true;
    ec = errno_ec(err);
    return false;
}

bool list_dir(const fs::path& dir, const std::function<bool(RawEntry&&)>& cb, std::error_code& ec) {
    Fd fd(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!fd.ok()) {
        ec = errno_ec(errno);
        return false;
    }
    return list_fd(fd.get(), cb, ec);
}

// ---------------------------------------------------------------- Dir

Dir::~Dir() { close(); }
Dir::Dir(Dir&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
Dir& Dir::operator=(Dir&& o) noexcept {
    if (this != &o) {
        close();
        fd_ = o.fd_;
        o.fd_ = -1;
    }
    return *this;
}
bool Dir::ok() const noexcept { return fd_ >= 0; }
void Dir::close() noexcept {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
}

bool Dir::open(const fs::path& p, bool follow_leaf, Dir& out, std::error_code& ec) {
    out.close();
    const char* path = p.empty() ? "." : p.c_str();
    int fd = ::open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | (follow_leaf ? 0 : O_NOFOLLOW));
    if (fd < 0) {
        ec = errno_ec(errno);
        return false;
    }
    out.fd_ = fd;
    return true;
}

namespace {
bool matches(int fd, const FileId* expect, std::error_code& ec) {
    if (!expect || !expect->valid) return true;
    struct stat s;
    if (::fstat(fd, &s) != 0) {
        ec = errno_ec(errno);
        return false;
    }
    if (static_cast<uint64_t>(s.st_ino) != expect->lo || static_cast<uint64_t>(s.st_dev) != expect->device) {
        ec = make_error_code(Errc::source_changed);
        return false;
    }
    return true;
}
} // namespace

bool Dir::open_child(const fs::path& name, const FileId* expect, Dir& out, std::error_code& ec) const {
    out.close();
    Fd fd(::openat(fd_, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!fd.ok()) {
        int e = errno;
        // The planned directory is no longer there: a link or a non-directory took its name.
        ec = (expect && expect->valid && (e == ELOOP || e == ENOTDIR)) ? make_error_code(Errc::source_changed)
                                                                       : errno_ec(e);
        return false;
    }
    if (!matches(fd.get(), expect, ec)) return false;
    out.fd_ = fd.release();
    return true;
}

bool Dir::stat(Stat& out, std::error_code& ec) const {
    struct stat s;
    if (::fstat(fd_, &s) != 0) {
        ec = errno_ec(errno);
        return false;
    }
    fill_from_stat(s, out);
    return true;
}

bool Dir::stat_child(const fs::path& name, Stat& out, std::error_code& ec) const {
    int err = 0;
    if (stat_at(fd_, name.c_str(), false, out, err)) return true;
    ec = errno_ec(err);
    return false;
}

bool Dir::list(const std::function<bool(RawEntry&&)>& cb, std::error_code& ec) const { return list_fd(fd_, cb, ec); }

bool Dir::remove_child(const fs::path& name, bool is_dir, const FileId* expect, std::error_code& ec) const {
    if (expect && expect->valid) {
        Stat st;
        if (!stat_child(name, st, ec)) return false;
        if (!(st.id == *expect) || (st.kind == FileKind::Directory) != is_dir) {
            ec = make_error_code(Errc::source_changed);
            return false;
        }
    }
    if (::unlinkat(fd_, name.c_str(), is_dir ? AT_REMOVEDIR : 0) != 0) {
        ec = errno_ec(errno);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------- renames

bool read_link_target(const fs::path& link, std::string& target, std::error_code& ec) {
    std::string buf(256, '\0');
    for (;;) {
        ssize_t n = ::readlink(link.c_str(), buf.data(), buf.size());
        if (n < 0) {
            ec = errno_ec(errno);
            return false;
        }
        if (static_cast<size_t>(n) < buf.size()) {
            buf.resize(static_cast<size_t>(n));
            target = std::move(buf);
            return true;
        }
        buf.resize(buf.size() * 2);
    }
}

std::error_code cross_device_error() { return errno_ec(EXDEV); }

bool rename_noreplace(const fs::path& from, const fs::path& to, std::error_code& ec) {
#if defined(__linux__)
    if (::renameat2(AT_FDCWD, from.c_str(), AT_FDCWD, to.c_str(), RENAME_NOREPLACE) == 0) return true;
    int e = errno;
    if (e != EINVAL && e != ENOSYS && e != ENOTSUP && e != EOPNOTSUPP) {
        ec = errno_ec(e);
        return false;
    }
#elif defined(__APPLE__)
    if (::renamex_np(from.c_str(), to.c_str(), RENAME_EXCL) == 0) return true;
    int e = errno;
    if (e != ENOTSUP && e != EINVAL) {
        ec = errno_ec(e);
        return false;
    }
#endif
    // No exclusive rename on this file system. For non-directories link()+unlink() is atomic
    // with respect to an existing destination; directories fall back to check-then-rename.
    struct stat s;
    if (::lstat(from.c_str(), &s) != 0) {
        ec = errno_ec(errno);
        return false;
    }
    if (!S_ISDIR(s.st_mode)) {
        if (::link(from.c_str(), to.c_str()) == 0) {
            if (::unlink(from.c_str()) != 0) {
                int e2 = errno;
                ::unlink(to.c_str());
                ec = errno_ec(e2);
                return false;
            }
            return true;
        }
        if (errno == EEXIST || errno == EXDEV) {
            ec = errno_ec(errno);
            return false;
        }
    }
    struct stat d;
    if (::lstat(to.c_str(), &d) == 0) {
        ec = errno_ec(EEXIST);
        return false;
    }
    if (::rename(from.c_str(), to.c_str()) != 0) {
        ec = errno_ec(errno);
        return false;
    }
    return true;
}

bool rename_replace(const fs::path& from, const fs::path& to, std::error_code& ec) {
    if (::rename(from.c_str(), to.c_str()) != 0) {
        ec = errno_ec(errno);
        return false;
    }
    return true;
}

bool is_cross_device(const std::error_code& ec) { return ec.category() == std::system_category() && ec.value() == EXDEV; }
bool is_case_variant(const fs::path&, const fs::path&) { return false; }
bool is_exists_error(const std::error_code& ec) {
    return ec.category() == std::system_category() && (ec.value() == EEXIST || ec.value() == ENOTEMPTY);
}
bool is_not_found(const std::error_code& ec) {
    return (ec.category() == std::system_category() && ec.value() == ENOENT) || ec == Errc::not_found;
}

// ---------------------------------------------------------------- create / remove

bool make_dir(const fs::path& p, std::error_code& ec) {
    if (::mkdir(p.c_str(), 0700) != 0) {
        ec = errno_ec(errno);
        return false;
    }
    return true;
}

bool make_dir_default(const fs::path& p, std::error_code& ec) {
    if (::mkdir(p.c_str(), 0777) != 0) {
        ec = errno_ec(errno);
        return false;
    }
    return true;
}

namespace {
// Removal by path goes through the parent directory's fd, so the identity check and the
// unlink name the same directory entry.
bool remove_via_parent(const fs::path& p_in, bool is_dir, const FileId* expect, std::error_code& ec) {
    fs::path p = strip_trailing_separators(p_in);
    fs::path leaf = leaf_name(p);
    if (leaf.empty() || leaf == "." || leaf == "..") {
        ec = make_error_code(Errc::invalid_argument);
        return false;
    }
    Dir parent;
    if (!Dir::open(p.parent_path(), true, parent, ec)) return false;
    return parent.remove_child(leaf, is_dir, expect, ec);
}
} // namespace

bool remove_dir(const fs::path& p, std::error_code& ec, const FileId* expect) {
    return remove_via_parent(p, true, expect, ec);
}

bool remove_nondir(const fs::path& p, std::error_code& ec, const FileId* expect) {
    return remove_via_parent(p, false, expect, ec);
}

bool make_hard_link(const fs::path& target, const fs::path& link, std::error_code& ec) {
    if (::linkat(AT_FDCWD, target.c_str(), AT_FDCWD, link.c_str(), 0) != 0) {
        ec = errno_ec(errno);
        return false;
    }
    return true;
}

bool copy_link(const fs::path& src, const Stat&, const fs::path& dst, std::error_code& ec) {
    std::string target;
    if (!read_link_target(src, target, ec)) return false;
    if (::symlink(target.c_str(), dst.c_str()) != 0) {
        ec = errno_ec(errno);
        return false;
    }
    return true;
}

bool copy_special(const Stat& st, const fs::path& dst, std::error_code& ec) {
    if (st.kind != FileKind::Fifo) {
        ec = make_error_code(Errc::unsupported_file_type);
        return false;
    }
    if (::mkfifo(dst.c_str(), static_cast<mode_t>(st.mode & 07777)) != 0) {
        ec = errno_ec(errno);
        return false;
    }
    return true;
}

void sync_dir(const fs::path& dir) {
    Fd fd(::open(dir.empty() ? "." : dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (fd.ok()) ::fsync(fd.get());
}

} // namespace sys
} // namespace bro::vfs

#endif // !_WIN32
