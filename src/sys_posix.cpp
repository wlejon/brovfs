#ifndef _WIN32

#include "src/sys.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/fs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#endif

namespace bro::vfs::sys {

namespace {

std::error_code errno_ec(int e) { return {e, std::system_category()}; }

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

void fill_from_stat(const struct stat& s, Stat& st) {
    st.kind = kind_from_mode(s.st_mode);
    st.size = st.kind == FileKind::Regular || st.kind == FileKind::Symlink ? static_cast<uint64_t>(s.st_size) : 0;
#if defined(__APPLE__)
    st.mtime_ns = static_cast<int64_t>(s.st_mtimespec.tv_sec) * 1000000000 + s.st_mtimespec.tv_nsec;
    st.atime_ns = static_cast<int64_t>(s.st_atimespec.tv_sec) * 1000000000 + s.st_atimespec.tv_nsec;
    st.btime_ns = static_cast<int64_t>(s.st_birthtimespec.tv_sec) * 1000000000 + s.st_birthtimespec.tv_nsec;
#else
    st.mtime_ns = static_cast<int64_t>(s.st_mtim.tv_sec) * 1000000000 + s.st_mtim.tv_nsec;
    st.atime_ns = static_cast<int64_t>(s.st_atim.tv_sec) * 1000000000 + s.st_atim.tv_nsec;
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

void fill_from_statx(const struct statx& s, Stat& st) {
    st.kind = kind_from_mode(s.stx_mode);
    st.size = st.kind == FileKind::Regular || st.kind == FileKind::Symlink ? s.stx_size : 0;
    st.mtime_ns = static_cast<int64_t>(s.stx_mtime.tv_sec) * 1000000000 + s.stx_mtime.tv_nsec;
    st.atime_ns = static_cast<int64_t>(s.stx_atime.tv_sec) * 1000000000 + s.stx_atime.tv_nsec;
    st.btime_ns = (s.stx_mask & STATX_BTIME)
                      ? static_cast<int64_t>(s.stx_btime.tv_sec) * 1000000000 + s.stx_btime.tv_nsec
                      : 0;
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

bool stat_at(int dirfd, const char* name, bool follow, Stat& out, int& err) {
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

class Fd {
public:
    explicit Fd(int fd = -1) : fd_(fd) {}
    ~Fd() { reset(); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int get() const { return fd_; }
    bool ok() const { return fd_ >= 0; }
    void reset() {
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
    }
    int release_close() { // close and return errno-style result (0 ok)
        int r = 0;
        if (fd_ >= 0 && ::close(fd_) != 0) r = errno;
        fd_ = -1;
        return r;
    }

private:
    int fd_;
};

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
    static const mode_t mask = [] {
        std::ifstream in("/proc/self/status");
        std::string line;
        while (std::getline(in, line)) {
            if (line.rfind("Umask:", 0) == 0) return static_cast<mode_t>(std::stoul(line.substr(6), nullptr, 8));
        }
        return static_cast<mode_t>(022);
    }();
    return mask;
}

#ifdef __linux__
void copy_xattrs(int in, int out, const fs::path& dst, std::vector<ItemError>* warnings) {
    ssize_t len = ::flistxattr(in, nullptr, 0);
    if (len <= 0) return;
    std::string names(static_cast<size_t>(len), '\0');
    len = ::flistxattr(in, names.data(), names.size());
    if (len <= 0) return;
    std::string value;
    for (size_t pos = 0; pos < static_cast<size_t>(len);) {
        const char* name = names.c_str() + pos;
        pos += std::strlen(name) + 1;
        // Only the user namespace is portable between file systems and users; security.* and
        // system.* (ACLs) are tied to the source's policy.
        if (std::strncmp(name, "user.", 5) != 0) continue;
        ssize_t vlen = ::fgetxattr(in, name, nullptr, 0);
        if (vlen < 0) continue;
        value.resize(static_cast<size_t>(vlen));
        vlen = ::fgetxattr(in, name, value.data(), value.size());
        if (vlen < 0) continue;
        if (::fsetxattr(out, name, value.data(), static_cast<size_t>(vlen), 0) != 0 && warnings &&
            errno != ENOTSUP && errno != EOPNOTSUPP) {
            warnings->push_back({{}, dst, errno_ec(errno), std::string("setxattr ") + name});
        }
    }
}
#endif

void set_file_metadata(int fd, const fs::path& dst, const Stat& st, bool preserve, std::vector<ItemError>* warnings) {
    mode_t mode = preserve ? static_cast<mode_t>(st.mode & 07777)
                           : static_cast<mode_t>(st.mode & 0777 & ~current_umask());
    if (preserve && ::geteuid() == 0) {
        if (::fchown(fd, st.uid, st.gid) != 0 && warnings) warnings->push_back({{}, dst, errno_ec(errno), "chown"});
    }
    if (::fchmod(fd, mode) != 0 && warnings) warnings->push_back({{}, dst, errno_ec(errno), "chmod"});
    if (preserve) {
        struct timespec ts[2];
        ts[0].tv_sec = st.atime_ns / 1000000000;
        ts[0].tv_nsec = st.atime_ns % 1000000000;
        ts[1].tv_sec = st.mtime_ns / 1000000000;
        ts[1].tv_nsec = st.mtime_ns % 1000000000;
        if (::futimens(fd, ts) != 0 && warnings) warnings->push_back({{}, dst, errno_ec(errno), "set times"});
    }
}

} // namespace

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
    auto deliver = [&](const char* name, unsigned char dtype) -> bool {
        if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0))) return true;
        RawEntry e;
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
        // Copy out the batch: the callback may recurse (scanner) and reuse the thread buffer.
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
    int dup_fd = ::dup(fd.get());
    DIR* d = ::fdopendir(dup_fd);
    if (!d) {
        ec = errno_ec(errno);
        ::close(dup_fd);
        return false;
    }
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
        if (!deliver(de->d_name, de->d_type)) break;
    }
    ::closedir(d);
    return true;
#endif
}

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
#ifdef __linux__
    if (::renameat2(AT_FDCWD, from.c_str(), AT_FDCWD, to.c_str(), RENAME_NOREPLACE) == 0) return true;
    int e = errno;
    if (e != EINVAL && e != ENOSYS && e != ENOTSUP && e != EOPNOTSUPP) {
        ec = errno_ec(e);
        return false;
    }
#endif
    // No RENAME_NOREPLACE on this file system. For non-directories link()+unlink() is atomic
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
bool identity_matches(const fs::path& p, const FileId* expect, std::error_code& ec) {
    if (!expect || !expect->valid) return true;
    Stat st;
    if (!lstat(p, st, ec)) return false;
    if (!(st.id == *expect)) {
        ec = make_error_code(Errc::source_changed);
        return false;
    }
    return true;
}
} // namespace

bool remove_dir(const fs::path& p, std::error_code& ec, const FileId* expect) {
    if (!identity_matches(p, expect, ec)) return false;
    if (::rmdir(p.c_str()) != 0) {
        ec = errno_ec(errno);
        return false;
    }
    return true;
}

bool remove_nondir(const fs::path& p, std::error_code& ec, const FileId* expect) {
    if (!identity_matches(p, expect, ec)) return false;
    if (::unlink(p.c_str()) != 0) {
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

CopyMethod copy_file_data(const fs::path& src, const Stat& src_st, const fs::path& dst, const DataCopyHooks& hooks,
                          uint64_t& bytes, std::error_code& ec) {
    bytes = 0;
    Fd in(::open(src.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if (!in.ok()) {
        ec = errno_ec(errno);
        return CopyMethod::None;
    }
    struct stat ins;
    if (::fstat(in.get(), &ins) != 0) {
        ec = errno_ec(errno);
        return CopyMethod::None;
    }
    if (!S_ISREG(ins.st_mode) || (src_st.id.valid && (static_cast<uint64_t>(ins.st_ino) != src_st.id.lo ||
                                                      static_cast<uint64_t>(ins.st_dev) != src_st.id.device))) {
        ec = make_error_code(Errc::source_changed);
        return CopyMethod::None;
    }
    Fd out(::open(dst.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (!out.ok()) {
        ec = errno_ec(errno);
        return CopyMethod::None;
    }
    auto fail = [&](std::error_code e) {
        ec = e;
        out.reset();
        ::unlink(dst.c_str());
        return CopyMethod::None;
    };
    auto report = [&](uint64_t delta) { return !hooks.on_chunk || hooks.on_chunk(delta); };

    CopyMethod method = CopyMethod::None;
#if defined(__linux__) && defined(FICLONE)
    if (hooks.allow_reflink) {
        if (::ioctl(out.get(), FICLONE, in.get()) == 0) {
            method = CopyMethod::Reflink;
            bytes = static_cast<uint64_t>(ins.st_size);
            if (!report(bytes)) return fail(make_error_code(Errc::cancelled));
        } else if (::ftruncate(out.get(), 0) != 0) {
            return fail(errno_ec(errno));
        }
    }
#endif
    if (hooks.require_reflink && method != CopyMethod::Reflink) {
        return fail(std::make_error_code(std::errc::operation_not_supported));
    }
#ifdef __linux__
    if (method == CopyMethod::None && hooks.allow_kernel_copy) {
        bool fallback = false;
        for (;;) {
            ssize_t r = ::copy_file_range(in.get(), nullptr, out.get(), nullptr, 8u << 20, 0);
            if (r < 0) {
                int e = errno;
                if (e == EINTR) continue;
                if (bytes == 0 && (e == EXDEV || e == EINVAL || e == ENOSYS || e == EOPNOTSUPP || e == ENOTSUP ||
                                   e == EPERM || e == EBADF)) {
                    fallback = true;
                    break;
                }
                return fail(errno_ec(e));
            }
            if (r == 0) {
                // Some file systems (procfs-like) report 0 early; let the stream loop confirm EOF.
                if (bytes < static_cast<uint64_t>(ins.st_size)) fallback = true;
                break;
            }
            bytes += static_cast<uint64_t>(r);
            if (!report(static_cast<uint64_t>(r))) return fail(make_error_code(Errc::cancelled));
        }
        if (!fallback) method = CopyMethod::KernelCopy;
    }
#endif
    if (method == CopyMethod::None) {
        std::vector<char> buf(hooks.buffer_size ? hooks.buffer_size : (1u << 20));
        uint64_t streamed = 0;
        for (;;) {
            ssize_t r = ::read(in.get(), buf.data(), buf.size());
            if (r < 0) {
                if (errno == EINTR) continue;
                return fail(errno_ec(errno));
            }
            if (r == 0) break;
            int err = 0;
            if (!write_all(out.get(), buf.data(), static_cast<size_t>(r), err)) return fail(errno_ec(err));
            bytes += static_cast<uint64_t>(r);
            streamed += static_cast<uint64_t>(r);
            if (!report(static_cast<uint64_t>(r))) return fail(make_error_code(Errc::cancelled));
        }
        method = streamed > 0 && bytes > streamed ? CopyMethod::KernelCopy : CopyMethod::Stream;
    }

    struct stat after;
    if (::fstat(in.get(), &after) != 0) return fail(errno_ec(errno));
    struct stat outs;
    if (::fstat(out.get(), &outs) != 0) return fail(errno_ec(errno));
    if (bytes != static_cast<uint64_t>(after.st_size) || static_cast<uint64_t>(outs.st_size) != bytes) {
        return fail(make_error_code(Errc::incomplete_copy));
    }

#ifdef __linux__
    if (hooks.preserve_metadata) copy_xattrs(in.get(), out.get(), dst, hooks.warnings);
#endif
    set_file_metadata(out.get(), dst, src_st, hooks.preserve_metadata, hooks.warnings);
    if (hooks.sync && ::fsync(out.get()) != 0) return fail(errno_ec(errno));
    int close_err = out.release_close(); // NFS and friends report write errors at close
    if (close_err != 0) {
        ec = errno_ec(close_err);
        ::unlink(dst.c_str());
        return CopyMethod::None;
    }
    return method;
}

void apply_metadata(const fs::path& dst, const Stat& st, std::vector<ItemError>* warnings) {
    bool link = st.kind == FileKind::Symlink;
    if (::geteuid() == 0 && ::lchown(dst.c_str(), st.uid, st.gid) != 0 && warnings) {
        warnings->push_back({{}, dst, errno_ec(errno), "chown"});
    }
    if (!link && ::chmod(dst.c_str(), static_cast<mode_t>(st.mode & 07777)) != 0 && warnings) {
        warnings->push_back({{}, dst, errno_ec(errno), "chmod"});
    }
    struct timespec ts[2];
    ts[0].tv_sec = st.atime_ns / 1000000000;
    ts[0].tv_nsec = st.atime_ns % 1000000000;
    ts[1].tv_sec = st.mtime_ns / 1000000000;
    ts[1].tv_nsec = st.mtime_ns % 1000000000;
    if (::utimensat(AT_FDCWD, dst.c_str(), ts, link ? AT_SYMLINK_NOFOLLOW : 0) != 0 && warnings &&
        !(link && errno == EOPNOTSUPP)) {
        warnings->push_back({{}, dst, errno_ec(errno), "set times"});
    }
}

void sync_dir(const fs::path& dir) {
    Fd fd(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (fd.ok()) ::fsync(fd.get());
}

bool reflink_supported(const fs::path& dir) {
#if defined(__linux__) && defined(FICLONE)
    fs::path a = temp_sibling(dir), b = temp_sibling(dir);
    Fd fa(::open(a.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    if (!fa.ok()) return false;
    Fd fb(::open(b.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    bool ok = false;
    if (fb.ok()) {
        std::vector<char> block(64 * 1024, 'r');
        int err = 0;
        if (write_all(fa.get(), block.data(), block.size(), err)) ok = ::ioctl(fb.get(), FICLONE, fa.get()) == 0;
        fb.reset();
        ::unlink(b.c_str());
    }
    fa.reset();
    ::unlink(a.c_str());
    return ok;
#else
    (void)dir;
    return false;
#endif
}

} // namespace bro::vfs::sys

#endif // !_WIN32
