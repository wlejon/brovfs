// POSIX data copy and metadata: FICLONE / clonefile reflinks, copy_file_range, the stream
// loop, and what travels with a copy (mode, ownership where permitted, times, birth time on
// macOS, xattrs, POSIX / extended ACLs).
#ifndef _WIN32

#include "src/posix_util.h"

#include <cstring>
#include <string>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <vector>

#ifdef __linux__
#include <linux/fs.h>
#include <sys/xattr.h>
#endif
#ifdef __APPLE__
#include <copyfile.h>
#include <ctime>
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/xattr.h>
#endif

namespace bro::vfs::sys {

using namespace posix;

namespace {

void warn(std::vector<ItemError>* w, const fs::path& dst, int err, std::string op) {
    if (w) w->push_back({{}, dst, errno_ec(err), std::move(op)});
}

bool unsupported(int e) { return e == ENOTSUP || e == EOPNOTSUPP; }

#ifdef __linux__
// Which extended attributes travel. user.* is the portable namespace; the POSIX ACLs are
// system.posix_acl_*; trusted.* and security.* (SELinux labels, file capabilities) belong to
// the source's policy and are never copied.
enum class XattrPass { User, Acl };

bool wanted(const char* name, XattrPass pass) {
    if (pass == XattrPass::User) return std::strncmp(name, "user.", 5) == 0;
    return std::strcmp(name, "system.posix_acl_access") == 0 || std::strcmp(name, "system.posix_acl_default") == 0;
}

void copy_xattrs(int in, int out, XattrPass pass, const fs::path& dst, std::vector<ItemError>* warnings) {
    ssize_t len = ::flistxattr(in, nullptr, 0);
    if (len <= 0) return;
    std::string names(static_cast<size_t>(len), '\0');
    len = ::flistxattr(in, names.data(), names.size());
    if (len <= 0) return;
    std::string value;
    for (size_t pos = 0; pos < static_cast<size_t>(len);) {
        const char* name = names.c_str() + pos;
        pos += std::strlen(name) + 1;
        if (!wanted(name, pass)) continue;
        ssize_t vlen = ::fgetxattr(in, name, nullptr, 0);
        if (vlen < 0) continue;
        value.resize(static_cast<size_t>(vlen));
        vlen = ::fgetxattr(in, name, value.data(), value.size());
        if (vlen < 0) continue;
        if (::fsetxattr(out, name, value.data(), static_cast<size_t>(vlen), 0) != 0) {
            warn(warnings, dst, errno, std::string("setxattr ") + name);
        }
    }
}
#endif

#ifdef __APPLE__
void set_birth_time(int fd, const char* path, int64_t btime_ns, const fs::path& dst, std::vector<ItemError>* w) {
    if (btime_ns == 0) return;
    struct attrlist al{};
    al.bitmapcount = ATTR_BIT_MAP_COUNT;
    al.commonattr = ATTR_CMN_CRTIME;
    struct timespec ts;
    ts.tv_sec = btime_ns / 1000000000;
    ts.tv_nsec = btime_ns % 1000000000;
    int r = fd >= 0 ? ::fsetattrlist(fd, &al, &ts, sizeof(ts), 0)
                    : ::setattrlist(path, &al, &ts, sizeof(ts), FSOPT_NOFOLLOW);
    if (r != 0 && !unsupported(errno)) warn(w, dst, errno, "set birth time");
}

copyfile_flags_t mac_flags(const MetaOptions& m) {
    return (m.xattrs ? COPYFILE_XATTR : 0) | (m.acls ? COPYFILE_ACL : 0);
}

// Removes an extended ACL (the way `chmod -N` does).
void strip_acl(const char* path) {
    filesec_t fsec = ::filesec_init();
    if (!fsec) return;
    if (::filesec_set_property(fsec, FILESEC_ACL, _FILESEC_REMOVE_ACL) == 0) ::chmodx_np(path, fsec);
    ::filesec_free(fsec);
}
#endif

void set_owner(int fd, const char* path, const Stat& st, const MetaOptions& m, const fs::path& dst,
               std::vector<ItemError>* w) {
    if (!m.owner) return;
    const bool root = ::geteuid() == 0;
    uid_t uid = root ? static_cast<uid_t>(st.uid) : static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(st.gid);
    if (!root && gid == ::getegid()) return; // already the default group of what we create
    int r = fd >= 0 ? ::fchown(fd, uid, gid) : ::lchown(path, uid, gid);
    // Unprivileged: only a group we belong to is permitted; anything else is skipped silently.
    if (r != 0 && (root || errno != EPERM)) warn(w, dst, errno, "chown");
}

struct timespec to_ts(int64_t ns) {
    struct timespec t;
    t.tv_sec = ns / 1000000000;
    t.tv_nsec = ns % 1000000000;
    return t;
}

// Order matters: user xattrs need write permission (before chmod), chown clears set-id bits
// (before chmod), an ACL write rewrites the group bits (after chmod), times last.
void set_file_metadata(int in, int out, const fs::path& dst, const Stat& st, const MetaOptions& m,
                       std::vector<ItemError>* warnings) {
    if (!m.enabled) {
        if (::fchmod(out, static_cast<mode_t>(st.mode & 0777 & ~current_umask())) != 0) warn(warnings, dst, errno, "chmod");
        return;
    }
#ifdef __linux__
    if (m.xattrs) copy_xattrs(in, out, XattrPass::User, dst, warnings);
#endif
#ifdef __APPLE__
    if (mac_flags(m) && ::fcopyfile(in, out, nullptr, mac_flags(m)) != 0) warn(warnings, dst, errno, "copy xattrs/ACL");
#endif
    set_owner(out, nullptr, st, m, dst, warnings);
    if (::fchmod(out, static_cast<mode_t>(st.mode & 07777)) != 0) warn(warnings, dst, errno, "chmod");
#ifdef __linux__
    if (m.acls) copy_xattrs(in, out, XattrPass::Acl, dst, warnings);
#endif
    (void)in;
    struct timespec ts[2] = {to_ts(st.atime_ns), to_ts(st.mtime_ns)};
    if (::futimens(out, ts) != 0) warn(warnings, dst, errno, "set times");
#ifdef __APPLE__
    set_birth_time(out, nullptr, st.btime_ns, dst, warnings);
#endif
}

} // namespace

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
    auto report = [&](uint64_t delta) { return !hooks.on_chunk || hooks.on_chunk(delta); };
    CopyMethod method = CopyMethod::None;
    Fd out;

#ifdef __APPLE__
    // clonefile creates the destination itself (exclusively) and shares the extents.
    if (hooks.allow_reflink) {
        if (::fclonefileat(in.get(), AT_FDCWD, dst.c_str(), CLONE_NOFOLLOW | CLONE_NOOWNERCOPY) == 0) {
            // The clone carries the source's mode, ACL, times and xattrs. Make it ours to
            // write (a read-only source gives a read-only clone) and drop its ACL: an ACL is
            // applied after the commit rename, or not at all (sys.h, staged_meta).
            strip_acl(dst.c_str());
            ::chmod(dst.c_str(), 0600);
            out = Fd(::open(dst.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC));
            if (!out.ok()) {
                ec = errno_ec(errno);
                ::unlink(dst.c_str());
                return CopyMethod::None;
            }
            method = CopyMethod::Reflink;
            bytes = static_cast<uint64_t>(ins.st_size);
            if (!hooks.meta.xattrs || !hooks.meta.enabled) {
                // A clone carries every xattr; drop them when they were not asked for.
                ssize_t len = ::flistxattr(out.get(), nullptr, 0, 0);
                if (len > 0) {
                    std::string names(static_cast<size_t>(len), '\0');
                    len = ::flistxattr(out.get(), names.data(), names.size(), 0);
                    for (size_t pos = 0; len > 0 && pos < static_cast<size_t>(len);) {
                        const char* name = names.c_str() + pos;
                        pos += std::strlen(name) + 1;
                        ::fremovexattr(out.get(), name, 0);
                    }
                }
            }
            if (!hooks.meta.enabled) {
                // A plain copy is a new file: now, not the source's times.
                ::futimens(out.get(), nullptr);
                struct timespec now{};
                ::clock_gettime(CLOCK_REALTIME, &now);
                set_birth_time(out.get(), nullptr, static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec, dst,
                               hooks.warnings);
            }
        } else if (errno == EEXIST) {
            ec = errno_ec(errno);
            return CopyMethod::None;
        }
    }
#endif
    if (hooks.require_reflink && method != CopyMethod::Reflink) {
#if defined(__linux__) && defined(FICLONE)
        // Linux tries FICLONE below on the exclusively created destination.
#else
        if (out.ok()) ::unlink(dst.c_str());
        ec = std::make_error_code(std::errc::operation_not_supported);
        return CopyMethod::None;
#endif
    }
    if (!out.ok()) {
        out = Fd(::open(dst.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (!out.ok()) {
            ec = errno_ec(errno);
            return CopyMethod::None;
        }
    }
    auto fail = [&](std::error_code e) {
        ec = e;
        out.reset();
        ::unlink(dst.c_str());
        return CopyMethod::None;
    };
    if (method == CopyMethod::Reflink && !report(bytes)) return fail(make_error_code(Errc::cancelled));

#if defined(__linux__) && defined(FICLONE)
    if (method == CopyMethod::None && hooks.allow_reflink) {
        if (::ioctl(out.get(), FICLONE, in.get()) == 0) {
            method = CopyMethod::Reflink;
            bytes = static_cast<uint64_t>(ins.st_size);
            if (!report(bytes)) return fail(make_error_code(Errc::cancelled));
        } else if (::ftruncate(out.get(), 0) != 0) {
            return fail(errno_ec(errno));
        }
    }
    if (hooks.require_reflink && method != CopyMethod::Reflink) {
        return fail(std::make_error_code(std::errc::operation_not_supported));
    }
#endif
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

    set_file_metadata(in.get(), out.get(), dst, src_st, hooks.meta, hooks.warnings);
    if (hooks.sync && ::fsync(out.get()) != 0) return fail(errno_ec(errno));
    int close_err = out.release_close(); // NFS and friends report write errors at close
    if (close_err != 0) {
        ec = errno_ec(close_err);
        ::unlink(dst.c_str());
        return CopyMethod::None;
    }
    return method;
}

void apply_metadata(const fs::path& src, const fs::path& dst, const Stat& st, const MetaOptions& m,
                    std::vector<ItemError>* warnings) {
    if (!m.enabled) return;
    const bool link = st.kind == FileKind::Symlink;
    const bool dir = st.kind == FileKind::Directory;
    // Directories are opened so every step names the object we created, not a path.
    Fd out, in;
    if (dir) {
        out = Fd(::open(dst.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        in = Fd(::open(src.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (!out.ok()) {
            warn(warnings, dst, errno, "open directory");
            return;
        }
    }
#ifdef __linux__
    if (dir && in.ok() && m.xattrs) copy_xattrs(in.get(), out.get(), XattrPass::User, dst, warnings);
#endif
#ifdef __APPLE__
    if (mac_flags(m)) {
        int r = 0;
        if (dir) {
            r = in.ok() ? ::fcopyfile(in.get(), out.get(), nullptr, mac_flags(m)) : 0;
        } else if (link) {
            r = ::copyfile(src.c_str(), dst.c_str(), nullptr, mac_flags(m) | COPYFILE_NOFOLLOW);
        } else if (st.kind == FileKind::Regular || st.kind == FileKind::Fifo) {
            // Never by path: copyfile() opens a FIFO blocking and would wait for a writer.
            // Devices are not opened at all (an open can have side effects); sockets cannot be.
            Fd a(::open(src.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
            Fd b(::open(dst.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
            r = a.ok() && b.ok() ? ::fcopyfile(a.get(), b.get(), nullptr, mac_flags(m)) : 0;
        }
        if (r != 0) warn(warnings, dst, errno, "copy xattrs/ACL");
    }
#endif
    set_owner(out.ok() ? out.get() : -1, dst.c_str(), st, m, dst, warnings);
    if (!link) {
        int r = out.ok() ? ::fchmod(out.get(), static_cast<mode_t>(st.mode & 07777))
                         : ::chmod(dst.c_str(), static_cast<mode_t>(st.mode & 07777));
        if (r != 0) warn(warnings, dst, errno, "chmod");
    }
#ifdef __linux__
    if (dir && in.ok() && m.acls) copy_xattrs(in.get(), out.get(), XattrPass::Acl, dst, warnings);
#endif
    struct timespec ts[2] = {to_ts(st.atime_ns), to_ts(st.mtime_ns)};
    int r = out.ok() ? ::futimens(out.get(), ts) : ::utimensat(AT_FDCWD, dst.c_str(), ts, link ? AT_SYMLINK_NOFOLLOW : 0);
    if (r != 0 && !(link && unsupported(errno))) warn(warnings, dst, errno, "set times");
#ifdef __APPLE__
    set_birth_time(out.ok() ? out.get() : -1, dst.c_str(), st.btime_ns, dst, warnings);
#endif
}

#ifdef __APPLE__
void apply_acl_committed(const fs::path& src, const fs::path& dst, const Stat& st, const MetaOptions& m,
                         std::vector<ItemError>* warnings) {
    if (!m.enabled || !m.acls) return;
    int r = 0;
    if (st.kind == FileKind::Symlink) {
        r = ::copyfile(src.c_str(), dst.c_str(), nullptr, COPYFILE_ACL | COPYFILE_NOFOLLOW);
    } else if (st.kind == FileKind::Regular || st.kind == FileKind::Fifo) {
        Fd a(::open(src.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
        Fd b(::open(dst.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
        if (!a.ok() || !b.ok()) {
            warn(warnings, dst, errno, "copy ACL");
            return;
        }
        r = ::fcopyfile(a.get(), b.get(), nullptr, COPYFILE_ACL);
    }
    if (r != 0) warn(warnings, dst, errno, "copy ACL");
}
#endif

bool reflink_supported(const fs::path& dir) {
#if (defined(__linux__) && defined(FICLONE)) || defined(__APPLE__)
    fs::path a = temp_sibling(dir), b = temp_sibling(dir);
    Fd fa(::open(a.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    if (!fa.ok()) return false;
    bool ok = false;
    std::vector<char> block(64 * 1024, 'r');
    int err = 0;
    if (write_all(fa.get(), block.data(), block.size(), err)) {
#ifdef __APPLE__
        ok = ::fclonefileat(fa.get(), AT_FDCWD, b.c_str(), CLONE_NOFOLLOW) == 0;
        if (ok) ::unlink(b.c_str());
#else
        Fd fb(::open(b.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
        if (fb.ok()) {
            ok = ::ioctl(fb.get(), FICLONE, fa.get()) == 0;
            fb.reset();
            ::unlink(b.c_str());
        }
#endif
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
