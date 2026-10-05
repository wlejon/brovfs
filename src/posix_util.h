#pragma once
// Private helpers shared by the POSIX platform files.
#ifndef _WIN32

#include "src/sys.h"

#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace bro::vfs::posix {

inline std::error_code errno_ec(int e) { return {e, std::system_category()}; }

class Fd {
public:
    explicit Fd(int fd = -1) : fd_(fd) {}
    ~Fd() { reset(); }
    Fd(Fd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    Fd& operator=(Fd&& o) noexcept {
        if (this != &o) {
            reset();
            fd_ = o.fd_;
            o.fd_ = -1;
        }
        return *this;
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int get() const { return fd_; }
    bool ok() const { return fd_ >= 0; }
    void reset() {
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
    }
    int release() {
        int f = fd_;
        fd_ = -1;
        return f;
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

FileKind kind_from_mode(mode_t m);
// fstatat / statx relative to dirfd (AT_FDCWD for paths). err = errno on failure.
bool stat_at(int dirfd, const char* name, bool follow, sys::Stat& out, int& err);
bool write_all(int fd, const char* p, size_t n, int& err);
mode_t current_umask();
// Lists `fd` (a directory) from the start without moving fd's own offset.
bool list_fd(int fd, const std::function<bool(sys::RawEntry&&)>& cb, std::error_code& ec);

} // namespace bro::vfs::posix

#endif
