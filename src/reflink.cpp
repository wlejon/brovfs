#include "brovfs/reflink.h"
#include "brovfs/file_ops.h"

#include <filesystem>
#include <system_error>

#ifdef __linux__
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace bro::vfs {

namespace fs = std::filesystem;

bool is_reflink_supported(const std::string& path) {
#ifdef __linux__
    struct statfs sfs;
    if (statfs(path.c_str(), &sfs) == 0) {
        // Btrfs: 0x9123683E, XFS: 0x58465342, ZFS: 0x2FC12FC1
        if (sfs.f_type == 0x9123683E || sfs.f_type == 0x58465342 || sfs.f_type == 0x2FC12FC1) {
            return true;
        }
    }
    return false;
#else
    (void)path;
    return false;
#endif
}

ReflinkResult clone_file(const std::string& src, const std::string& dst, bool allow_fallback) {
    ReflinkResult result;

    fs::path src_p(src);
    std::error_code ec;
    if (!fs::exists(src_p, ec) || fs::is_directory(src_p, ec)) {
        result.success = false;
        result.error_message = "Source file does not exist or is a directory";
        return result;
    }

#ifdef __linux__
    int src_fd = open(src.c_str(), O_RDONLY);
    if (src_fd >= 0) {
        fs::path dst_p(dst);
        if (dst_p.has_parent_path()) {
            fs::create_directories(dst_p.parent_path(), ec);
        }

        struct stat st;
        if (fstat(src_fd, &st) == 0) {
            int dst_fd = open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC, st.st_mode);
            if (dst_fd >= 0) {
#ifdef FICLONE
                if (ioctl(dst_fd, FICLONE, src_fd) == 0) {
                    close(dst_fd);
                    close(src_fd);
                    result.success = true;
                    result.was_reflink = true;
                    return result;
                }
#endif
                // Try copy_file_range if FICLONE failed
                off_t src_off = 0;
                off_t dst_off = 0;
                size_t len = st.st_size;
                ssize_t bytes = copy_file_range(src_fd, &src_off, dst_fd, &dst_off, len, 0);
                if (bytes >= 0 && static_cast<size_t>(bytes) == len) {
                    close(dst_fd);
                    close(src_fd);
                    result.success = true;
                    result.was_reflink = true;
                    return result;
                }
                close(dst_fd);
            }
        }
        close(src_fd);
    }
#endif

    // If CoW reflink is unsupported or failed:
    if (!allow_fallback) {
        result.success = false;
        result.was_reflink = false;
        result.error_message = "Reflink cloning unsupported or failed, and fallback is disabled";
        return result;
    }

    // Fallback standard copy
    FileOpOptions opt;
    opt.conflict_resolution = ConflictResolution::Overwrite;
    if (copy_file(src, dst, opt)) {
        result.success = true;
        result.was_reflink = false;
        return result;
    }

    result.success = false;
    result.was_reflink = false;
    result.error_message = "Fallback file copy failed";
    return result;
}

} // namespace bro::vfs
