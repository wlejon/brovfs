#pragma once
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>

#include "brovfs/path.h"
#include "src/sys.h"

namespace bro::vfs::win {

class Handle {
public:
    Handle() = default;
    explicit Handle(HANDLE h) : h_(h) {}
    ~Handle() { reset(); }
    Handle(Handle&& o) noexcept : h_(o.h_) { o.h_ = INVALID_HANDLE_VALUE; }
    Handle& operator=(Handle&& o) noexcept {
        if (this != &o) {
            reset();
            h_ = o.h_;
            o.h_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return h_; }
    bool ok() const { return h_ != INVALID_HANDLE_VALUE && h_ != nullptr; }
    HANDLE release() {
        HANDLE h = h_;
        h_ = INVALID_HANDLE_VALUE;
        return h;
    }
    void reset() {
        if (ok()) CloseHandle(h_);
        h_ = INVALID_HANDLE_VALUE;
    }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

inline std::error_code win_error(DWORD e) { return {static_cast<int>(e), std::system_category()}; }
inline std::error_code last_error() { return win_error(GetLastError()); }
inline std::error_code hresult_error(HRESULT hr) {
    if (HRESULT_FACILITY(hr) == FACILITY_WIN32) return win_error(HRESULT_CODE(hr));
    return {static_cast<int>(hr), std::system_category()};
}

constexpr int64_t kFiletimeUnixOffset = 116444736000000000LL; // 100ns ticks 1601 -> 1970
inline int64_t filetime_to_unix_ns(int64_t ft) { return ft == 0 ? 0 : (ft - kFiletimeUnixOffset) * 100; }
inline int64_t unix_ns_to_filetime(int64_t ns) { return ns == 0 ? 0 : ns / 100 + kFiletimeUnixOffset; }
inline int64_t ft64(const FILETIME& ft) {
    return static_cast<int64_t>((static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime);
}

// Opens the object itself (reparse points are not followed), sharing everything.
inline Handle open_nofollow(const fs::path& p, DWORD access, DWORD extra_flags = 0) {
    std::wstring w = win_extended_path(p);
    return Handle(CreateFileW(w.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | extra_flags,
                              nullptr));
}

inline bool is_link_tag(DWORD tag) { return tag == IO_REPARSE_TAG_SYMLINK || tag == IO_REPARSE_TAG_MOUNT_POINT; }

// Kind from attributes + reparse tag. Reparse points that are not links (OneDrive / cloud
// placeholders, dedup, WCI, AppExecLink...) are ordinary files or directories.
inline FileKind kind_from(DWORD attrs, DWORD tag, bool& link_is_dir) {
    link_is_dir = false;
    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) && tag == IO_REPARSE_TAG_SYMLINK) {
        link_is_dir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
        return FileKind::Symlink;
    }
    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) && tag == IO_REPARSE_TAG_MOUNT_POINT) {
        link_is_dir = true;
        return FileKind::Junction;
    }
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) ? FileKind::Directory : FileKind::Regular;
}

bool stat_handle(HANDLE h, sys::Stat& out, std::error_code& ec);

// sys_win_meta.cpp
void copy_security(const fs::path& src, const fs::path& dst, bool owner, std::vector<ItemError>* warnings);
void copy_streams(const fs::path& src, const fs::path& dst, std::vector<ItemError>* warnings);
bool set_birth_time(const fs::path& dst, int64_t btime_ns, std::error_code& ec);

// REPARSE_DATA_BUFFER lives in the DDK (ntifs.h); this is its documented layout.
struct ReparseData {
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } Symlink;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPoint;
    };
};
constexpr ULONG kSymlinkFlagRelative = 1;

} // namespace bro::vfs::win

#endif
