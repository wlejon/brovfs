#ifdef _WIN32

#include "src/win_util.h"

#include <cstring>
#include <vector>

namespace bro::vfs {

namespace win {

bool stat_handle(HANDLE h, sys::Stat& out, std::error_code& ec) {
    FILE_BASIC_INFO basic{};
    FILE_STANDARD_INFO standard{};
    if (!GetFileInformationByHandleEx(h, FileBasicInfo, &basic, sizeof(basic)) ||
        !GetFileInformationByHandleEx(h, FileStandardInfo, &standard, sizeof(standard))) {
        ec = last_error();
        return false;
    }
    DWORD tag = 0;
    if (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        FILE_ATTRIBUTE_TAG_INFO ti{};
        if (GetFileInformationByHandleEx(h, FileAttributeTagInfo, &ti, sizeof(ti))) tag = ti.ReparseTag;
    }
    out.attributes = basic.FileAttributes;
    out.reparse_tag = tag;
    out.kind = kind_from(basic.FileAttributes, tag, out.link_is_dir);
    out.size = out.kind == FileKind::Regular ? static_cast<uint64_t>(standard.EndOfFile.QuadPart) : 0;
    out.mtime_ns = filetime_to_unix_ns(basic.LastWriteTime.QuadPart);
    out.atime_ns = filetime_to_unix_ns(basic.LastAccessTime.QuadPart);
    out.btime_ns = filetime_to_unix_ns(basic.CreationTime.QuadPart);
    out.nlink = standard.NumberOfLinks;
    FILE_ID_INFO idi{};
    if (GetFileInformationByHandleEx(h, FileIdInfo, &idi, sizeof(idi))) {
        out.id.device = idi.VolumeSerialNumber;
        std::memcpy(&out.id.lo, idi.FileId.Identifier, 8);
        std::memcpy(&out.id.hi, idi.FileId.Identifier + 8, 8);
        out.id.valid = true;
    } else {
        BY_HANDLE_FILE_INFORMATION bh{};
        if (GetFileInformationByHandle(h, &bh)) {
            out.id.device = bh.dwVolumeSerialNumber;
            out.id.lo = (static_cast<uint64_t>(bh.nFileIndexHigh) << 32) | bh.nFileIndexLow;
            out.id.hi = 0;
            out.id.valid = true;
        }
    }
    return true;
}

} // namespace win

namespace sys {

using namespace win;

namespace {

// Fallback for objects that cannot be opened even for attributes (pagefile.sys and friends).
bool stat_find(const fs::path& p, Stat& out, std::error_code& ec) {
    WIN32_FIND_DATAW fd{};
    std::wstring w = win_extended_path(p);
    HANDLE h = FindFirstFileExW(w.c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, 0);
    if (h == INVALID_HANDLE_VALUE) {
        ec = last_error();
        return false;
    }
    FindClose(h);
    DWORD tag = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ? fd.dwReserved0 : 0;
    out = Stat{};
    out.attributes = fd.dwFileAttributes;
    out.reparse_tag = tag;
    out.kind = kind_from(fd.dwFileAttributes, tag, out.link_is_dir);
    out.size = out.kind == FileKind::Regular ? (static_cast<uint64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow : 0;
    out.mtime_ns = filetime_to_unix_ns(ft64(fd.ftLastWriteTime));
    out.atime_ns = filetime_to_unix_ns(ft64(fd.ftLastAccessTime));
    out.btime_ns = filetime_to_unix_ns(ft64(fd.ftCreationTime));
    return true;
}

bool is_not_found_code(DWORD e) {
    return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND || e == ERROR_INVALID_NAME ||
           e == ERROR_BAD_NETPATH || e == ERROR_BAD_NET_NAME;
}

// Delete the object behind `h` (opened with DELETE): POSIX semantics so the name disappears
// at once, ignoring the read-only attribute where the OS supports it.
bool delete_by_handle(HANDLE h, std::error_code& ec) {
    FILE_DISPOSITION_INFO_EX ex{};
    ex.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
               FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
    if (SetFileInformationByHandle(h, FileDispositionInfoEx, &ex, sizeof(ex))) return true;
    DWORD e = GetLastError();
    if (e != ERROR_INVALID_PARAMETER && e != ERROR_NOT_SUPPORTED && e != ERROR_INVALID_FUNCTION) {
        ec = win_error(e);
        return false;
    }
    // Older OS / FAT: classic disposition; clear read-only first.
    FILE_BASIC_INFO basic{};
    if (GetFileInformationByHandleEx(h, FileBasicInfo, &basic, sizeof(basic)) &&
        (basic.FileAttributes & FILE_ATTRIBUTE_READONLY)) {
        FILE_BASIC_INFO nb{};
        nb.FileAttributes = basic.FileAttributes & ~FILE_ATTRIBUTE_READONLY;
        if (nb.FileAttributes == 0) nb.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        SetFileInformationByHandle(h, FileBasicInfo, &nb, sizeof(nb));
    }
    FILE_DISPOSITION_INFO d{};
    d.DeleteFile = TRUE;
    if (SetFileInformationByHandle(h, FileDispositionInfo, &d, sizeof(d))) return true;
    ec = last_error();
    return false;
}

} // namespace

bool lstat(const fs::path& p, Stat& out, std::error_code& ec) {
    out = Stat{};
    Handle h = open_nofollow(p, FILE_READ_ATTRIBUTES);
    if (!h.ok()) {
        DWORD e = GetLastError();
        if (is_not_found_code(e)) {
            ec = win_error(e);
            return false;
        }
        return stat_find(p, out, ec);
    }
    return stat_handle(h.get(), out, ec);
}

bool stat_follow(const fs::path& p, Stat& out, std::error_code& ec) {
    out = Stat{};
    std::wstring w = win_extended_path(p);
    Handle h(CreateFileW(w.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (!h.ok()) {
        ec = last_error();
        return false;
    }
    return stat_handle(h.get(), out, ec);
}

bool list_dir(const fs::path& dir, const std::function<bool(RawEntry&&)>& cb, std::error_code& ec) {
    Handle h = open_nofollow(dir, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE);
    if (!h.ok()) {
        ec = last_error();
        return false;
    }
    Stat self;
    if (!stat_handle(h.get(), self, ec)) return false;
    if (is_link(self.kind)) {
        ec = std::make_error_code(std::errc::too_many_symbolic_link_levels);
        return false;
    }
    if (self.kind != FileKind::Directory) {
        ec = std::make_error_code(std::errc::not_a_directory);
        return false;
    }
    const uint64_t volume = self.id.device;

    std::vector<uint64_t> buffer(64 * 1024 / sizeof(uint64_t));
    FILE_INFO_BY_HANDLE_CLASS cls = FileIdExtdDirectoryInfo;
    bool first = true;
    for (;;) {
        if (!GetFileInformationByHandleEx(h.get(), cls, buffer.data(), static_cast<DWORD>(buffer.size() * 8))) {
            DWORD e = GetLastError();
            if (e == ERROR_NO_MORE_FILES) break;
            if (first && cls == FileIdExtdDirectoryInfo &&
                (e == ERROR_INVALID_PARAMETER || e == ERROR_NOT_SUPPORTED || e == ERROR_INVALID_LEVEL)) {
                cls = FileIdBothDirectoryInfo; // FAT, older SMB servers
                continue;
            }
            ec = win_error(e);
            return false;
        }
        first = false;
        const auto* base = reinterpret_cast<const unsigned char*>(buffer.data());
        for (size_t off = 0;;) {
            RawEntry e;
            DWORD next = 0, attrs = 0, tag = 0;
            int64_t ctime = 0, atime = 0, mtime = 0, size = 0;
            std::wstring_view name;
            if (cls == FileIdExtdDirectoryInfo) {
                const auto* r = reinterpret_cast<const FILE_ID_EXTD_DIR_INFO*>(base + off);
                next = r->NextEntryOffset;
                attrs = r->FileAttributes;
                tag = r->ReparsePointTag;
                ctime = r->CreationTime.QuadPart;
                atime = r->LastAccessTime.QuadPart;
                mtime = r->LastWriteTime.QuadPart;
                size = r->EndOfFile.QuadPart;
                name = std::wstring_view(r->FileName, r->FileNameLength / sizeof(WCHAR));
                std::memcpy(&e.st.id.lo, r->FileId.Identifier, 8);
                std::memcpy(&e.st.id.hi, r->FileId.Identifier + 8, 8);
            } else {
                const auto* r = reinterpret_cast<const FILE_ID_BOTH_DIR_INFO*>(base + off);
                next = r->NextEntryOffset;
                attrs = r->FileAttributes;
                tag = (attrs & FILE_ATTRIBUTE_REPARSE_POINT) ? r->EaSize : 0; // documented overlay
                ctime = r->CreationTime.QuadPart;
                atime = r->LastAccessTime.QuadPart;
                mtime = r->LastWriteTime.QuadPart;
                size = r->EndOfFile.QuadPart;
                name = std::wstring_view(r->FileName, r->FileNameLength / sizeof(WCHAR));
                e.st.id.lo = static_cast<uint64_t>(r->FileId.QuadPart);
                e.st.id.hi = 0;
            }
            if (!(name == L"." || name == L"..")) {
                e.name = fs::path(std::wstring(name));
                e.name_utf8 = utf8_from_wide(name);
                e.st.attributes = attrs;
                e.st.reparse_tag = tag;
                e.st.kind = kind_from(attrs, tag, e.st.link_is_dir);
                e.st.size = e.st.kind == FileKind::Regular ? static_cast<uint64_t>(size) : 0;
                e.st.btime_ns = filetime_to_unix_ns(ctime);
                e.st.atime_ns = filetime_to_unix_ns(atime);
                e.st.mtime_ns = filetime_to_unix_ns(mtime);
                e.st.id.device = volume;
                e.st.id.valid = self.id.valid && (e.st.id.lo != 0 || e.st.id.hi != 0);
                if (!cb(std::move(e))) return true;
            }
            if (next == 0) break;
            off += next;
        }
    }
    return true;
}

std::error_code cross_device_error() { return win_error(ERROR_NOT_SAME_DEVICE); }

bool rename_noreplace(const fs::path& from, const fs::path& to, std::error_code& ec) {
    std::wstring f = win_extended_path(from), t = win_extended_path(to);
    if (MoveFileExW(f.c_str(), t.c_str(), 0)) return true;
    ec = last_error();
    return false;
}

bool rename_replace(const fs::path& from, const fs::path& to, std::error_code& ec) {
    std::wstring f = win_extended_path(from), t = win_extended_path(to);
    if (MoveFileExW(f.c_str(), t.c_str(), MOVEFILE_REPLACE_EXISTING)) return true;
    DWORD e = GetLastError();
    DWORD attrs = GetFileAttributesW(t.c_str());
    if (e == ERROR_ACCESS_DENIED && attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY) &&
        !(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        // The caller decided to overwrite: a read-only destination does not veto that.
        SetFileAttributesW(t.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
        if (MoveFileExW(f.c_str(), t.c_str(), MOVEFILE_REPLACE_EXISTING)) return true;
        e = GetLastError();
        SetFileAttributesW(t.c_str(), attrs);
    }
    ec = win_error(e);
    return false;
}

bool is_cross_device(const std::error_code& ec) {
    return ec.category() == std::system_category() && ec.value() == ERROR_NOT_SAME_DEVICE;
}
bool is_case_variant(const fs::path& a, const fs::path& b) {
    std::wstring x = win_extended_path(a), y = win_extended_path(b);
    if (x == y) return false;
    return CompareStringOrdinal(x.c_str(), static_cast<int>(x.size()), y.c_str(), static_cast<int>(y.size()), TRUE) ==
           CSTR_EQUAL;
}

bool is_exists_error(const std::error_code& ec) {
    return ec.category() == std::system_category() &&
           (ec.value() == ERROR_ALREADY_EXISTS || ec.value() == ERROR_FILE_EXISTS || ec.value() == ERROR_DIR_NOT_EMPTY);
}
bool is_not_found(const std::error_code& ec) {
    return (ec.category() == std::system_category() && is_not_found_code(static_cast<DWORD>(ec.value()))) ||
           ec == Errc::not_found;
}

bool make_dir(const fs::path& p, std::error_code& ec) {
    std::wstring w = win_extended_path(p);
    if (CreateDirectoryW(w.c_str(), nullptr)) return true;
    ec = last_error();
    return false;
}

bool make_dir_default(const fs::path& p, std::error_code& ec) { return make_dir(p, ec); }

bool remove_dir(const fs::path& p, std::error_code& ec, const FileId* expect) {
    Handle h = open_nofollow(p, DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES);
    if (!h.ok()) {
        ec = last_error();
        return false;
    }
    Stat st;
    if (!stat_handle(h.get(), st, ec)) return false;
    if (expect && expect->valid && !(st.id == *expect)) {
        ec = make_error_code(Errc::source_changed);
        return false;
    }
    if (st.kind != FileKind::Directory) {
        ec = std::make_error_code(std::errc::not_a_directory);
        return false;
    }
    return delete_by_handle(h.get(), ec);
}

bool remove_nondir(const fs::path& p, std::error_code& ec, const FileId* expect) {
    Handle h = open_nofollow(p, DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES);
    if (!h.ok()) {
        ec = last_error();
        return false;
    }
    Stat st;
    if (!stat_handle(h.get(), st, ec)) return false;
    if (expect && expect->valid && !(st.id == *expect)) {
        ec = make_error_code(Errc::source_changed);
        return false;
    }
    if (st.kind == FileKind::Directory) {
        ec = std::make_error_code(std::errc::is_a_directory);
        return false;
    }
    // A junction / directory symlink opened with FILE_FLAG_OPEN_REPARSE_POINT is the link
    // itself: deleting it never touches the target's contents.
    return delete_by_handle(h.get(), ec);
}

void sync_dir(const fs::path&) {}

} // namespace sys
} // namespace bro::vfs

#endif // _WIN32
