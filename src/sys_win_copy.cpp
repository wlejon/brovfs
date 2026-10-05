#ifdef _WIN32

#include "src/win_util.h"

#include <cstring>
#include <vector>

namespace bro::vfs::sys {

using namespace win;

namespace {

bool read_reparse(const fs::path& p, std::vector<unsigned char>& buf, std::error_code& ec) {
    Handle h = open_nofollow(p, FILE_READ_ATTRIBUTES);
    if (!h.ok()) {
        ec = last_error();
        return false;
    }
    buf.assign(MAXIMUM_REPARSE_DATA_BUFFER_SIZE, 0);
    DWORD got = 0;
    if (!DeviceIoControl(h.get(), FSCTL_GET_REPARSE_POINT, nullptr, 0, buf.data(), static_cast<DWORD>(buf.size()), &got,
                         nullptr)) {
        ec = last_error();
        return false;
    }
    buf.resize(got);
    return true;
}

struct LinkTarget {
    DWORD tag = 0;
    std::wstring print;
    std::wstring substitute;
    bool relative = false;
};

bool parse_reparse(const std::vector<unsigned char>& buf, LinkTarget& out, std::error_code& ec) {
    if (buf.size() < 8) {
        ec = win_error(ERROR_INVALID_REPARSE_DATA);
        return false;
    }
    const auto* rd = reinterpret_cast<const ReparseData*>(buf.data());
    out.tag = rd->ReparseTag;
    const WCHAR* pb = nullptr;
    USHORT so = 0, sl = 0, po = 0, pl = 0;
    if (rd->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
        pb = rd->Symlink.PathBuffer;
        so = rd->Symlink.SubstituteNameOffset;
        sl = rd->Symlink.SubstituteNameLength;
        po = rd->Symlink.PrintNameOffset;
        pl = rd->Symlink.PrintNameLength;
        out.relative = (rd->Symlink.Flags & kSymlinkFlagRelative) != 0;
    } else if (rd->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
        pb = rd->MountPoint.PathBuffer;
        so = rd->MountPoint.SubstituteNameOffset;
        sl = rd->MountPoint.SubstituteNameLength;
        po = rd->MountPoint.PrintNameOffset;
        pl = rd->MountPoint.PrintNameLength;
    } else {
        ec = win_error(ERROR_NOT_A_REPARSE_POINT);
        return false;
    }
    const auto* end = buf.data() + buf.size();
    auto in_bounds = [&](USHORT off, USHORT len) {
        return reinterpret_cast<const unsigned char*>(pb) + off + len <= end;
    };
    if (!in_bounds(so, sl) || !in_bounds(po, pl)) {
        ec = win_error(ERROR_INVALID_REPARSE_DATA);
        return false;
    }
    out.substitute.assign(pb + so / sizeof(WCHAR), sl / sizeof(WCHAR));
    out.print.assign(pb + po / sizeof(WCHAR), pl / sizeof(WCHAR));
    return true;
}

std::wstring display_target(const LinkTarget& t) {
    if (!t.print.empty()) return t.print;
    std::wstring s = t.substitute;
    if (s.rfind(L"\\??\\UNC\\", 0) == 0) return L"\\\\" + s.substr(8);
    if (s.rfind(L"\\??\\", 0) == 0) return s.substr(4);
    return s;
}

} // namespace

bool read_link_target(const fs::path& link, std::string& target, std::error_code& ec) {
    std::vector<unsigned char> buf;
    LinkTarget t;
    if (!read_reparse(link, buf, ec) || !parse_reparse(buf, t, ec)) return false;
    target = utf8_from_wide(display_target(t));
    return true;
}

bool copy_link(const fs::path& src, const Stat& st, const fs::path& dst, std::error_code& ec) {
    std::vector<unsigned char> buf;
    LinkTarget t;
    if (!read_reparse(src, buf, ec) || !parse_reparse(buf, t, ec)) return false;
    std::wstring d = win_extended_path(dst);
    if (t.tag == IO_REPARSE_TAG_SYMLINK) {
        // Relative targets must be passed through verbatim so they stay relative.
        std::wstring target = t.relative ? (t.print.empty() ? t.substitute : t.print) : display_target(t);
        DWORD flags = (st.link_is_dir ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0) | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
        if (CreateSymbolicLinkW(d.c_str(), target.c_str(), flags)) return true;
        ec = last_error();
        return false;
    }
    // Junction: a directory carrying the same mount-point reparse data. No privilege needed.
    if (!CreateDirectoryW(d.c_str(), nullptr)) {
        ec = last_error();
        return false;
    }
    Handle h = open_nofollow(dst, GENERIC_WRITE);
    DWORD got = 0;
    if (!h.ok() || !DeviceIoControl(h.get(), FSCTL_SET_REPARSE_POINT, buf.data(), static_cast<DWORD>(buf.size()),
                                    nullptr, 0, &got, nullptr)) {
        ec = last_error();
        h.reset();
        RemoveDirectoryW(d.c_str());
        return false;
    }
    return true;
}

bool copy_special(const Stat&, const fs::path&, std::error_code& ec) {
    ec = make_error_code(Errc::unsupported_file_type);
    return false;
}

namespace {

struct CopyContext {
    const DataCopyHooks* hooks = nullptr;
    uint64_t last = 0;
    bool cancelled = false;
};

COPYFILE2_MESSAGE_ACTION CALLBACK copy_progress(const COPYFILE2_MESSAGE* msg, PVOID ctx_ptr) {
    auto* ctx = static_cast<CopyContext*>(ctx_ptr);
    if (msg->Type == COPYFILE2_CALLBACK_CHUNK_FINISHED) {
        uint64_t total = msg->Info.ChunkFinished.uliTotalBytesTransferred.QuadPart;
        uint64_t delta = total > ctx->last ? total - ctx->last : 0;
        ctx->last = total;
        if (ctx->hooks->on_chunk && !ctx->hooks->on_chunk(delta)) {
            ctx->cancelled = true;
            return COPYFILE2_PROGRESS_CANCEL;
        }
    }
    return COPYFILE2_PROGRESS_CONTINUE;
}

} // namespace

CopyMethod copy_file_data(const fs::path& src, const Stat& src_st, const fs::path& dst, const DataCopyHooks& hooks,
                          uint64_t& bytes, std::error_code& ec) {
    bytes = 0;
    if (hooks.require_reflink) {
        // CopyFile2 may block-clone on ReFS (Windows 11 24H2+) but cannot report whether it
        // did, so a guaranteed CoW clone is not claimed on Windows.
        ec = std::make_error_code(std::errc::operation_not_supported);
        return CopyMethod::None;
    }
    std::wstring s = win_extended_path(src), d = win_extended_path(dst);
    CopyContext ctx;
    ctx.hooks = &hooks;
    COPYFILE2_EXTENDED_PARAMETERS params{};
    params.dwSize = sizeof(params);
    // FAIL_IF_EXISTS: `dst` is our fresh temp name, but never clobber anything regardless.
    params.dwCopyFlags = COPY_FILE_FAIL_IF_EXISTS;
    params.pProgressRoutine = copy_progress;
    params.pvCallbackContext = &ctx;
    HRESULT hr = CopyFile2(s.c_str(), d.c_str(), &params);
    if (FAILED(hr)) {
        ec = ctx.cancelled ? make_error_code(Errc::cancelled) : hresult_error(hr);
        if (!(HRESULT_FACILITY(hr) == FACILITY_WIN32 &&
              (HRESULT_CODE(hr) == ERROR_FILE_EXISTS || HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS))) {
            std::error_code rec;
            remove_nondir(dst, rec);
        }
        return CopyMethod::None;
    }
    // Verify: the written size must equal the source as it is now. (Whether the source still
    // matches the plan is the transfer layer's question.)
    Stat now_src, out;
    std::error_code sec;
    auto fail = [&](std::error_code e) {
        ec = e;
        std::error_code rec;
        remove_nondir(dst, rec);
        return CopyMethod::None;
    };
    if (!lstat(dst, out, sec)) return fail(sec);
    if (!lstat(src, now_src, sec)) return fail(sec);
    if (out.size != now_src.size) return fail(make_error_code(Errc::incomplete_copy));
    bytes = out.size;
    if (ctx.last < bytes && hooks.on_chunk && !hooks.on_chunk(bytes - ctx.last)) {
        return fail(make_error_code(Errc::cancelled));
    }
    if (hooks.sync) {
        // A read-only attribute carried over from the source forbids write opens: lift it
        // for the flush only.
        std::wstring dw = win_extended_path(dst);
        DWORD attrs = GetFileAttributesW(dw.c_str());
        bool ro = attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY);
        if (ro) SetFileAttributesW(dw.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
        Handle h = open_nofollow(dst, GENERIC_WRITE);
        bool flushed = h.ok() && FlushFileBuffers(h.get());
        std::error_code fe = flushed ? std::error_code() : last_error();
        h.reset();
        if (ro) SetFileAttributesW(dw.c_str(), attrs);
        if (!flushed) return fail(fe);
    }
    if (!hooks.meta.enabled) {
        // CopyFile2 always carries attributes and times over; reset times to "now" to honour
        // the option (attributes such as read-only stay, as Explorer does).
        Handle h = open_nofollow(dst, FILE_WRITE_ATTRIBUTES);
        FILE_BASIC_INFO bi{};
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        bi.LastWriteTime.QuadPart = ft64(ft);
        if (h.ok()) SetFileInformationByHandle(h.get(), FileBasicInfo, &bi, sizeof(bi));
    } else {
        // CopyFile2 keeps the write time, attributes, streams and EAs but stamps a new
        // creation time; the security descriptor follows only when asked.
        std::error_code bec;
        if (!set_birth_time(dst, src_st.btime_ns, bec) && hooks.warnings) {
            hooks.warnings->push_back({{}, dst, bec, "set creation time"});
        }
        if (hooks.meta.acls) copy_security(src, dst, hooks.meta.owner, hooks.warnings);
    }
    return CopyMethod::KernelCopy;
}

void apply_metadata(const fs::path& src, const fs::path& dst, const Stat& st, const MetaOptions& meta,
                    std::vector<ItemError>* warnings) {
    if (!meta.enabled) return;
    if (st.kind == FileKind::Directory) {
        if (meta.xattrs) copy_streams(src, dst, warnings);
        if (meta.acls) copy_security(src, dst, meta.owner, warnings);
    }
    Handle h = open_nofollow(dst, FILE_WRITE_ATTRIBUTES);
    if (!h.ok()) {
        if (warnings) warnings->push_back({{}, dst, last_error(), "set attributes"});
        return;
    }
    FILE_BASIC_INFO bi{};
    bi.CreationTime.QuadPart = unix_ns_to_filetime(st.btime_ns);
    bi.LastAccessTime.QuadPart = unix_ns_to_filetime(st.atime_ns);
    bi.LastWriteTime.QuadPart = unix_ns_to_filetime(st.mtime_ns);
    DWORD keep = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE |
                 FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    bi.FileAttributes = st.attributes & keep; // 0 = leave unchanged
    if (!SetFileInformationByHandle(h.get(), FileBasicInfo, &bi, sizeof(bi)) && warnings) {
        warnings->push_back({{}, dst, last_error(), "set attributes"});
    }
}

bool reflink_supported(const fs::path& dir) {
    std::wstring w = win_extended_path(dir);
    std::vector<wchar_t> root(w.size() + 2);
    if (!GetVolumePathNameW(w.c_str(), root.data(), static_cast<DWORD>(root.size()))) return false;
    DWORD flags = 0;
    if (!GetVolumeInformationW(root.data(), nullptr, 0, nullptr, nullptr, &flags, nullptr, 0)) return false;
    return (flags & FILE_SUPPORTS_BLOCK_REFCOUNTING) != 0;
}

} // namespace bro::vfs::sys

#endif // _WIN32
