// Windows metadata that CopyFile2 does not carry: security descriptors (DACL, and owner/group
// where the process may set them) and alternate data streams of directories.
#ifdef _WIN32

#include "src/win_util.h"

#include <aclapi.h>
#include <sddl.h>

#include <vector>

namespace bro::vfs::win {

namespace {

void warn(std::vector<ItemError>* w, const fs::path& dst, DWORD err, const char* op) {
    if (w) w->push_back({{}, dst, win_error(err), op});
}

struct LocalSd {
    PSECURITY_DESCRIPTOR sd = nullptr;
    ~LocalSd() {
        if (sd) LocalFree(sd);
    }
};

// The explicit ACEs of `dacl` (inherited ones are recomputed from the destination's parent).
bool explicit_aces(PACL dacl, std::vector<unsigned char>& out) {
    ACL_SIZE_INFORMATION info{};
    if (!GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation)) return false;
    out.assign(info.AclBytesInUse + sizeof(ACL), 0);
    auto* acl = reinterpret_cast<PACL>(out.data());
    if (!InitializeAcl(acl, static_cast<DWORD>(out.size()), ACL_REVISION_DS)) return false;
    for (DWORD i = 0; i < info.AceCount; ++i) {
        void* ace = nullptr;
        if (!GetAce(dacl, i, &ace)) return false;
        auto* hdr = static_cast<ACE_HEADER*>(ace);
        if (hdr->AceFlags & INHERITED_ACE) continue;
        if (!AddAce(acl, ACL_REVISION_DS, MAXDWORD, ace, hdr->AceSize)) return false;
    }
    return true;
}

} // namespace

void copy_security(const fs::path& src, const fs::path& dst, bool owner, std::vector<ItemError>* warnings) {
    Handle hs = open_nofollow(src, READ_CONTROL);
    if (!hs.ok()) {
        warn(warnings, dst, GetLastError(), "read security");
        return;
    }
    LocalSd sd;
    PACL dacl = nullptr;
    PSID own = nullptr, grp = nullptr;
    SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION | (owner ? OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION : 0);
    DWORD r = GetSecurityInfo(hs.get(), SE_FILE_OBJECT, si, &own, &grp, &dacl, nullptr, &sd.sd);
    if (r != ERROR_SUCCESS) {
        warn(warnings, dst, r, "read security");
        return;
    }
    SECURITY_DESCRIPTOR_CONTROL ctl = 0;
    DWORD rev = 0;
    GetSecurityDescriptorControl(sd.sd, &ctl, &rev);
    const bool is_protected = (ctl & SE_DACL_PROTECTED) != 0;

    Handle hd = open_nofollow(dst, WRITE_DAC | READ_CONTROL);
    if (!hd.ok()) {
        warn(warnings, dst, GetLastError(), "write security");
        return;
    }
    if (ctl & SE_DACL_PRESENT) {
        std::vector<unsigned char> own_aces;
        PACL to_set = dacl;
        if (!is_protected && dacl) {
            if (!explicit_aces(dacl, own_aces)) {
                warn(warnings, dst, GetLastError(), "write security");
                return;
            }
            to_set = reinterpret_cast<PACL>(own_aces.data());
        }
        SECURITY_INFORMATION wsi = DACL_SECURITY_INFORMATION |
                                   (is_protected ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION);
        r = SetSecurityInfo(hd.get(), SE_FILE_OBJECT, wsi, nullptr, nullptr, to_set, nullptr);
        if (r != ERROR_SUCCESS) warn(warnings, dst, r, "write DACL");
    }
    if (owner && (own || grp)) {
        // Setting another owner needs SeRestorePrivilege; without it this is skipped, as the
        // option promises ("where the process may set them").
        Handle ho = open_nofollow(dst, WRITE_OWNER);
        if (ho.ok()) {
            r = SetSecurityInfo(ho.get(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION, own,
                                grp, nullptr, nullptr);
            if (r != ERROR_SUCCESS && r != ERROR_INVALID_OWNER && r != ERROR_ACCESS_DENIED &&
                r != ERROR_PRIVILEGE_NOT_HELD) {
                warn(warnings, dst, r, "write owner");
            }
        }
    }
}

void copy_streams(const fs::path& src, const fs::path& dst, std::vector<ItemError>* warnings) {
    std::wstring s = win_extended_path(src), d = win_extended_path(dst);
    WIN32_FIND_STREAM_DATA fsd{};
    HANDLE f = FindFirstStreamW(s.c_str(), FindStreamInfoStandard, &fsd, 0);
    if (f == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e != ERROR_HANDLE_EOF && e != ERROR_INVALID_PARAMETER) warn(warnings, dst, e, "list streams");
        return;
    }
    std::vector<char> buf(1 << 16);
    do {
        std::wstring name = fsd.cStreamName; // ":name:$DATA"
        if (name == L"::$DATA") continue;    // the unnamed stream is the file's content
        Handle in(CreateFileW((s + name).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
        Handle out(CreateFileW((d + name).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_FLAG_BACKUP_SEMANTICS,
                               nullptr));
        if (!in.ok() || !out.ok()) {
            warn(warnings, dst, GetLastError(), "copy stream");
            continue;
        }
        for (;;) {
            DWORD got = 0, put = 0;
            if (!ReadFile(in.get(), buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr)) {
                warn(warnings, dst, GetLastError(), "copy stream");
                break;
            }
            if (got == 0) break;
            if (!WriteFile(out.get(), buf.data(), got, &put, nullptr) || put != got) {
                warn(warnings, dst, GetLastError(), "copy stream");
                break;
            }
        }
    } while (FindNextStreamW(f, &fsd));
    FindClose(f);
}

bool set_birth_time(const fs::path& dst, int64_t btime_ns, std::error_code& ec) {
    if (btime_ns == 0) return true;
    Handle h = open_nofollow(dst, FILE_WRITE_ATTRIBUTES);
    FILE_BASIC_INFO bi{}; // zero fields are left unchanged
    bi.CreationTime.QuadPart = unix_ns_to_filetime(btime_ns);
    if (h.ok() && SetFileInformationByHandle(h.get(), FileBasicInfo, &bi, sizeof(bi))) return true;
    ec = last_error();
    return false;
}

} // namespace bro::vfs::win

#endif // _WIN32
