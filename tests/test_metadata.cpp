// Metadata preservation on copy and move: hard-link sets, times (birth time where settable),
// mode and group ownership, xattrs on files and directories (Windows: alternate data
// streams), ACLs / DACLs only when asked, and recognising / cleaning crash leftovers.
#include "harness.h"

#include <atomic>
#include <thread>

#ifdef _WIN32
#include <aclapi.h>
#include <sddl.h>
#else
#include <grp.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#endif
#ifdef __APPLE__
#include <sys/acl.h>
#include <sys/attr.h>
#endif

namespace bro::vfs::sys {
extern std::atomic<bool> g_force_cross_device;
}

using namespace t;

namespace {

vfs::FileId id_of(const fs::path& p) {
    vfs::FileEntry e;
    std::error_code ec;
    if (!vfs::stat_entry(p, e, ec)) return vfs::FileId{};
    return e.id;
}

vfs::FileEntry entry(const fs::path& p) {
    vfs::FileEntry e;
    std::error_code ec;
    if (!vfs::stat_entry(p, e, ec)) return vfs::FileEntry{};
    return e;
}

bool make_hard_link(const fs::path& target, const fs::path& link) {
    std::error_code ec;
    fs::create_hard_link(L(target), L(link), ec);
    return !ec;
}

// ------------------------------------------------------------------ platform probes

#ifdef _WIN32
bool write_stream(const fs::path& p, const std::wstring& stream, const std::string& data) {
    std::wstring w = vfs::win_extended_path(p) + L":" + stream;
    HANDLE h = CreateFileW(w.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD put = 0;
    bool ok = WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &put, nullptr) && put == data.size();
    CloseHandle(h);
    return ok;
}

std::string read_stream(const fs::path& p, const std::wstring& stream) {
    std::wstring w = vfs::win_extended_path(p) + L":" + stream;
    HANDLE h = CreateFileW(w.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) return "<missing>";
    std::string out(4096, '\0');
    DWORD got = 0;
    ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &got, nullptr);
    CloseHandle(h);
    out.resize(got);
    return out;
}

// NTFS extended attributes through ntdll (an independent path from the library's).
using NtSetEaFileFn = LONG(NTAPI*)(HANDLE, void*, PVOID, ULONG);
using NtQueryEaFileFn = LONG(NTAPI*)(HANDLE, void*, PVOID, ULONG, BOOLEAN, PVOID, ULONG, PULONG, BOOLEAN);
struct IoStatus {
    void* status_or_pointer;
    ULONG_PTR information;
};

HANDLE open_ea(const fs::path& p, DWORD access) {
    std::wstring w = vfs::win_extended_path(p);
    return CreateFileW(w.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS, nullptr);
}

bool set_ea(const fs::path& p, const std::string& name, const std::string& value) {
    auto fn = reinterpret_cast<NtSetEaFileFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetEaFile")));
    std::vector<unsigned char> buf(8 + name.size() + 1 + value.size() + 4, 0);
    buf[5] = static_cast<unsigned char>(name.size());
    auto vl = static_cast<USHORT>(value.size());
    std::memcpy(buf.data() + 6, &vl, 2);
    std::memcpy(buf.data() + 8, name.data(), name.size());
    std::memcpy(buf.data() + 8 + name.size() + 1, value.data(), value.size());
    HANDLE h = open_ea(p, FILE_WRITE_EA);
    if (h == INVALID_HANDLE_VALUE || !fn) return false;
    IoStatus io{};
    LONG st = fn(h, &io, buf.data(), static_cast<ULONG>(buf.size()));
    CloseHandle(h);
    return st >= 0;
}

// The value of EA `name` (NTFS stores names upper-cased), "<missing>" if absent.
std::string get_ea(const fs::path& p, const std::string& name) {
    auto fn = reinterpret_cast<NtQueryEaFileFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryEaFile")));
    HANDLE h = open_ea(p, FILE_READ_EA);
    if (h == INVALID_HANDLE_VALUE || !fn) return "<missing>";
    std::vector<unsigned char> buf(1 << 17);
    IoStatus io{};
    LONG st = fn(h, &io, buf.data(), static_cast<ULONG>(buf.size()), FALSE, nullptr, 0, nullptr, TRUE);
    CloseHandle(h);
    if (st < 0) return "<missing>";
    for (size_t off = 0;;) {
        ULONG next = 0;
        std::memcpy(&next, buf.data() + off, 4);
        size_t nl = buf[off + 5];
        USHORT vl = 0;
        std::memcpy(&vl, buf.data() + off + 6, 2);
        std::string n(reinterpret_cast<char*>(buf.data() + off + 8), nl);
        if (_stricmp(n.c_str(), name.c_str()) == 0) {
            return std::string(reinterpret_cast<char*>(buf.data() + off + 8 + nl + 1), vl);
        }
        if (next == 0) return "<missing>";
        off += next;
    }
}

PSID everyone() {
    static std::vector<unsigned char> sid;
    if (sid.empty()) {
        DWORD n = SECURITY_MAX_SID_SIZE;
        sid.resize(n);
        CreateWellKnownSid(WinWorldSid, nullptr, sid.data(), &n);
    }
    return sid.data();
}

// Adds an explicit "Everyone: read" ACE; optionally protects the DACL (no inheritance).
bool grant_everyone_read(const fs::path& p, bool protect) {
    std::wstring w = vfs::win_extended_path(p);
    PACL old = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(w.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &old, nullptr,
                              &sd) != ERROR_SUCCESS) {
        return false;
    }
    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = GENERIC_READ;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = static_cast<LPWSTR>(everyone());
    PACL acl = nullptr;
    bool ok = SetEntriesInAclW(1, &ea, old, &acl) == ERROR_SUCCESS;
    if (ok) {
        SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION |
                                  (protect ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION);
        ok = SetNamedSecurityInfoW(const_cast<LPWSTR>(w.c_str()), SE_FILE_OBJECT, si, nullptr, nullptr, acl, nullptr) ==
             ERROR_SUCCESS;
        LocalFree(acl);
    }
    LocalFree(sd);
    return ok;
}

struct DaclFacts {
    bool everyone_explicit = false;
    bool is_protected = false;
};

DaclFacts dacl_facts(const fs::path& p) {
    DaclFacts f;
    std::wstring w = vfs::win_extended_path(p);
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(w.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr,
                              &sd) != ERROR_SUCCESS) {
        return f;
    }
    SECURITY_DESCRIPTOR_CONTROL ctl = 0;
    DWORD rev = 0;
    GetSecurityDescriptorControl(sd, &ctl, &rev);
    f.is_protected = (ctl & SE_DACL_PROTECTED) != 0;
    ACL_SIZE_INFORMATION info{};
    if (dacl && GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation)) {
        for (DWORD i = 0; i < info.AceCount; ++i) {
            void* ace = nullptr;
            if (!GetAce(dacl, i, &ace)) continue;
            auto* hdr = static_cast<ACE_HEADER*>(ace);
            if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE || (hdr->AceFlags & INHERITED_ACE)) continue;
            auto* allowed = static_cast<ACCESS_ALLOWED_ACE*>(ace);
            if (EqualSid(reinterpret_cast<PSID>(&allowed->SidStart), everyone())) f.everyone_explicit = true;
        }
    }
    LocalFree(sd);
    return f;
}

bool set_creation_time(const fs::path& p, int64_t unix_ms) {
    HANDLE h = CreateFileW(vfs::win_extended_path(p).c_str(), FILE_WRITE_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    FILE_BASIC_INFO bi{};
    bi.CreationTime.QuadPart = unix_ms * 10000 + 116444736000000000LL;
    bool ok = SetFileInformationByHandle(h, FileBasicInfo, &bi, sizeof(bi));
    CloseHandle(h);
    return ok;
}
#else
bool set_xattr(const fs::path& p, const char* name, const std::string& v) {
#ifdef __APPLE__
    return ::setxattr(p.c_str(), name, v.data(), v.size(), 0, XATTR_NOFOLLOW) == 0;
#else
    return ::lsetxattr(p.c_str(), name, v.data(), v.size(), 0) == 0;
#endif
}

std::string get_xattr(const fs::path& p, const char* name) {
    std::string v(4096, '\0');
#ifdef __APPLE__
    ssize_t n = ::getxattr(p.c_str(), name, v.data(), v.size(), 0, XATTR_NOFOLLOW);
#else
    ssize_t n = ::lgetxattr(p.c_str(), name, v.data(), v.size());
#endif
    if (n < 0) return "<missing>";
    v.resize(static_cast<size_t>(n));
    return v;
}

#ifdef __linux__
// The kernel's POSIX ACL xattr format (version 2): user::rw- user:<uid>:r-- group::r-- mask::r-- other::---
std::string linux_acl(uint32_t named_uid) {
    std::string a;
    auto u32 = [&](uint32_t v) { a.append(reinterpret_cast<const char*>(&v), 4); };
    auto u16 = [&](uint16_t v) { a.append(reinterpret_cast<const char*>(&v), 2); };
    auto entry = [&](uint16_t tag, uint16_t perm, uint32_t id) {
        u16(tag);
        u16(perm);
        u32(id);
    };
    u32(2);
    entry(0x01, 6, 0xffffffffu);   // USER_OBJ
    entry(0x02, 4, named_uid);     // USER
    entry(0x04, 4, 0xffffffffu);   // GROUP_OBJ
    entry(0x10, 4, 0xffffffffu);   // MASK
    entry(0x20, 0, 0xffffffffu);   // OTHER
    return a;
}
#endif

#ifdef __APPLE__
bool set_birth_time(const fs::path& p, int64_t unix_ms) {
    struct attrlist al{};
    al.bitmapcount = ATTR_BIT_MAP_COUNT;
    al.commonattr = ATTR_CMN_CRTIME;
    struct timespec ts;
    ts.tv_sec = unix_ms / 1000;
    ts.tv_nsec = (unix_ms % 1000) * 1000000;
    return ::setattrlist(p.c_str(), &al, &ts, sizeof(ts), FSOPT_NOFOLLOW) == 0;
}

bool has_extended_acl(const fs::path& p) {
    acl_t a = ::acl_get_link_np(p.c_str(), ACL_TYPE_EXTENDED);
    if (!a) return false;
    acl_entry_t e;
    bool any = ::acl_get_entry(a, ACL_FIRST_ENTRY, &e) == 0;
    ::acl_free(a);
    return any;
}
#endif
#endif

// ------------------------------------------------------------------ tests

void test_hard_links(const Scratch& s) {
    section("hard-link sets inside a copied tree stay linked");
    fs::path src = s / "hl" / "src";
    write_file(src / "a.txt", "shared content");
    write_file(src / "solo.txt", "solo");
    fs::create_directories(L(src / "sub"));
    if (!make_hard_link(src / "a.txt", src / "b.txt") || !make_hard_link(src / "a.txt", src / "sub" / "c.txt")) {
        note("hard links not supported here");
        return;
    }
    auto r = vfs::copy_to(src, s / "hl" / "dst");
    CHECK_MSG(r.ok(), describe(r));
    fs::path d = s / "hl" / "dst";
    CHECK(id_of(d / "a.txt") == id_of(d / "b.txt") && id_of(d / "a.txt") == id_of(d / "sub" / "c.txt"));
    CHECK(!(id_of(d / "a.txt") == id_of(src / "a.txt")));
    CHECK(!(id_of(d / "solo.txt") == id_of(d / "a.txt")));
    CHECK(entry(d / "a.txt").nlink == 3 && read_file(d / "sub" / "c.txt") == "shared content");
    CHECK(r.hard_linked == 2 && r.files_done == 4);

    vfs::FileOpOptions off;
    off.preserve_hard_links = false;
    r = vfs::copy_to(src, s / "hl" / "dst_off", off);
    fs::path o = s / "hl" / "dst_off";
    CHECK_MSG(r.ok() && r.hard_linked == 0, describe(r));
    CHECK(!(id_of(o / "a.txt") == id_of(o / "b.txt")) && entry(o / "a.txt").nlink == 1);

    section("hard links across separate sources of one copy, and a forced cross-device move");
    write_file(s / "hl" / "x" / "one.txt", "one");
    fs::create_directories(L(s / "hl" / "y"));
    make_hard_link(s / "hl" / "x" / "one.txt", s / "hl" / "y" / "two.txt");
    fs::create_directories(L(s / "hl" / "pair"));
    r = vfs::copy_into({s / "hl" / "x" / "one.txt", s / "hl" / "y" / "two.txt"}, s / "hl" / "pair");
    CHECK_MSG(r.ok() && r.hard_linked == 1, describe(r));
    CHECK(id_of(s / "hl" / "pair" / "one.txt") == id_of(s / "hl" / "pair" / "two.txt"));

    {
        bro::vfs::sys::g_force_cross_device = true;
        r = vfs::move_to(src, s / "hl" / "moved");
        bro::vfs::sys::g_force_cross_device = false;
    }
    fs::path m = s / "hl" / "moved";
    CHECK_MSG(r.ok() && !path_exists(src), describe(r));
    CHECK(id_of(m / "a.txt") == id_of(m / "b.txt") && id_of(m / "a.txt") == id_of(m / "sub" / "c.txt"));
}

void test_times_and_mode(const Scratch& s) {
    section("times (incl. birth time where settable) and mode");
    fs::path src = s / "tm" / "src";
    write_file(src / "f.txt", "f");
    write_file(src / "d" / "inner.txt", "i");
    const int64_t old_ms = 1000000000000LL; // 2001-09-09
    std::error_code ec;
    auto old_tp = fs::file_time_type::clock::now() - std::chrono::hours(24 * 365 * 3);
    fs::last_write_time(L(src / "f.txt"), old_tp, ec);
    bool birth_set = false;
#ifdef _WIN32
    birth_set = set_creation_time(src / "f.txt", old_ms) && set_creation_time(src / "d", old_ms);
#elif defined(__APPLE__)
    birth_set = set_birth_time(src / "f.txt", old_ms) && set_birth_time(src / "d", old_ms);
#else
    (void)old_ms;
    ::chmod((src / "f.txt").c_str(), 0640);
    ::chmod((src / "d").c_str(), 0751);
#endif
#ifdef __APPLE__
    ::chmod((src / "f.txt").c_str(), 0640);
    ::chmod((src / "d").c_str(), 0751);
#endif
    fs::last_write_time(L(src / "d"), old_tp, ec);

    auto r = vfs::copy_to(src, s / "tm" / "dst");
    CHECK_MSG(r.ok() && r.warnings.empty(), describe(r));
    fs::path d = s / "tm" / "dst";
    CHECK(entry(d / "f.txt").mtime_ms == entry(src / "f.txt").mtime_ms);
    CHECK(entry(d / "d").mtime_ms == entry(src / "d").mtime_ms);
    if (birth_set) {
        CHECK_MSG(entry(d / "f.txt").birthtime_ms == old_ms, std::to_string(entry(d / "f.txt").birthtime_ms));
        CHECK_MSG(entry(d / "d").birthtime_ms == old_ms, std::to_string(entry(d / "d").birthtime_ms));
    } else {
        note("birth time is not settable on this platform; not checked");
    }
#ifndef _WIN32
    CHECK((entry(d / "f.txt").mode & 07777) == 0640 && (entry(d / "d").mode & 07777) == 0751);
#endif

    vfs::FileOpOptions plain;
    plain.preserve_metadata = false;
    r = vfs::copy_to(src, s / "tm" / "plain", plain);
    CHECK_MSG(r.ok(), describe(r));
    CHECK(entry(s / "tm" / "plain" / "f.txt").mtime_ms > entry(src / "f.txt").mtime_ms + 1000);
}

void test_xattrs(const Scratch& s) {
    section("extended attributes / alternate data streams on files and directories");
    fs::path src = s / "xa" / "src";
    write_file(src / "f.txt", "f");
    fs::create_directories(L(src / "d"));
#ifdef _WIN32
    bool ok = write_stream(src / "f.txt", L"meta", "file stream") && write_stream(src / "d", L"meta", "dir stream");
    if (!ok) {
        note("alternate data streams unsupported on this volume");
        return;
    }
    const bool eas = set_ea(src / "f.txt", "BROVFS.FILE", "file ea") && set_ea(src / "d", "BROVFS.DIR", "dir ea");
    if (!eas) note("extended attributes unsupported on this volume");
    auto r = vfs::copy_to(src, s / "xa" / "dst");
    CHECK_MSG(r.ok() && r.warnings.empty(), describe(r));
    CHECK(read_stream(s / "xa" / "dst" / "f.txt", L"meta") == "file stream");
    CHECK(read_stream(s / "xa" / "dst" / "d", L"meta") == "dir stream");
    if (eas) {
        CHECK(get_ea(s / "xa" / "dst" / "f.txt", "BROVFS.FILE") == "file ea");
        CHECK(get_ea(s / "xa" / "dst" / "d", "BROVFS.DIR") == "dir ea");
        // A forced cross-device move copies the directory, EAs included.
        vfs::sys::g_force_cross_device = true;
        r = vfs::move_to(s / "xa" / "dst", s / "xa" / "moved");
        vfs::sys::g_force_cross_device = false;
        CHECK_MSG(r.ok() && r.warnings.empty(), describe(r));
        CHECK(get_ea(s / "xa" / "moved" / "d", "BROVFS.DIR") == "dir ea");
    }
    vfs::FileOpOptions off;
    off.preserve_xattrs = false;
    r = vfs::copy_to(src, s / "xa" / "off", off);
    CHECK(r.ok() && read_stream(s / "xa" / "off" / "d", L"meta") == "<missing>");
    CHECK(get_ea(s / "xa" / "off" / "d", "BROVFS.DIR") == "<missing>");
#else
#ifdef __APPLE__
    const char* name = "com.example.brovfs";
#else
    const char* name = "user.brovfs";
#endif
    if (!set_xattr(src / "f.txt", name, "file value") || !set_xattr(src / "d", name, "dir value")) {
        note("xattrs unsupported on this file system");
        return;
    }
    auto r = vfs::copy_to(src, s / "xa" / "dst");
    CHECK_MSG(r.ok() && r.warnings.empty(), describe(r));
    CHECK(get_xattr(s / "xa" / "dst" / "f.txt", name) == "file value");
    CHECK(get_xattr(s / "xa" / "dst" / "d", name) == "dir value");
    vfs::FileOpOptions off;
    off.preserve_xattrs = false;
    off.allow_reflink = false;
    r = vfs::copy_to(src, s / "xa" / "off", off);
    CHECK(r.ok() && get_xattr(s / "xa" / "off" / "f.txt", name) == "<missing>" &&
          get_xattr(s / "xa" / "off" / "d", name) == "<missing>");
    {
        // A read-only file still receives its xattrs (they are written before the mode).
        ::chmod((src / "f.txt").c_str(), 0444);
        r = vfs::copy_to(src / "f.txt", s / "xa" / "ro.txt");
        CHECK_MSG(r.ok() && r.warnings.empty() && get_xattr(s / "xa" / "ro.txt", name) == "file value", describe(r));
        ::chmod((src / "f.txt").c_str(), 0644);
    }
#endif
}

void test_acls(const Scratch& s) {
    section("ACLs travel only when asked");
    fs::path src = s / "acl" / "src";
    write_file(src / "f.txt", "f");
    fs::create_directories(L(src / "d"));
#ifdef _WIN32
    if (!grant_everyone_read(src / "f.txt", false) || !grant_everyone_read(src / "d", true)) {
        note("could not set a DACL");
        return;
    }
    auto r = vfs::copy_to(src, s / "acl" / "plain");
    CHECK_MSG(r.ok(), describe(r));
    CHECK(!dacl_facts(s / "acl" / "plain" / "f.txt").everyone_explicit);
    CHECK(!dacl_facts(s / "acl" / "plain" / "d").is_protected);
    vfs::FileOpOptions o;
    o.preserve_acls = true;
    r = vfs::copy_to(src, s / "acl" / "with", o);
    CHECK_MSG(r.ok() && r.warnings.empty(), describe(r));
    auto ff = dacl_facts(s / "acl" / "with" / "f.txt");
    auto fd = dacl_facts(s / "acl" / "with" / "d");
    CHECK(ff.everyone_explicit && !ff.is_protected);
    CHECK(fd.everyone_explicit && fd.is_protected);
#elif defined(__linux__)
    std::string acl = linux_acl(::getuid() + 4242);
    if (!set_xattr(src / "f.txt", "system.posix_acl_access", acl) ||
        !set_xattr(src / "d", "system.posix_acl_default", acl)) {
        note("POSIX ACLs unsupported on this file system");
        return;
    }
    auto r = vfs::copy_to(src, s / "acl" / "plain");
    CHECK_MSG(r.ok(), describe(r));
    CHECK(get_xattr(s / "acl" / "plain" / "f.txt", "system.posix_acl_access") == "<missing>");
    CHECK(get_xattr(s / "acl" / "plain" / "d", "system.posix_acl_default") == "<missing>");
    vfs::FileOpOptions o;
    o.preserve_acls = true;
    r = vfs::copy_to(src, s / "acl" / "with", o);
    CHECK_MSG(r.ok() && r.warnings.empty(), describe(r));
    CHECK(get_xattr(s / "acl" / "with" / "f.txt", "system.posix_acl_access") == acl);
    CHECK(get_xattr(s / "acl" / "with" / "d", "system.posix_acl_default") == acl);
    CHECK((entry(s / "acl" / "with" / "f.txt").mode & 0777) == (entry(src / "f.txt").mode & 0777));
#elif defined(__APPLE__)
    std::string cmd = "/bin/chmod +a 'everyone deny delete' '" + src.string() + "/f.txt' '" + src.string() + "/d'";
    if (std::system(cmd.c_str()) != 0 || !has_extended_acl(src / "f.txt")) {
        note("could not set an extended ACL");
        return;
    }
    vfs::FileOpOptions noclone;
    noclone.allow_reflink = false;
    auto r = vfs::copy_to(src, s / "acl" / "plain", noclone);
    CHECK_MSG(r.ok(), describe(r));
    CHECK(!has_extended_acl(s / "acl" / "plain" / "f.txt") && !has_extended_acl(s / "acl" / "plain" / "d"));
    vfs::FileOpOptions o;
    o.preserve_acls = true;
    r = vfs::copy_to(src, s / "acl" / "with", o);
    CHECK_MSG(r.ok() && r.warnings.empty(), describe(r));
    CHECK(has_extended_acl(s / "acl" / "with" / "f.txt") && has_extended_acl(s / "acl" / "with" / "d"));
    std::system(("/bin/chmod -R -N '" + s.root().string() + "/acl'").c_str());
#endif
}

void test_group_owner(const Scratch& s) {
    section("group ownership where permitted");
#ifdef _WIN32
    note("POSIX ownership: not applicable");
    (void)s;
#else
    if (is_root_user()) {
        note("running as root: full chown is permitted, not exercised");
        return;
    }
    gid_t groups[256];
    int n = ::getgroups(256, groups);
    gid_t other = static_cast<gid_t>(-1);
    for (int i = 0; i < n; ++i) {
        if (groups[i] != ::getegid()) other = groups[i];
    }
    if (other == static_cast<gid_t>(-1)) {
        note("no supplementary group to test with");
        return;
    }
    write_file(s / "grp" / "f.txt", "g");
    if (::chown((s / "grp" / "f.txt").c_str(), static_cast<uid_t>(-1), other) != 0) {
        note("chgrp to a supplementary group refused");
        return;
    }
    auto r = vfs::copy_to(s / "grp" / "f.txt", s / "grp" / "copy.txt");
    CHECK_MSG(r.ok() && r.warnings.empty(), describe(r));
    struct stat st;
    CHECK(::stat((s / "grp" / "copy.txt").c_str(), &st) == 0 && st.st_gid == other);
    vfs::FileOpOptions o;
    o.preserve_owner = false;
    r = vfs::copy_to(s / "grp" / "f.txt", s / "grp" / "mine.txt", o);
    CHECK(r.ok() && ::stat((s / "grp" / "mine.txt").c_str(), &st) == 0 && st.st_gid != other);
#endif
}

void test_leftovers(const Scratch& s) {
    section("crash leftovers are recognised and cleaned");
    CHECK(vfs::is_staging_name(".brovfs-0123456789abcdef.tmp"));
    CHECK(!vfs::is_staging_name(".brovfs-0123456789ABCDEF.tmp"));
    CHECK(!vfs::is_staging_name(".brovfs-0123456789abcde.tmp"));
    CHECK(!vfs::is_staging_name("x.brovfs-0123456789abcdef.tmp"));
    CHECK(!vfs::is_staging_name(".brovfs-0123456789abcdef.tmp2"));

    fs::path root = s / "left";
    write_file(root / ".brovfs-0123456789abcdef.tmp", "half written");
    write_file(root / "sub" / ".brovfs-fedcba9876543210.tmp", "another");
    write_file(root / "keep.txt", "keep");
    write_file(root / ".brovfs-notahexnumber00.tmp", "not ours");
    fs::create_directories(L(root / "dirlike" / ".brovfs-1111111111111111.tmp" / "x")); // a non-empty directory: not ours
    write_file(root / "victim.txt", "victim");
#ifdef _WIN32
    bool link_ok = make_junction(root / ".brovfs-2222222222222222.tmp", root / "sub");
#else
    std::error_code lec;
    fs::create_symlink(root / "victim.txt", root / ".brovfs-2222222222222222.tmp", lec);
    bool link_ok = !lec;
#endif

    auto young = vfs::find_staging_leftovers(root, true, std::chrono::seconds(3600));
    CHECK_MSG(young.empty(), "a fresh staging file may belong to a running operation");
    auto top = vfs::find_staging_leftovers(root, false, std::chrono::seconds(0));
    auto all = vfs::find_staging_leftovers(root, true, std::chrono::seconds(0));
    CHECK_MSG(top.size() == (link_ok ? 2u : 1u), std::to_string(top.size()));
    CHECK_MSG(all.size() == (link_ok ? 3u : 2u), std::to_string(all.size()));

    auto r = vfs::clean_staging_leftovers(root, true, std::chrono::seconds(0));
    CHECK_MSG(r.ok() && r.files_done == 2, describe(r));
    CHECK(!path_exists(root / ".brovfs-0123456789abcdef.tmp") && !path_exists(root / "sub" / ".brovfs-fedcba9876543210.tmp"));
    CHECK(!path_exists(root / ".brovfs-2222222222222222.tmp"));
    CHECK(read_file(root / "keep.txt") == "keep" && read_file(root / "victim.txt") == "victim");
    CHECK(path_exists(root / ".brovfs-notahexnumber00.tmp") && path_exists(root / "dirlike" / ".brovfs-1111111111111111.tmp" / "x"));
    CHECK(path_exists(root / "sub")); // the junction's target is untouched
    CHECK(vfs::find_staging_leftovers(root, true, std::chrono::seconds(0)).empty());
}

} // namespace

int main() {
    Scratch s("meta");
    test_hard_links(s);
    test_times_and_mode(s);
    test_xattrs(s);
    test_acls(s);
    test_group_owner(s);
    test_leftovers(s);
    return finish("test_metadata");
}
