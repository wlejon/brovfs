// Move: rename semantics, conflicts, merge, and the cross-device copy + verified delete path
// (forced on one volume through the test hook, and for real across volumes when available).
#include "harness.h"

#include <atomic>
#include <set>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace bro::vfs::sys {
extern std::atomic<bool> g_force_cross_device;
}

using namespace t;

struct ForceCrossDevice {
    ForceCrossDevice() { bro::vfs::sys::g_force_cross_device = true; }
    ~ForceCrossDevice() { bro::vfs::sys::g_force_cross_device = false; }
};

static vfs::FileOpOptions policy(vfs::ConflictPolicy p) {
    vfs::FileOpOptions o;
    o.conflict = p;
    return o;
}

static std::set<std::string> names_in(const fs::path& dir) {
    std::set<std::string> out;
    for (auto& e : vfs::scan_directory(dir).entries) out.insert(e.name);
    return out;
}

static void test_rename(const Scratch& s) {
    section("same-volume move is a rename");
    write_file(s / "rn" / "f.txt", "f");
    write_file(s / "rn" / "d" / "inner.txt", "i");
    auto r = vfs::move_into({s / "rn" / "f.txt", s / "rn" / "d"}, s / "rn_out");
    CHECK(!r.ok()); // destination folder does not exist: honest failure, nothing moved
    CHECK(path_exists(s / "rn" / "f.txt") && path_exists(s / "rn" / "d" / "inner.txt"));
    fs::create_directories(s / "rn_out");
    r = vfs::move_into({s / "rn" / "f.txt", s / "rn" / "d"}, s / "rn_out");
    CHECK_MSG(r.ok(), describe(r));
    CHECK(!path_exists(s / "rn" / "f.txt") && !path_exists(s / "rn" / "d"));
    CHECK(read_file(s / "rn_out" / "f.txt") == "f" && read_file(s / "rn_out" / "d" / "inner.txt") == "i");
    CHECK(r.created.size() == 2 && r.kernel_copied == 0 && r.bytes_done == 0);
}

static void test_conflicts(const Scratch& s) {
    section("move conflicts");
    write_file(s / "mc" / "src" / "f.txt", "new");
    write_file(s / "mc" / "dst" / "f.txt", "old");
    auto r = vfs::move_into({s / "mc" / "src" / "f.txt"}, s / "mc" / "dst");
    CHECK(has_error(r, vfs::Errc::conflict_unresolved));
    CHECK(read_file(s / "mc" / "src" / "f.txt") == "new" && read_file(s / "mc" / "dst" / "f.txt") == "old");
    r = vfs::move_into({s / "mc" / "src" / "f.txt"}, s / "mc" / "dst", policy(vfs::ConflictPolicy::KeepBoth));
    CHECK(r.ok() && read_file(s / "mc" / "dst" / "f (2).txt") == "new" && !path_exists(s / "mc" / "src" / "f.txt"));
    write_file(s / "mc" / "src" / "f.txt", "newer");
    r = vfs::move_into({s / "mc" / "src" / "f.txt"}, s / "mc" / "dst", policy(vfs::ConflictPolicy::Overwrite));
    CHECK(r.ok() && read_file(s / "mc" / "dst" / "f.txt") == "newer" && !path_exists(s / "mc" / "src" / "f.txt"));

    section("merge into an existing folder; skipped items keep their source folder");
    write_file(s / "mg" / "src" / "tree" / "a.txt", "a");
    write_file(s / "mg" / "src" / "tree" / "b.txt", "b-new");
    write_file(s / "mg" / "src" / "tree" / "sub" / "c.txt", "c");
    write_file(s / "mg" / "dst" / "tree" / "b.txt", "b-old");
    write_file(s / "mg" / "dst" / "tree" / "sub" / "d.txt", "d");
    r = vfs::move_into({s / "mg" / "src" / "tree"}, s / "mg" / "dst", policy(vfs::ConflictPolicy::Skip));
    CHECK_MSG(r.ok() && r.skipped == 1, describe(r));
    CHECK(read_file(s / "mg" / "dst" / "tree" / "a.txt") == "a" && read_file(s / "mg" / "dst" / "tree" / "b.txt") == "b-old");
    CHECK(read_file(s / "mg" / "dst" / "tree" / "sub" / "c.txt") == "c" && read_file(s / "mg" / "dst" / "tree" / "sub" / "d.txt") == "d");
    CHECK(read_file(s / "mg" / "src" / "tree" / "b.txt") == "b-new" && !path_exists(s / "mg" / "src" / "tree" / "sub"));
}

static void test_same_file(const Scratch& s) {
    section("moving onto itself is refused; case-only rename works");
    fs::path a = s / "sf" / "Case.txt";
    write_file(a, "data");
    auto r = vfs::move_to(a, a, policy(vfs::ConflictPolicy::Overwrite));
    CHECK(has_error(r, vfs::Errc::same_file) && read_file(a) == "data");
    std::error_code ec;
    fs::create_hard_link(L(a), L(s / "sf" / "hard.txt"), ec);
    if (!ec) {
        r = vfs::move_to(a, s / "sf" / "hard.txt", policy(vfs::ConflictPolicy::Overwrite));
        CHECK(has_error(r, vfs::Errc::same_file) && read_file(a) == "data" && read_file(s / "sf" / "hard.txt") == "data");
    }
#ifdef _WIN32
    r = vfs::move_to(a, s / "sf" / "case.TXT");
    CHECK_MSG(r.ok(), describe(r));
    auto names = names_in(s / "sf");
    CHECK(names.count("case.TXT") == 1 && names.count("Case.txt") == 0);
    CHECK(read_file(s / "sf" / "case.TXT") == "data");
#endif
    write_file(s / "sf" / "dir" / "sub" / "x", "x");
    r = vfs::move_into({s / "sf" / "dir"}, s / "sf" / "dir" / "sub");
    CHECK(has_error(r, vfs::Errc::destination_inside_source) && read_file(s / "sf" / "dir" / "sub" / "x") == "x");
}

static void make_tree(const fs::path& root, const fs::path& victim) {
    write_file(root / "f.txt", "file");
    write_file(root / "sub" / "g.txt", "g");
    write_file(root / p8("ünï 日本.txt"), "uni");
    write_big(root / "big.bin", 5ull << 20, 'q');
#ifdef _WIN32
    make_junction(root / "junction", victim);
    write_file(root / "ro.txt", "readonly");
    SetFileAttributesW((root / "ro.txt").c_str(), FILE_ATTRIBUTE_READONLY);
#else
    std::error_code ec;
    fs::create_symlink("f.txt", root / "rel_link", ec);
    fs::create_directory_symlink(victim, root / "dir_link", ec);
    ::mkfifo((root / "fifo").c_str(), 0600);
#endif
}

static void verify_tree(const fs::path& root, const fs::path& victim, const std::string& what) {
    CHECK_MSG(read_file(root / "f.txt") == "file" && read_file(root / "sub" / "g.txt") == "g", what);
    CHECK_MSG(read_file(root / p8("ünï 日本.txt")) == "uni", what);
    CHECK_MSG(size_of(root / "big.bin") == (5ull << 20), what);
    vfs::FileEntry e;
    std::error_code ec;
#ifdef _WIN32
    CHECK_MSG(vfs::stat_entry(root / "junction", e, ec) && e.kind == vfs::FileKind::Junction, what);
    CHECK_MSG(read_file(root / "ro.txt") == "readonly", what);
#else
    CHECK_MSG(vfs::stat_entry(root / "rel_link", e, ec) && e.kind == vfs::FileKind::Symlink && e.link_target == "f.txt", what);
    CHECK_MSG(vfs::stat_entry(root / "dir_link", e, ec) && e.kind == vfs::FileKind::Symlink, what);
    CHECK_MSG(vfs::stat_entry(root / "fifo", e, ec) && e.kind == vfs::FileKind::Fifo, what);
#endif
    CHECK_MSG(read_file(victim / "v.txt") == "victim" && count_tree(victim) == 1, what + ": link target untouched");
}

static void test_forced_cross_device(const Scratch& s) {
    section("cross-device path (forced): tree with links arrives whole, source removed");
    fs::path victim = s / "xd_victim";
    write_file(victim / "v.txt", "victim");
    make_tree(s / "xd_src", victim);
    vfs::OpResult r;
    {
        ForceCrossDevice force;
        r = vfs::move_to(s / "xd_src", s / "xd_dst");
    }
    CHECK_MSG(r.ok(), describe(r));
    verify_tree(s / "xd_dst", victim, "forced xdev");
    CHECK(!path_exists(s / "xd_src"));
    CHECK(r.bytes_done >= (5ull << 20));

    section("cross-device path (forced): a source that changes during the copy is kept");
    write_big(s / "chg" / "src" / "big.bin", 16ull << 20);
    write_file(s / "chg" / "src" / "small.txt", "small");
    bool touched = false;
    {
        ForceCrossDevice force;
        r = vfs::move_to(s / "chg" / "src", s / "chg" / "dst", vfs::FileOpOptions(), [&](const vfs::ProgressInfo& p) {
            if (!touched && p.current_path.filename() == "big.bin" && p.bytes_processed > 0) {
                touched = true;
                std::error_code ec;
                fs::last_write_time(L(s / "chg" / "src" / "big.bin"),
                                    fs::file_time_type::clock::now() + std::chrono::hours(2), ec);
            }
            return true;
        });
    }
    CHECK(touched);
    CHECK_MSG(r.outcome == vfs::Outcome::Partial && has_error(r, vfs::Errc::source_changed), describe(r));
    CHECK(size_of(s / "chg" / "src" / "big.bin") == (16ull << 20)); // source kept, intact
    CHECK(path_exists(s / "chg" / "src"));                                 // its folder too
    CHECK(read_file(s / "chg" / "dst" / "small.txt") == "small" && !path_exists(s / "chg" / "src" / "small.txt"));

#ifndef _WIN32
    section("cross-device path (forced): source truncated mid-copy -> nothing deleted");
    write_big(s / "trunc" / "big.bin", 16ull << 20);
    bool cut = false;
    {
        ForceCrossDevice force;
        vfs::FileOpOptions o;
        o.allow_kernel_copy = false; // stream in 1 MiB chunks so the truncation lands mid-copy
        o.allow_reflink = false;
        r = vfs::move_to(s / "trunc" / "big.bin", s / "trunc" / "moved.bin", o, [&](const vfs::ProgressInfo& p) {
            if (!cut && p.bytes_processed > (2u << 20)) {
                cut = true;
                ::truncate((s / "trunc" / "big.bin").c_str(), 4u << 20);
            }
            return true;
        });
    }
    CHECK(cut);
    CHECK_MSG(r.outcome == vfs::Outcome::Failed, describe(r));
    CHECK(path_exists(s / "trunc" / "big.bin") && !path_exists(s / "trunc" / "moved.bin"));
#endif

    section("a rename error that is not cross-device is reported, nothing copied or deleted");
    write_file(s / "nx" / "f.txt", "f");
    r = vfs::move_to(s / "nx" / "f.txt", s / "nx" / "missing_parent" / "f.txt");
    CHECK(r.outcome == vfs::Outcome::Failed && read_file(s / "nx" / "f.txt") == "f");
    CHECK(!path_exists(s / "nx" / "missing_parent"));
}

static void test_real_cross_device(const Scratch& s) {
    fs::path other = other_volume_base(s.root());
    section("real cross-volume move");
    if (other.empty()) {
        note("no second volume available (set BROVFS_TEST_SCRATCH2); skipped");
        return;
    }
    Scratch s2("move-xvol", other);
    note("second volume scratch: " + u8(s2.root()));
    fs::path victim = s / "rx_victim";
    write_file(victim / "v.txt", "victim");
    make_tree(s / "rx_src", victim);
    auto r = vfs::move_to(s / "rx_src", s2 / "rx_dst");
    CHECK_MSG(r.ok(), describe(r));
    verify_tree(s2 / "rx_dst", victim, "real xdev");
    CHECK(!path_exists(s / "rx_src"));
    CHECK(r.kernel_copied + r.reflinked > 0 || r.bytes_done > 0);

    // And back again, merging into an existing folder.
    write_file(s / "rx_back" / "rx_dst" / "already.txt", "here");
    r = vfs::move_into({s2 / "rx_dst"}, s / "rx_back");
    CHECK_MSG(r.ok(), describe(r));
    CHECK(read_file(s / "rx_back" / "rx_dst" / "f.txt") == "file" && read_file(s / "rx_back" / "rx_dst" / "already.txt") == "here");
    CHECK(!path_exists(s2 / "rx_dst"));

#ifdef _WIN32
    section("real cross-volume move with a read error mid-file keeps the source");
    fs::path src = s / "rx_locked" / "data.bin";
    write_big(src, 8ull << 20);
    HANDLE h = CreateFileW(src.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    OVERLAPPED ov{};
    ov.Offset = 4u << 20;
    CHECK(LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1u << 20, 0, &ov) != 0);
    r = vfs::move_to(src, s2 / "locked_moved.bin");
    UnlockFileEx(h, 0, 1u << 20, 0, &ov);
    CloseHandle(h);
    CHECK_MSG(r.outcome == vfs::Outcome::Failed, describe(r));
    CHECK(size_of(src) == (8ull << 20));
    CHECK(!path_exists(s2 / "locked_moved.bin"));
#endif
}

int main() {
    Scratch s("move");
    test_rename(s);
    test_conflicts(s);
    test_same_file(s);
    test_forced_cross_device(s);
    test_real_cross_device(s);
    return finish("test_move");
}
