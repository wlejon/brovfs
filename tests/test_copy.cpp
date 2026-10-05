// Copy: self-copy safety, overwrite atomicity, conflict decisions, links, special files,
// unicode / long paths, partial-result honesty, metadata, clone honesty.
#include "harness.h"

#ifdef _WIN32
#else
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#endif

using namespace t;

static size_t temps_left(const fs::path& root) {
    size_t n = 0;
    vfs::ScanOptions rec;
    rec.recursive = true;
    for (auto& e : vfs::scan_directory(root, rec).entries) {
        if (e.name.rfind(".brovfs-", 0) == 0) ++n;
    }
    return n;
}

static vfs::FileOpOptions policy(vfs::ConflictPolicy p) {
    vfs::FileOpOptions o;
    o.conflict = p;
    return o;
}

static void test_self_copy(const Scratch& s) {
    section("copy onto itself never truncates the source");
    fs::path a = s / "self" / "precious.txt";
    const std::string data = "precious user data";
    write_file(a, data);
    auto r = vfs::copy_to(a, a, policy(vfs::ConflictPolicy::Overwrite));
    CHECK(read_file(a) == data);
    CHECK_MSG(!r.ok() && has_error(r, vfs::Errc::same_file), describe(r));

    auto c = vfs::clone_file(a, a);
    CHECK(read_file(a) == data && c.error == vfs::Errc::same_file);

    std::error_code ec;
    fs::create_hard_link(L(a), L(s / "self" / "hard.txt"), ec);
    if (!ec) {
        r = vfs::copy_to(a, s / "self" / "hard.txt", policy(vfs::ConflictPolicy::Overwrite));
        CHECK(read_file(a) == data && has_error(r, vfs::Errc::same_file));
        c = vfs::clone_file(a, s / "self" / "hard.txt");
        CHECK(read_file(a) == data && !c.ok());
    }
#ifdef _WIN32
    r = vfs::copy_to(a, s / "SELF" / "." / "PRECIOUS.TXT", policy(vfs::ConflictPolicy::Overwrite));
    CHECK(read_file(a) == data && has_error(r, vfs::Errc::same_file));
#endif
    // Copy into its own folder: Explorer-style "keep both".
    r = vfs::copy_into({a}, s / "self", policy(vfs::ConflictPolicy::KeepBoth));
    CHECK_MSG(r.ok(), describe(r));
    CHECK(read_file(s / "self" / "precious (2).txt") == data && read_file(a) == data);
    CHECK(r.created.size() == 1 && r.created[0] == s / "self" / "precious (2).txt");
    // KeepNewer on the same file is a skip, never a write.
    r = vfs::copy_to(a, a, policy(vfs::ConflictPolicy::KeepNewer));
    CHECK(r.ok() && r.skipped == 1 && read_file(a) == data);
}

static void test_overwrite_cancel(const Scratch& s) {
    section("a cancelled or failed overwrite leaves the destination intact");
    fs::path src = s / "ow" / "src.bin";
    fs::path dst = s / "ow" / "dst.txt";
    write_big(src, 32ull << 20);
    write_file(dst, "existing destination");
    // A clone is one step with nothing to cancel part-way, so this exercises the data copy.
    vfs::FileOpOptions ow = policy(vfs::ConflictPolicy::Overwrite);
    ow.allow_reflink = false;
    int calls = 0;
    auto r = vfs::copy_to(src, dst, ow, [&](const vfs::ProgressInfo& p) {
        return p.bytes_processed == 0 || ++calls < 2;
    });
    CHECK_MSG(r.outcome == vfs::Outcome::Cancelled, describe(r));
    CHECK(read_file(dst) == "existing destination");
    CHECK(temps_left(s / "ow") == 0);

    auto token = std::make_shared<vfs::CancellationToken>();
    r = vfs::copy_to(src, dst, ow, [&](const vfs::ProgressInfo& p) {
        if (p.bytes_processed > (4u << 20)) token->cancel();
        return true;
    }, token);
    CHECK(r.outcome == vfs::Outcome::Cancelled && read_file(dst) == "existing destination");
    CHECK(temps_left(s / "ow") == 0);

    r = vfs::copy_to(src, dst, policy(vfs::ConflictPolicy::Overwrite));
    CHECK_MSG(r.ok() && same_content(src, dst), describe(r));
}

static void make_conflict_tree(const Scratch& s, const fs::path& src, const fs::path& dst) {
    write_file(src / "a.txt", "new a");
    write_file(src / "b.txt", "new b");
    write_file(src / "c.txt", "new c");
    write_file(dst / "a.txt", "old a");
    write_file(dst / "b.txt", "old b");
    (void)s;
}

static void test_conflicts(const Scratch& s) {
    section("conflict policies and the resolver");
    fs::path src = s / "cf_src" / "tree", base = s / "cf_dst";
    make_conflict_tree(s, src, base / "tree");

    auto r = vfs::copy_into({src}, base); // Ask, no resolver
    CHECK_MSG(r.outcome == vfs::Outcome::Partial, describe(r));
    CHECK(r.errors.size() == 2 && has_error(r, vfs::Errc::conflict_unresolved));
    CHECK(read_file(base / "tree" / "a.txt") == "old a" && read_file(base / "tree" / "c.txt") == "new c");

    r = vfs::copy_into({src}, base, policy(vfs::ConflictPolicy::Skip));
    CHECK(r.ok() && r.skipped == 3 && read_file(base / "tree" / "a.txt") == "old a");

    r = vfs::copy_into({src}, base, policy(vfs::ConflictPolicy::KeepBoth));
    CHECK(r.ok() && read_file(base / "tree" / "a (2).txt") == "new a" && read_file(base / "tree" / "a.txt") == "old a");

    std::vector<vfs::Conflict> seen;
    vfs::FileOpOptions ask;
    ask.on_conflict = [&](const vfs::Conflict& c) {
        seen.push_back(c);
        return c.destination.filename() == "a.txt" ? vfs::ConflictAction::Overwrite : vfs::ConflictAction::Skip;
    };
    r = vfs::copy_into({src}, base, ask);
    CHECK_MSG(r.ok(), describe(r));
    CHECK(read_file(base / "tree" / "a.txt") == "new a" && read_file(base / "tree" / "b.txt") == "old b");
    bool fields_ok = !seen.empty();
    for (auto& c : seen) {
        fields_ok &= c.kind == vfs::ConflictKind::Exists && c.source_kind == vfs::FileKind::Regular &&
                     c.destination_kind == vfs::FileKind::Regular && c.source_size == 5 && c.destination_size > 0;
    }
    CHECK(fields_ok);

    // Abort stops everything after the first conflict.
    fs::path abort_dst = s / "cf_abort";
    write_file(abort_dst / "tree" / "a.txt", "keep");
    vfs::FileOpOptions abort_opt;
    abort_opt.on_conflict = [](const vfs::Conflict&) { return vfs::ConflictAction::Abort; };
    r = vfs::copy_into({src}, abort_dst, abort_opt);
    CHECK(r.outcome == vfs::Outcome::Cancelled && read_file(abort_dst / "tree" / "a.txt") == "keep");

    // KeepNewer by mtime.
    fs::path kn = s / "cf_newer";
    write_file(kn / "src" / "f.txt", "src");
    write_file(kn / "dst" / "f.txt", "dst-newer");
    std::error_code ec;
    auto now = fs::file_time_type::clock::now();
    fs::last_write_time(L(kn / "src" / "f.txt"), now - std::chrono::hours(1), ec);
    fs::last_write_time(L(kn / "dst" / "f.txt"), now, ec);
    r = vfs::copy_into({kn / "src" / "f.txt"}, kn / "dst", policy(vfs::ConflictPolicy::KeepNewer));
    CHECK(r.ok() && r.skipped == 1 && read_file(kn / "dst" / "f.txt") == "dst-newer");
    fs::last_write_time(L(kn / "src" / "f.txt"), now + std::chrono::hours(1), ec);
    r = vfs::copy_into({kn / "src" / "f.txt"}, kn / "dst", policy(vfs::ConflictPolicy::KeepNewer));
    CHECK(r.ok() && read_file(kn / "dst" / "f.txt") == "src");

    // Type mismatch is never "overwritten".
    fs::path tm = s / "cf_type";
    write_file(tm / "src" / "x", "file");
    write_file(tm / "dst" / "x" / "inner.txt", "dir content");
    r = vfs::copy_into({tm / "src" / "x"}, tm / "dst", policy(vfs::ConflictPolicy::Overwrite));
    CHECK(has_error(r, vfs::Errc::type_mismatch) && read_file(tm / "dst" / "x" / "inner.txt") == "dir content");
}

static void test_inside_source(const Scratch& s) {
    section("a directory is never copied into itself");
    fs::path d = s / "inside" / "dir";
    write_file(d / "sub" / "f.txt", "f");
    auto r = vfs::copy_into({d}, d / "sub");
    CHECK(has_error(r, vfs::Errc::destination_inside_source) && !path_exists(d / "sub" / "dir"));
    r = vfs::copy_to(d, d);
    CHECK(!r.ok() && count_tree(d) == 2);
    bool alias = false;
#ifdef _WIN32
    alias = make_junction(s / "inside" / "alias", d / "sub");
#else
    alias = make_dir_symlink(s / "inside" / "alias", d / "sub");
#endif
    if (alias) {
        r = vfs::copy_into({d}, s / "inside" / "alias");
        CHECK(has_error(r, vfs::Errc::destination_inside_source) && !path_exists(d / "sub" / "dir"));
    }
}

#ifndef _WIN32
static void make_special_tree(const fs::path& root) {
    write_file(root / "file.txt", "file");
    write_file(root / "sub" / "g.txt", "g");
    std::error_code ec;
    fs::create_symlink("file.txt", root / "rel_link", ec);
    fs::create_directory_symlink("sub", root / "dir_link", ec);
    fs::create_symlink("does-not-exist", root / "dangling", ec);
    ::mkfifo((root / "fifo").c_str(), 0640);
    ::chmod((root / "file.txt").c_str(), 0751);
}
#endif

static void test_links_and_special(const Scratch& s) {
    section("links copied as links; special files honest");
#ifdef _WIN32
    fs::path victim = s / "lk_victim";
    write_file(victim / "v.txt", "victim");
    fs::path src = s / "lk_src";
    write_file(src / "f.txt", "f");
    bool j = make_junction(src / "junction", victim);
    bool sym = make_dir_symlink(src / "dirsym", victim);
    std::error_code ec;
    fs::create_symlink("f.txt", L(src / "filesym"), ec);
    bool fsym = !ec;
    auto r = vfs::copy_to(src, s / "lk_dst");
    CHECK_MSG(r.ok(), describe(r));
    vfs::FileEntry e;
    if (j) {
        CHECK(vfs::stat_entry(s / "lk_dst" / "junction", e, ec) && e.kind == vfs::FileKind::Junction);
        CHECK(e.link_target == u8(victim));
        CHECK(read_file(s / "lk_dst" / "junction" / "v.txt") == "victim"); // resolves like the original
    }
    if (sym) CHECK(vfs::stat_entry(s / "lk_dst" / "dirsym", e, ec) && e.kind == vfs::FileKind::Symlink);
    if (fsym) {
        CHECK(vfs::stat_entry(s / "lk_dst" / "filesym", e, ec) && e.kind == vfs::FileKind::Symlink &&
              e.link_target == "f.txt");
    }
    if (!sym || !fsym) note("symlink creation not permitted (no Developer Mode): only junctions covered");
    CHECK(read_file(victim / "v.txt") == "victim" && count_tree(victim) == 1);
#else
    fs::path src = s / "lk_src";
    make_special_tree(src);
    auto r = vfs::copy_to(src, s / "lk_dst");
    CHECK_MSG(r.ok(), describe(r));
    fs::path d = s / "lk_dst";
    std::error_code ec;
    CHECK(read_file(d / "file.txt") == "file" && read_file(d / "sub" / "g.txt") == "g");
    CHECK(fs::is_symlink(d / "rel_link", ec) && fs::read_symlink(d / "rel_link", ec) == "file.txt");
    CHECK(fs::is_symlink(d / "dir_link", ec) && fs::read_symlink(d / "dir_link", ec) == "sub");
    CHECK(fs::is_symlink(d / "dangling", ec) && fs::read_symlink(d / "dangling", ec) == "does-not-exist");
    CHECK(fs::is_fifo(fs::symlink_status(d / "fifo", ec)));
    struct stat st{};
    CHECK(::stat((d / "file.txt").c_str(), &st) == 0 && (st.st_mode & 07777) == 0751);
    CHECK(r.links_done == 4);

    // A socket cannot be copied: reported, the rest still copied.
    fs::path sockdir = s / "sock";
    fs::create_directories(sockdir);
    write_file(sockdir / "plain.txt", "p");
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::string sp = (sockdir / "s.sock").string();
    if (fd >= 0 && sp.size() < sizeof(addr.sun_path)) {
        std::memcpy(addr.sun_path, sp.c_str(), sp.size() + 1);
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            r = vfs::copy_to(sockdir, s / "sock_copy");
            CHECK_MSG(r.outcome == vfs::Outcome::Partial && has_error(r, vfs::Errc::unsupported_file_type), describe(r));
            CHECK(read_file(s / "sock_copy" / "plain.txt") == "p");
        }
        ::close(fd);
    }
#endif
}

static void test_unicode_and_long(const Scratch& s) {
    section("unicode and long-path trees");
    fs::path root = s / "uni";
    std::vector<std::string> names = {"日本語.txt", "Ünïcödé €.txt", "emoji 😀.txt"};
    for (auto& n : names) write_file(root / p8(n), n);
    write_file(root / p8("ελληνικά") / p8("файл.txt"), "cyr");
    auto r = vfs::copy_to(root, s / "uni_copy");
    CHECK_MSG(r.ok(), describe(r));
    for (auto& n : names) CHECK_MSG(read_file(s / "uni_copy" / p8(n)) == n, n);
    CHECK(read_file(s / "uni_copy" / p8("ελληνικά") / p8("файл.txt")) == "cyr");
    CHECK(count_tree(s / "uni_copy") == count_tree(root));

    fs::path lroot = s / "long";
    fs::path deep = lroot;
    for (int i = 0; i < 12; ++i) deep /= "a_rather_long_directory_name_" + std::to_string(i);
    write_file(deep / "deep_file.txt", "deep");
    write_file(lroot / "shallow.txt", "s");
    r = vfs::copy_to(lroot, s / "long_copy");
    CHECK_MSG(r.ok(), describe(r));
    CHECK(count_tree(s / "long_copy") == count_tree(lroot));
}

static void test_partial(const Scratch& s) {
    section("an unreadable subtree makes the copy Partial, with detail");
    if (is_root_user()) {
        note("running as root; skipped");
        return;
    }
    fs::path root = s / "perm";
    write_file(root / "a_ok" / "a.txt", "a");
    write_file(root / "b_denied" / "secret.txt", "s");
    write_file(root / "c_ok" / "c.txt", "c");
#ifdef _WIN32
    std::wstring user = _wgetenv(L"USERNAME");
    run_cmd(L"icacls \"" + (root / "b_denied").wstring() + L"\" /deny " + user + L":(RD)");
#else
    ::chmod((root / "b_denied").c_str(), 0);
#endif
    auto r = vfs::copy_to(root, s / "perm_copy");
    CHECK_MSG(r.outcome == vfs::Outcome::Partial, describe(r));
    CHECK(!r.errors.empty() && r.errors[0].source == root / "b_denied");
    CHECK(read_file(s / "perm_copy" / "c_ok" / "c.txt") == "c" && read_file(s / "perm_copy" / "a_ok" / "a.txt") == "a");
#ifdef _WIN32
    run_cmd(L"icacls \"" + (root / "b_denied").wstring() + L"\" /remove:d " + user);
#else
    ::chmod((root / "b_denied").c_str(), 0755);
#endif
}

static void test_metadata(const Scratch& s) {
    section("timestamps and attributes preserved");
    fs::path src = s / "meta" / "src";
    write_file(src / "f.txt", "f");
    write_file(src / "d" / "g.txt", "g");
    std::error_code ec;
    auto when = fs::file_time_type::clock::now() - std::chrono::hours(24 * 30);
    fs::last_write_time(src / "f.txt", when, ec);
#ifdef _WIN32
    SetFileAttributesW((src / "f.txt").c_str(), FILE_ATTRIBUTE_READONLY);
#endif
    fs::last_write_time(src / "d", when, ec);
    auto r = vfs::copy_to(src, s / "meta" / "dst");
    CHECK_MSG(r.ok() && r.warnings.empty(), describe(r));
    auto diff = [](fs::file_time_type a, fs::file_time_type b) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(a > b ? a - b : b - a).count();
    };
    CHECK(diff(fs::last_write_time(s / "meta" / "dst" / "f.txt", ec), when) < 2000);
    CHECK(diff(fs::last_write_time(s / "meta" / "dst" / "d", ec), when) < 2000);
#ifdef _WIN32
    DWORD a = GetFileAttributesW((s / "meta" / "dst" / "f.txt").c_str());
    CHECK(a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_READONLY));
    SetFileAttributesW((src / "f.txt").c_str(), FILE_ATTRIBUTE_NORMAL);
#endif
}

static void test_read_error(const Scratch& s) {
    section("a read error mid-file is a failure, never a short success");
#ifdef _WIN32
    fs::path src = s / "locked" / "data.bin";
    write_big(src, 8ull << 20);
    HANDLE h = CreateFileW(src.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    OVERLAPPED ov{};
    ov.Offset = 4u << 20;
    bool locked = LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1u << 20, 0, &ov) != 0;
    CHECK(locked);
    write_file(s / "locked" / "existing.bin", "keep me");
    auto r = vfs::copy_to(src, s / "locked" / "copy.bin");
    CHECK_MSG(r.outcome == vfs::Outcome::Failed, describe(r));
    CHECK(!path_exists(s / "locked" / "copy.bin"));
    r = vfs::copy_to(src, s / "locked" / "existing.bin", policy(vfs::ConflictPolicy::Overwrite));
    CHECK(!r.ok() && read_file(s / "locked" / "existing.bin") == "keep me");
    CHECK(temps_left(s / "locked") == 0);
    UnlockFileEx(h, 0, 1u << 20, 0, &ov);
    CloseHandle(h);
#else
    (void)s;
    note("no portable way to inject EIO on Linux; covered by source-changed tests in test_move");
#endif
}

static void test_clone(const Scratch& s) {
    section("clone_file reports the method honestly");
    fs::path src = s / "clone" / "src.bin";
    write_big(src, 3ull << 20);
    bool cow = vfs::reflink_supported(s / "clone");
    note(std::string("reflink_supported=") + (cow ? "true" : "false"));
    auto c = vfs::clone_file(src, s / "clone" / "dst.bin");
    CHECK_MSG(c.ok(), c.error.message());
    CHECK(same_content(src, s / "clone" / "dst.bin"));
    note(std::string("method=") + std::string(vfs::to_string(c.method)));
    CHECK(c.method != vfs::CopyMethod::Reflink || cow);
    auto strict = vfs::clone_file(src, s / "clone" / "strict.bin", false);
    if (cow) {
        CHECK(strict.ok() && strict.method == vfs::CopyMethod::Reflink);
    } else {
        CHECK(strict.error == std::errc::operation_not_supported && !path_exists(s / "clone" / "strict.bin"));
    }
#ifdef __APPLE__
    CHECK_MSG(cow, "APFS scratch expected to support clonefile");
#endif
    if (cow && strict.ok()) {
        // A clone shares blocks, not identity: writing it leaves the source untouched.
        write_file(s / "clone" / "strict.bin", "rewritten");
        CHECK(read_file(s / "clone" / "strict.bin") == "rewritten" && same_content(src, s / "clone" / "dst.bin"));
    }
    auto again = vfs::clone_file(src, s / "clone" / "dst.bin");
    CHECK(again.error == std::errc::file_exists && same_content(src, s / "clone" / "dst.bin"));
    auto r = vfs::copy_to(src, s / "clone" / "via_copy.bin");
    CHECK(r.ok() && r.reflinked == (cow ? 1u : 0u));
    CHECK(temps_left(s / "clone") == 0);
}

static void test_misc(const Scratch& s) {
    section("trailing separators, empty files, missing sources");
    write_file(s / "misc" / "dir" / "x.txt", "x");
    write_file(s / "misc" / "empty.txt", "");
    fs::path dir_slash = s / "misc" / "dir";
    dir_slash += fs::path::preferred_separator;
    auto r = vfs::copy_into({dir_slash, s / "misc" / "empty.txt"}, s / "misc_out");
    CHECK(r.outcome == vfs::Outcome::Failed && !path_exists(s / "misc_out")); // destination folder must exist
    fs::create_directories(s / "misc_out");
    r = vfs::copy_into({dir_slash, s / "misc" / "empty.txt"}, s / "misc_out");
    CHECK_MSG(r.ok(), describe(r));
    CHECK(read_file(s / "misc_out" / "dir" / "x.txt") == "x" && path_exists(s / "misc_out" / "empty.txt"));
    CHECK(size_of(s / "misc_out" / "empty.txt") == 0);
    r = vfs::copy_into({s / "misc" / "nope"}, s / "misc_out");
    CHECK(r.outcome == vfs::Outcome::Failed && r.errors.size() == 1);
    r = vfs::copy_to(s / "misc" / "empty.txt", s / "misc" / "no_such_dir" / "e.txt");
    CHECK(r.outcome == vfs::Outcome::Failed && !path_exists(s / "misc" / "no_such_dir"));
}

int main() {
    Scratch s("copy");
    test_self_copy(s);
    test_overwrite_cancel(s);
    test_conflicts(s);
    test_inside_source(s);
    test_links_and_special(s);
    test_unicode_and_long(s);
    test_partial(s);
    test_metadata(s);
    test_read_error(s);
    test_clone(s);
    test_misc(s);
    return finish("test_copy");
}
