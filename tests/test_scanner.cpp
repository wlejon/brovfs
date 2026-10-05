// Scanner: oracle counts, per-entry errors, links never followed, cancel latency, async.
#include "harness.h"

#include <atomic>
#include <set>
#include <thread>

#ifndef _WIN32
#include <sys/stat.h>
#endif

using namespace t;

static std::set<std::string> names_of(const vfs::ScanResult& r) {
    std::set<std::string> out;
    for (auto& e : r.entries) out.insert(e.name);
    return out;
}

static void test_basic(const Scratch& s) {
    section("flat and recursive listing match std::filesystem");
    fs::path root = s / "basic";
    write_file(root / "a.txt", "aa");
    write_file(root / "sub" / "b.txt", "b");
    write_file(root / "sub" / "deeper" / "c.txt", "c");
    write_file(root / ".hidden", "h");
    vfs::ScanOptions flat;
    auto r = vfs::scan_directory(root, flat);
    CHECK(r.complete());
    CHECK(r.entries.size() == 3);
    vfs::ScanOptions rec;
    rec.recursive = true;
    r = vfs::scan_directory(root, rec);
    CHECK(r.entries.size() == count_tree(root));
    for (auto& e : r.entries) {
        if (e.name == "a.txt") CHECK(e.size == 2 && e.kind == vfs::FileKind::Regular && e.depth == 0);
        if (e.name == "c.txt") CHECK(e.depth == 2);
        if (e.name == "sub") CHECK(e.kind == vfs::FileKind::Directory);
        CHECK(e.mtime_ms > 0);
    }
    vfs::ScanOptions depth1 = rec;
    depth1.max_depth = 2;
    r = vfs::scan_directory(root, depth1);
    CHECK(names_of(r).count("b.txt") == 1 && names_of(r).count("c.txt") == 0);
#ifndef _WIN32
    vfs::ScanOptions nohidden = rec;
    nohidden.include_hidden = false;
    CHECK(names_of(vfs::scan_directory(root, nohidden)).count(".hidden") == 0);
#endif
    auto missing = vfs::scan_directory(s / "does-not-exist", flat);
    CHECK(!missing.complete() && missing.errors.size() == 1);
}

static void test_unicode(const Scratch& s) {
    section("unicode names");
    fs::path root = s / "uni";
    std::vector<std::string> names = {"日本語.txt", "Ünïcödé €.txt", "emoji 😀.txt", "ελληνικά"};
    for (auto& n : names) {
        if (n == "ελληνικά") {
            write_file(root / p8(n) / p8("файл.txt"), "x");
        } else {
            write_file(root / p8(n), "x");
        }
    }
    vfs::ScanOptions rec;
    rec.recursive = true;
    auto got = names_of(vfs::scan_directory(root, rec));
    for (auto& n : names) CHECK_MSG(got.count(n) == 1, n);
    CHECK(got.count("файл.txt") == 1);
#ifndef _WIN32
    std::string bad = std::string("bad\xff\xfe") + "name.txt";
    write_file(root / bad, "raw");
    if (path_exists(root / bad)) {
        CHECK(names_of(vfs::scan_directory(root, vfs::ScanOptions())).count(bad) == 1);
    } else {
        note("file system rejects non-UTF-8 names (APFS); raw-name case skipped");
    }
#endif
}

static void test_links(const Scratch& s) {
    section("links reported, never descended");
    fs::path victim = s / "victim";
    write_file(victim / "inside.txt", "v");
    fs::path root = s / "links";
    write_file(root / "own.txt", "o");
    bool made = false;
#ifdef _WIN32
    made = make_junction(root / "junction", victim);
    if (!made) note("mklink /J failed");
#endif
    bool sym = make_dir_symlink(root / "dirlink", victim);
    if (!sym) note("directory symlinks not permitted here");
    vfs::ScanOptions rec;
    rec.recursive = true;
    auto r = vfs::scan_directory(root, rec);
    CHECK(names_of(r).count("inside.txt") == 0);
    for (auto& e : r.entries) {
        if (e.name == "junction") {
            CHECK(e.kind == vfs::FileKind::Junction && e.is_link() && e.link_is_directory);
            CHECK(!e.link_target.empty());
        }
        if (e.name == "dirlink") CHECK(e.kind == vfs::FileKind::Symlink && !e.link_target.empty());
    }
    CHECK(r.entries.size() == 1 + (made ? 1 : 0) + (sym ? 1 : 0));
    if (sym) {
        // The root itself may be a link the user navigated into: it is listed.
        auto through = vfs::scan_directory(root / "dirlink", vfs::ScanOptions());
        CHECK(names_of(through).count("inside.txt") == 1);
        CHECK(through.entries.size() == 1 && through.entries[0].path == root / "dirlink" / "inside.txt");
    }
}

static void test_unreadable(const Scratch& s) {
    section("unreadable subdirectory is a per-entry error, scan continues");
    if (is_root_user()) {
        note("running as root: permissions are not enforced; skipped");
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
    vfs::ScanOptions rec;
    rec.recursive = true;
    auto r = vfs::scan_directory(root, rec);
    auto got = names_of(r);
    CHECK(got.count("a.txt") == 1 && got.count("c.txt") == 1 && got.count("b_denied") == 1);
    CHECK(got.count("secret.txt") == 0);
    CHECK(!r.complete());
    CHECK(r.errors.size() == 1 && r.errors[0].path == root / "b_denied");
#ifdef _WIN32
    run_cmd(L"icacls \"" + (root / "b_denied").wstring() + L"\" /remove:d " + user);
#else
    ::chmod((root / "b_denied").c_str(), 0755);
#endif
}

static void test_long(const Scratch& s) {
    section("paths beyond MAX_PATH");
    fs::path root = s / "long";
    fs::path deep = root;
    for (int i = 0; i < 12; ++i) deep /= "a_rather_long_directory_name_" + std::to_string(i);
    write_file(deep / "deep_file.txt", "deep");
    write_file(root / "shallow.txt", "s");
    vfs::ScanOptions rec;
    rec.recursive = true;
    auto r = vfs::scan_directory(root, rec);
    CHECK(r.complete());
    CHECK(r.entries.size() == count_tree(root));
    CHECK(names_of(r).count("deep_file.txt") == 1);
}

static void test_cancel_and_async(const Scratch& s) {
    section("streaming, cancellation latency, async");
    fs::path root = s / "big";
    const int D = 60, F = 100;
    for (int d = 0; d < D; ++d) {
        for (int f = 0; f < F; ++f) write_file(root / ("d" + std::to_string(d)) / ("f" + std::to_string(f)), "x");
    }
    const size_t truth = count_tree(root);
    vfs::ScanOptions rec;
    rec.recursive = true;
    rec.batch_size = 64;
    size_t streamed = 0, batches = 0;
    auto summary = vfs::scan_directory_stream(root, [&](vfs::ScanBatch&& b) {
        streamed += b.entries.size();
        ++batches;
        return true;
    }, rec);
    CHECK(streamed == truth && summary.entries.empty() && summary.complete());
    CHECK(batches >= truth / 64);

    std::atomic<size_t> seen{0};
    std::atomic<int> nb{0};
    auto h = vfs::scan_directory_async(root, [&](vfs::ScanBatch&& b) {
        seen += b.entries.size();
        ++nb;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        return true;
    }, rec);
    while (nb.load() < 3 && h->is_running()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    double c0 = now_ms();
    h->cancel();
    h->wait();
    double c1 = now_ms();
    note("cancelled after " + std::to_string(seen.load()) + " entries in " + std::to_string(c1 - c0) + " ms");
    CHECK(seen.load() < truth);
    CHECK(c1 - c0 < 250);
    CHECK(h->result().cancelled);

    auto full = vfs::scan_directory_async(root, nullptr, rec);
    auto res = full->result();
    CHECK(res.entries.size() == truth && res.complete());
}

int main() {
    Scratch s("scanner");
    test_basic(s);
    test_unicode(s);
    test_links(s);
    test_unreadable(s);
    test_long(s);
    test_cancel_and_async(s);
    return finish("test_scanner");
}
