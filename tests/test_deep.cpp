// Deep trees: every traversal (scan, copy, move, remove) keeps a bounded number of directory
// handles open however deep the tree is, and a level whose handle was dropped is reopened by
// path only if it is still the planned directory.
#include "harness.h"

#include "src/sys.h"
#include "src/walk.h"

#ifndef _WIN32
#include <sys/resource.h>
#endif

using namespace t;
namespace sys = bro::vfs::sys;
namespace detail = bro::vfs::detail;

namespace {

constexpr int kDepth = 300;

// root/d/d/.../d (kDepth levels), each level holding f.txt.
fs::path make_chain(const fs::path& root, int depth, const std::string& content) {
    fs::path p = root;
    for (int i = 0; i < depth; ++i) {
        p /= "d";
        write_file(p / "f.txt", content + std::to_string(i));
    }
    return p;
}

// Breadth first, one directory open at a time (recursive_directory_iterator keeps one open
// per level and runs out of descriptors at macOS's default limit of 256).
size_t count_tree(const fs::path& root) {
    size_t n = 0;
    std::vector<fs::path> queue{L(root)};
    while (!queue.empty()) {
        fs::path dir = std::move(queue.back());
        queue.pop_back();
        std::error_code ec;
        for (auto it = fs::directory_iterator(dir, ec); !ec && it != fs::directory_iterator(); it.increment(ec)) {
            ++n;
            if (it->is_directory(ec) && !it->is_symlink(ec)) queue.push_back(it->path());
        }
        if (ec) return 0;
    }
    return n;
}

void reset_peak() { sys::g_open_dirs_peak = sys::g_open_dirs.load(); }
int peak_above_baseline(int baseline) { return sys::g_open_dirs_peak.load() - baseline; }

void test_bounded(const Scratch& s) {
    section("scan / copy / move / remove of a 300-deep tree with a handle budget of 8");
    detail::g_dir_handle_budget = 8;
    const int base = sys::g_open_dirs.load();
    fs::path src = s / "deep";
    make_chain(src, kDepth, "x");
    const size_t expect = 2u * kDepth;

    reset_peak();
    vfs::ScanOptions so;
    so.recursive = true;
    auto sr = vfs::scan_directory(src, so);
    CHECK_MSG(sr.complete() && sr.entries.size() == expect, std::to_string(sr.entries.size()));
    // The budget, plus the child being opened before the oldest handle is dropped.
    CHECK_MSG(peak_above_baseline(base) <= 9, "scan peak " + std::to_string(peak_above_baseline(base)));

    reset_peak();
    auto r = vfs::copy_to(src, s / "copy");
    CHECK_MSG(r.ok() && r.files_done == kDepth && r.dirs_done == kDepth + 1, describe(r));
    CHECK(count_tree(s / "copy") == expect);
    CHECK_MSG(peak_above_baseline(base) <= 12, "copy peak " + std::to_string(peak_above_baseline(base)));

    // A cross-device move deletes every source item through the handle chain.
    reset_peak();
    sys::g_force_cross_device = true;
    r = vfs::move_to(s / "copy", s / "moved");
    sys::g_force_cross_device = false;
    CHECK_MSG(r.ok(), describe(r));
    CHECK(!path_exists(s / "copy") && count_tree(s / "moved") == expect);
    CHECK_MSG(peak_above_baseline(base) <= 16, "move peak " + std::to_string(peak_above_baseline(base)));

    reset_peak();
    r = vfs::remove({s / "moved", src});
    CHECK_MSG(r.ok() && r.files_done == 2u * kDepth, describe(r));
    CHECK(!path_exists(s / "moved") && !path_exists(src));
    CHECK_MSG(peak_above_baseline(base) <= 12, "remove peak " + std::to_string(peak_above_baseline(base)));
    CHECK(sys::g_open_dirs.load() == base);
    detail::g_dir_handle_budget = 32;
}

// While a remove climbs back up a deep tree, an ancestor is swapped for a look-alike tree. The
// dropped levels are reopened by path, which now reaches the look-alike: refused by identity,
// and the look-alike is untouched.
void test_swap_while_climbing(const Scratch& s) {
    section("an ancestor swapped while a deep remove climbs: reopen refuses the look-alike");
    detail::g_dir_handle_budget = 4;
    fs::path root = s / "climb";
    make_chain(root, 60, "real");
    bool swapped = false, refused = false;
    int items = 0;
    auto r = vfs::remove({root}, [&](const vfs::ProgressInfo& pi) {
        // Deletion runs deepest first: after ~20 items it is around level 50.
        if (!swapped && !refused && pi.phase == vfs::Phase::Deleting && ++items == 20) {
            std::error_code ec;
            fs::rename(L(root / "d"), L(root / "gone"), ec);
            if (ec) {
                refused = true; // Windows: a directory with open handles below it cannot be renamed
                return true;
            }
            make_chain(root, 60, "decoy");
            swapped = true;
        }
        return true;
    });
    if (refused) {
        note("the OS refused to rename an ancestor of open directory handles; nothing to swap");
        CHECK_MSG(r.ok(), describe(r));
        detail::g_dir_handle_budget = 32;
        return;
    }
    CHECK(swapped);
    CHECK_MSG(!r.ok() && !r.errors.empty(), describe(r));
    bool changed = false;
    for (auto& e : r.errors) changed |= e.code == vfs::Errc::source_changed;
    CHECK_MSG(changed, describe(r));
    // Every decoy file is intact.
    fs::path p = root;
    bool intact = true;
    for (int i = 0; i < 60; ++i) {
        p /= "d";
        intact &= read_file(p / "f.txt") == "decoy" + std::to_string(i);
    }
    CHECK(intact);
    detail::g_dir_handle_budget = 32;
    vfs::remove({root});
}

#ifndef _WIN32
// The real limit: with RLIMIT_NOFILE far below the depth, everything still works.
void test_fd_limit(const Scratch& s) {
    section("POSIX: a 300-deep tree under RLIMIT_NOFILE = 96");
    struct rlimit old {};
    ::getrlimit(RLIMIT_NOFILE, &old);
    fs::path src = s / "fdl";
    make_chain(src, kDepth, "x");
    struct rlimit low = old;
    low.rlim_cur = 96;
    if (::setrlimit(RLIMIT_NOFILE, &low) != 0) {
        note("setrlimit failed; skipped");
        return;
    }
    vfs::ScanOptions so;
    so.recursive = true;
    auto sr = vfs::scan_directory(src, so);
    CHECK_MSG(sr.complete() && sr.entries.size() == 2u * kDepth, std::to_string(sr.entries.size()));
    sys::g_force_cross_device = true;
    auto r = vfs::move_to(src, s / "fdl-moved");
    sys::g_force_cross_device = false;
    CHECK_MSG(r.ok(), describe(r));
    r = vfs::remove({s / "fdl-moved"});
    CHECK_MSG(r.ok() && r.files_done == kDepth, describe(r));
    ::setrlimit(RLIMIT_NOFILE, &old);
}
#endif

} // namespace

int main() {
    Scratch s("deep");
    test_bounded(s);
    test_swap_while_climbing(s);
#ifndef _WIN32
    test_fd_limit(s);
#endif
    return finish("test_deep");
}
