// Permanent delete: links are deleted as links, identity is re-checked against the plan,
// unicode / long / read-only paths work, partial results are reported.
#include "harness.h"

#ifndef _WIN32
#include <sys/stat.h>
#endif

using namespace t;

static bool make_dir_link(const fs::path& link, const fs::path& target) {
#ifdef _WIN32
    return make_junction(link, target);
#else
    return make_dir_symlink(link, target);
#endif
}

static void fill_victim(const fs::path& victim) {
    write_file(victim / "keep_me.txt", "victim data");
    write_file(victim / "sub" / "keep_me_too.txt", "victim data 2");
}

static bool victim_intact(const fs::path& victim) {
    return read_file(victim / "keep_me.txt") == "victim data" &&
           read_file(victim / "sub" / "keep_me_too.txt") == "victim data 2";
}

static void test_links(const Scratch& s) {
    section("removing a link never touches its target");
    fs::path victim = s / "victim";
    fill_victim(victim);

    if (make_dir_link(s / "top_link", victim)) {
        auto r = vfs::remove({s / "top_link"});
        CHECK_MSG(r.ok() && r.links_done == 1, describe(r));
        CHECK(!path_exists(s / "top_link") && victim_intact(victim));
    }
    fs::path trailing = s / "top_link2";
    if (make_dir_link(trailing, victim)) {
        fs::path with_slash = trailing;
        with_slash += fs::path::preferred_separator;
        auto r = vfs::remove({with_slash});
        CHECK_MSG(r.ok(), describe(r));
        CHECK(!path_exists(trailing) && victim_intact(victim));
    }
    write_file(s / "container" / "own.txt", "x");
    if (make_dir_link(s / "container" / "inner_link", victim)) {
        auto r = vfs::remove({s / "container"});
        CHECK_MSG(r.ok(), describe(r));
        CHECK(!path_exists(s / "container") && victim_intact(victim));
    }
#ifdef _WIN32
    if (make_dir_symlink(s / "sym_link", victim)) {
        auto r = vfs::remove({s / "sym_link"});
        CHECK(r.ok() && !path_exists(s / "sym_link") && victim_intact(victim));
    } else {
        note("directory symlinks not permitted; junctions covered");
    }
#else
    std::error_code ec;
    fs::create_symlink(victim / "keep_me.txt", s / "file_link", ec);
    auto r = vfs::remove({s / "file_link"});
    CHECK(r.ok() && !path_exists(s / "file_link") && victim_intact(victim));
#endif
}

static void test_swap_after_plan(const Scratch& s) {
    section("a directory swapped for a link after planning is not descended");
    fs::path victim = s / "swap_victim";
    fill_victim(victim);
    fs::path root = s / "swap";
    write_file(root / "b" / "keep_me.txt", "decoy");
    write_file(root / "b" / "sub" / "keep_me_too.txt", "decoy 2");
    write_file(root / "z.txt", "z");
    bool swapped = false, tried = false;
    auto r = vfs::remove({root}, [&](const vfs::ProgressInfo& p) {
        if (!tried && !p.current_path.empty()) {
            tried = true; // first deletion is about to happen: the plan is complete
            std::error_code ec;
            fs::rename(L(root / "b"), L(s / "swap_moved_b"), ec);
            swapped = !ec && make_dir_link(root / "b", victim);
        }
        return true;
    });
    CHECK(tried);
    if (swapped) {
        CHECK_MSG(victim_intact(victim), "victim intact after swap");
        CHECK_MSG(has_error(r, vfs::Errc::source_changed), describe(r));
        CHECK(r.outcome == vfs::Outcome::Partial);
        CHECK(path_exists(root / "b")); // the link is still there, untouched
    } else {
        note("could not stage the swap");
    }
}

static void test_names_and_attrs(const Scratch& s) {
    section("unicode, long paths, read-only");
    fs::path root = s / "uni";
    write_file(root / p8("日本語.txt"), "x");
    write_file(root / p8("ελληνικά") / p8("файл.txt"), "y");
    auto r = vfs::remove({root / p8("日本語.txt")});
    CHECK(r.ok() && r.files_done == 1 && !path_exists(root / p8("日本語.txt")));
    r = vfs::remove({root});
    CHECK(r.ok() && !path_exists(root));

    fs::path lroot = s / "long";
    fs::path deep = lroot;
    for (int i = 0; i < 12; ++i) deep /= "a_rather_long_directory_name_" + std::to_string(i);
    write_file(deep / "deep.txt", "deep");
    r = vfs::remove({lroot});
    CHECK_MSG(r.ok() && !path_exists(lroot), describe(r));
    CHECK(r.dirs_done == 13 && r.files_done == 1);

#ifdef _WIN32
    write_file(s / "ro" / "readonly.txt", "r");
    SetFileAttributesW((s / "ro" / "readonly.txt").c_str(), FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN);
    r = vfs::remove({s / "ro"});
    CHECK_MSG(r.ok() && !path_exists(s / "ro"), describe(r));
#endif
}

static void test_partial(const Scratch& s) {
    section("errors are per item; missing paths are errors");
    auto r = vfs::remove({s / "nope"});
    CHECK(r.outcome == vfs::Outcome::Failed && r.errors.size() == 1);
    if (is_root_user()) return;
    fs::path root = s / "perm";
    write_file(root / "a.txt", "a");
    write_file(root / "locked" / "inner.txt", "i");
#ifdef _WIN32
    // An open handle without FILE_SHARE_DELETE makes the delete fail.
    HANDLE h = CreateFileW((root / "locked" / "inner.txt").c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           0, nullptr);
    r = vfs::remove({root});
    CloseHandle(h);
#else
    ::chmod((root / "locked").c_str(), 0500); // cannot unlink entries inside
    r = vfs::remove({root});
    ::chmod((root / "locked").c_str(), 0755);
#endif
    CHECK_MSG(r.outcome == vfs::Outcome::Partial && r.errors.size() == 1, describe(r));
    CHECK(!r.errors.empty() && r.errors[0].source == root / "locked" / "inner.txt");
    CHECK(!path_exists(root / "a.txt") && path_exists(root / "locked" / "inner.txt"));
}

static void test_cancel(const Scratch& s) {
    section("cancellation stops between items");
    fs::path root = s / "many";
    for (int i = 0; i < 200; ++i) write_file(root / ("f" + std::to_string(i)), "x");
    auto token = std::make_shared<vfs::CancellationToken>();
    int n = 0;
    auto r = vfs::remove({root}, [&](const vfs::ProgressInfo&) {
        if (++n == 20) token->cancel();
        return true;
    }, token);
    CHECK(r.outcome == vfs::Outcome::Cancelled);
    CHECK(path_exists(root) && count_tree(root) > 100);
}

int main() {
    Scratch s("remove");
    test_links(s);
    test_swap_after_plan(s);
    test_names_and_attrs(s);
    test_partial(s);
    test_cancel(s);
    return finish("test_remove");
}
