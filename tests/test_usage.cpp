// Usage scan: subtree totals against an oracle, biggest-first children with a limit, lookups,
// remove() taking a subtree off every ancestor, links never followed, cancel latency.
#include "harness.h"

#include "brovfs/usage.h"

using namespace t;

static void test_totals(const Scratch& s) {
    section("subtree totals, children, entry");
    fs::path root = s / "tree";
    write_file(root / "a.txt", std::string(10, 'a'));
    write_file(root / "big" / "one.bin", std::string(1000, 'b'));
    write_file(root / "big" / "inner" / "two.bin", std::string(500, 'c'));
    write_file(root / "small" / "x.txt", std::string(3, 'x'));
    fs::create_directories(root / "empty");

    auto scan = vfs::start_usage_scan(root);
    auto p = scan->wait();
    CHECK(p.finished && !p.cancelled);
    CHECK(p.files == 4);
    CHECK(p.directories == 4); // big, big/inner, small, empty
    CHECK(p.bytes == 1513);
    CHECK(p.errors == 0);

    std::vector<vfs::UsageItem> kids;
    CHECK(scan->children(root, kids));
    CHECK(kids.size() == 4);
    if (kids.size() == 4) {
        CHECK(kids[0].name == "big" && kids[0].bytes == 1500 && kids[0].files == 2 && kids[0].directories == 1);
        CHECK(kids[0].is_directory() && kids[0].complete && kids[0].children == 2);
        CHECK(kids[1].name == "a.txt" && kids[1].bytes == 10 && !kids[1].is_directory());
        CHECK(kids[2].name == "small" && kids[2].bytes == 3);
        CHECK(kids[3].name == "empty" && kids[3].bytes == 0 && kids[3].children == 0);
        CHECK(kids[0].path == root / "big");
    }
    CHECK(scan->children(root, kids, vfs::UsageSort::Bytes, 2) && kids.size() == 2 && kids[1].name == "a.txt");
    CHECK(scan->children(root, kids, vfs::UsageSort::Name) && kids.size() == 4 && kids[0].name == "a.txt");
    CHECK(scan->children(root / "big" / "inner", kids) && kids.size() == 1 && kids[0].name == "two.bin");
    CHECK(!scan->children(root / "a.txt", kids));
    CHECK(!scan->children(root / "nope", kids));
    CHECK(!scan->children(s / "elsewhere", kids));

    vfs::UsageItem it;
    CHECK(scan->entry(root, it) && it.bytes == 1513 && it.is_directory());
    CHECK(scan->entry(root / "big" / "one.bin", it) && it.bytes == 1000 && it.path == root / "big" / "one.bin");
    CHECK(scan->entry(fs::path(u8(root / "big") + "/"), it) && it.bytes == 1500);
    CHECK(!scan->entry(root / "big" / "missing", it));

    section("remove takes a subtree off every ancestor");
    CHECK(scan->remove(root / "big" / "inner"));
    CHECK(scan->entry(root / "big", it) && it.bytes == 1000 && it.files == 1 && it.directories == 0);
    p = scan->progress();
    CHECK(p.bytes == 1013 && p.files == 3 && p.directories == 3);
    CHECK(scan->remove(root / "a.txt"));
    p = scan->progress();
    CHECK(p.bytes == 1003 && p.files == 2);
    CHECK(!scan->entry(root / "a.txt", it));
    CHECK(!scan->remove(root / "a.txt"));
}

static void test_links(const Scratch& s) {
    section("links are counted, not followed");
    fs::path root = s / "links";
    write_file(root / "target" / "f.bin", std::string(100, 'f'));
    fs::create_directories(root / "holder");
#ifdef _WIN32
    bool made = make_junction(root / "holder" / "j", root / "target");
#else
    bool made = make_dir_symlink(root / "holder" / "j", root / "target");
#endif
    if (!made) {
        note("could not make a directory link; skipped");
        return;
    }
    auto scan = vfs::start_usage_scan(root);
    auto p = scan->wait();
    CHECK(p.finished);
    CHECK(p.bytes == 100);
    vfs::UsageItem it;
    CHECK(scan->entry(root / "holder", it) && it.files == 1 && it.directories == 0);
}

static void test_missing(const Scratch& s) {
    section("a missing root finishes with an error");
    auto scan = vfs::start_usage_scan(s / "does-not-exist");
    auto p = scan->wait();
    CHECK(p.finished && p.errors == 1 && p.files == 0);
}

static void test_cancel(const Scratch& s) {
    section("a big tree: partial results while running, prompt cancel");
    fs::path root = s / "wide";
    for (int d = 0; d < 40; ++d) {
        for (int e = 0; e < 40; ++e) {
            write_file(root / ("d" + std::to_string(d)) / ("s" + std::to_string(e)) / "f.txt", "12345");
        }
    }
    auto full = vfs::start_usage_scan(root);
    auto fp = full->wait();
    CHECK(fp.finished && fp.files == 1600 && fp.bytes == 8000 && fp.directories == 40 + 1600);
    note("1600 files in " + std::to_string(fp.elapsed_ms) + " ms");

    vfs::UsageOptions one;
    one.threads = 1;
    auto scan = vfs::start_usage_scan(root, one);
    double c0 = now_ms();
    scan->cancel();
    auto p = scan->wait();
    double c1 = now_ms();
    CHECK(p.cancelled && !p.finished);
    CHECK(c1 - c0 < 250);
    std::vector<vfs::UsageItem> kids;
    CHECK(scan->children(root, kids)); // what was gathered stays readable
}

int main() {
    Scratch s("usage");
    test_totals(s);
    test_links(s);
    test_missing(s);
    test_cancel(s);
    return finish("test_usage");
}
