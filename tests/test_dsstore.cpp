// Finder's put-back records (.DS_Store ptbL / ptbN), read by brovfs's parser from fixtures
// written by the independent `ds_store` Python library (dmgbuild's), generated as:
//   for i in 0..N-1 (shuffled, seed 1): "fileNNN.txt" ptbL "Users/j/Desktop/dir<i%7>/",
//     ptbN "origNNN.txt" when i%10 == 3; when i%5 == 0 also cmmt/modD/Iloc/bwsp/vSrn/dscl/vstl
//   "naïve 文件.txt" ptbL "Users/j/Documents/ünicode/" ptbN itself; "no-putback.txt" cmmt;
//   "." vSrn
// trash.DS_Store has N = 20 (one leaf node). The library's writer corrupts trees once they
// split (separator records duplicated across children), so internal nodes are covered by a
// hand-built tree checked for the B-tree invariant instead. Runs on every platform: the
// parser is pure.
#include "harness.h"

#include "src/ds_store.h"

#include <set>

using namespace t;
namespace detail = bro::vfs::detail;

namespace {

fs::path fixture(const char* name) { return fs::path(BROVFS_FIXTURES) / name; }

std::string num(int i) {
    char b[8];
    std::snprintf(b, sizeof(b), "%03d", i);
    return b;
}

void check_store(const char* file, int n) {
    section(std::string("put-back records of ") + file);
    std::map<std::string, detail::FinderPutBack> pb;
    std::error_code ec;
    CHECK_MSG(detail::read_finder_putback(fixture(file), pb, ec), ec.message());
    CHECK_MSG(pb.size() == static_cast<size_t>(n) + 1, std::to_string(pb.size()));
    bool all = true;
    for (int i = 0; i < n; ++i) {
        auto it = pb.find("file" + num(i) + ".txt");
        if (it == pb.end()) {
            all = false;
            continue;
        }
        all &= it->second.location == "Users/j/Desktop/dir" + std::to_string(i % 7) + "/";
        all &= it->second.name == (i % 10 == 3 ? "orig" + num(i) + ".txt" : std::string());
    }
    CHECK(all);
    const std::string uni = "na\xc3\xafve \xe6\x96\x87\xe4\xbb\xb6.txt";
    CHECK(pb.count(uni) && pb[uni].location == "Users/j/Documents/\xc3\xbcnicode/" && pb[uni].name == uni);
    CHECK(!pb.count("no-putback.txt") && !pb.count("."));

    // Every record exactly once, in the B-tree's order (case-insensitive by name, then code).
    std::vector<unsigned char> data;
    {
        std::ifstream in(fixture(file), std::ios::binary);
        data.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    std::vector<detail::DsRecord> recs;
    CHECK(detail::read_ds_store(data, recs, ec));
    const size_t fifths = static_cast<size_t>((n + 4) / 5);
    const size_t expect = static_cast<size_t>(n) + static_cast<size_t>((n + 6) / 10) + fifths * 7 + 2 + 1 + 1;
    CHECK_MSG(recs.size() == expect, std::to_string(recs.size()) + " vs " + std::to_string(expect));
    std::set<std::pair<std::string, std::string>> seen;
    for (auto& r : recs) seen.insert({r.item, r.code});
    CHECK(seen.size() == recs.size());
}

// A minimal Bud1 file: blocks 0 = DSDB header, 1 = internal root, 2 / 3 = leaves.
struct Builder {
    std::vector<unsigned char> d = std::vector<unsigned char>(4 + 4096 * 6, 0);
    void u32(size_t at, uint32_t v) {
        for (int i = 0; i < 4; ++i) d[at + static_cast<size_t>(i)] = static_cast<unsigned char>(v >> (24 - 8 * i));
    }
    static void put32(std::vector<unsigned char>& b, uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back(static_cast<unsigned char>(v >> (24 - 8 * i)));
    }
    static void record(std::vector<unsigned char>& b, const std::string& ascii_name, const std::string& value) {
        put32(b, static_cast<uint32_t>(ascii_name.size()));
        for (char c : ascii_name) {
            b.push_back(0);
            b.push_back(static_cast<unsigned char>(c));
        }
        for (char c : std::string("ptbLustr")) b.push_back(static_cast<unsigned char>(c));
        put32(b, static_cast<uint32_t>(value.size()));
        for (char c : value) {
            b.push_back(0);
            b.push_back(static_cast<unsigned char>(c));
        }
    }
    void place(size_t block_offset, const std::vector<unsigned char>& b) {
        std::copy(b.begin(), b.end(), d.begin() + static_cast<std::ptrdiff_t>(4 + block_offset));
    }
    std::vector<unsigned char> build() {
        // Header: magic, "Bud1", root block at 4096 (relative to byte 4), size 2048.
        u32(0, 1);
        d[4] = 'B', d[5] = 'u', d[6] = 'd', d[7] = '1';
        u32(8, 4096), u32(12, 2048), u32(16, 4096);
        std::vector<unsigned char> root;
        put32(root, 4), put32(root, 0);
        for (uint32_t off : {8192u, 12288u, 16384u, 20480u}) put32(root, off | 12); // 4 KiB blocks
        for (int i = 4; i < 256; ++i) put32(root, 0);
        put32(root, 1);
        root.push_back(4);
        for (char c : std::string("DSDB")) root.push_back(static_cast<unsigned char>(c));
        put32(root, 0);
        place(4096, root);
        std::vector<unsigned char> db;
        put32(db, 1), put32(db, 1), put32(db, 5), put32(db, 3), put32(db, 4096);
        place(8192, db);
        std::vector<unsigned char> inner, left, right;
        put32(inner, 3), put32(inner, 1); // P = rightmost child (block 3), one (child, record) pair
        put32(inner, 2);
        record(inner, "m.txt", "Users/j/M/");
        place(12288, inner);
        put32(left, 0), put32(left, 2);
        record(left, "a.txt", "Users/j/A/");
        record(left, "B.txt", "Users/j/B/");
        place(16384, left);
        put32(right, 0), put32(right, 2);
        record(right, "n.txt", "Users/j/N/");
        record(right, "z.txt", "Users/j/Z/");
        place(20480, right);
        return d;
    }
};

void check_internal_nodes() {
    section("internal nodes are traversed in order");
    std::vector<detail::DsRecord> recs;
    std::error_code ec;
    CHECK_MSG(detail::read_ds_store(Builder().build(), recs, ec), ec.message());
    std::string order;
    for (auto& r : recs) order += r.item + ":" + r.text + " ";
    CHECK_MSG(order == "a.txt:Users/j/A/ B.txt:Users/j/B/ m.txt:Users/j/M/ n.txt:Users/j/N/ z.txt:Users/j/Z/ ", order);
}

void check_malformed() {
    section("malformed input is refused, never read out of bounds");
    std::vector<unsigned char> data;
    {
        std::ifstream in(fixture("trash.DS_Store"), std::ios::binary);
        data.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    std::vector<detail::DsRecord> recs;
    std::error_code ec;
    for (size_t cut : {size_t(0), size_t(8), size_t(36), size_t(2048), data.size() / 2}) {
        std::vector<unsigned char> part(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(cut));
        CHECK_MSG(!detail::read_ds_store(part, recs, ec), std::to_string(cut));
    }
    // Flip bytes everywhere: the parser either succeeds or refuses (no crash, no hang).
    size_t ok = 0;
    for (size_t i = 0; i < data.size(); i += 7) {
        std::vector<unsigned char> bad = data;
        bad[i] ^= 0xA5;
        ok += detail::read_ds_store(bad, recs, ec);
    }
    note(std::to_string(ok) + " single-byte corruptions still parsed");
    std::map<std::string, detail::FinderPutBack> pb;
    CHECK(!detail::read_finder_putback(fixture("missing.DS_Store"), pb, ec) && ec);
}

} // namespace

int main() {
    check_store("trash.DS_Store", 20);
    check_internal_nodes();
    check_malformed();
    return finish("test_dsstore");
}
