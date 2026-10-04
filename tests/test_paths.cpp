// Path encoding, long paths and file identity.
#include "harness.h"

using namespace t;

static void test_utf8_roundtrip() {
    section("utf8 <-> native round trip");
    for (std::string s : {"plain.txt", "日本語.txt", "Ünïcödé €", "emoji 😀.txt", "ελληνικά/файл.txt"}) {
        CHECK_MSG(u8(p8(s)) == s, s);
    }
#ifdef _WIN32
    // A lone surrogate is a legal NTFS name character: WTF-8 must round-trip it.
    std::wstring lone = L"a\xD800" L"b";
    std::string enc = vfs::utf8_from_wide(lone);
    CHECK(vfs::wide_from_utf8(enc) == lone);
    CHECK(vfs::wide_from_utf8("\xF0\x9F\x98\x80") == L"\xD83D\xDE00");
    // Malformed UTF-8 becomes U+FFFD rather than being dropped or crashing.
    CHECK(vfs::wide_from_utf8("a\xFF" "b") == L"a\xFFFD" L"b");
    CHECK(vfs::wide_from_utf8("\xE6\x97") == L"\xFFFD\xFFFD");
#endif
}

static void test_path_shapes() {
    section("leaf / trailing separators / extended paths");
    CHECK(vfs::leaf_name(fs::path("a/b/")) == fs::path("b"));
    CHECK(vfs::leaf_name(fs::path("a/b")) == fs::path("b"));
    CHECK(vfs::strip_trailing_separators(fs::path("a/b//")) == fs::path("a/b"));
#ifdef _WIN32
    CHECK(vfs::leaf_name(fs::path(L"C:\\")).empty());
    CHECK(vfs::win_extended_path(fs::path(L"C:\\x\\..\\y\\")) == L"\\\\?\\C:\\y");
    CHECK(vfs::win_extended_path(fs::path(L"\\\\server\\share\\d")) == L"\\\\?\\UNC\\server\\share\\d");
    CHECK(vfs::win_extended_path(fs::path(L"C:/a/b")) == L"\\\\?\\C:\\a\\b");
    // Trailing dots / spaces are kept (Win32 normalisation would strip them).
    CHECK(vfs::win_extended_path(fs::path(L"C:\\dir\\name. ")) == L"\\\\?\\C:\\dir\\name. ");
#else
    CHECK(vfs::leaf_name(fs::path("/")).empty());
#endif
}

static void test_identity(const Scratch& s) {
    section("same_file by identity, not text");
    fs::path a = s / "id" / "file.txt";
    write_file(a, "x");
    std::error_code ec;
    CHECK(vfs::same_file(a, a, ec));
    CHECK(vfs::same_file(a, s / "id" / "." / "file.txt", ec));
    fs::create_hard_link(a, s / "id" / "hard.txt", ec);
    if (!ec) {
        CHECK(vfs::same_file(a, s / "id" / "hard.txt", ec));
    } else {
        note("hard links unsupported here: " + ec.message());
    }
#ifdef _WIN32
    CHECK(vfs::same_file(a, s / "ID" / "FILE.TXT", ec));
#endif
    write_file(s / "id" / "other.txt", "x");
    CHECK(!vfs::same_file(a, s / "id" / "other.txt", ec));
    vfs::FileEntry e;
    CHECK(vfs::stat_entry(a, e, ec) && e.kind == vfs::FileKind::Regular && e.size == 1 && e.id.valid);
    CHECK(!vfs::stat_entry(s / "id" / "missing", e, ec));
}

static void test_long_and_unicode(const Scratch& s) {
    section("long and unicode paths through stat");
    fs::path deep = s.root();
    for (int i = 0; i < 12; ++i) deep /= "a_rather_long_directory_name_" + std::to_string(i);
    write_file(deep / p8("ünïcode-深い.txt"), "deep");
    note("deep path length " + std::to_string(deep.native().size()));
    vfs::FileEntry e;
    std::error_code ec;
    CHECK_MSG(vfs::stat_entry(deep / p8("ünïcode-深い.txt"), e, ec), ec.message());
    CHECK(e.size == 4);
    CHECK(e.name == "ünïcode-深い.txt");
}

int main() {
    Scratch s("paths");
    test_utf8_roundtrip();
    test_path_shapes();
    test_identity(s);
    test_long_and_unicode(s);
    return finish("test_paths");
}
