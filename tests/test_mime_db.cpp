// MimeDatabase: the built-in table (deterministic oracle), shared-mime-info parsing from fixture
// directories written here, name/content reconciliation on real files, and the platform database
// this machine provides (shared-mime-info / UTType / registry).
#include "brovfs/mime.h"
#include "harness.h"

#include <algorithm>

using namespace t;

namespace {

bool contains(const std::vector<std::string>& v, std::string_view s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

std::span<const uint8_t> bytes(std::string_view s) {
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

const std::string kPng("\x89PNG\r\n\x1a\n\0\0\0\rIHDR", 16);
const std::string kZip("PK\x03\x04\x14\0\0\0", 8);

void test_builtin() {
    const auto& db = vfs::MimeDatabase::built_in();
    section("built-in: extensions");
    CHECK(db.backend() == "built-in");
    CHECK(db.type_for_extension(".txt") == "text/plain" && db.type_for_extension("txt") == "text/plain");
    CHECK(db.type_for_extension("HTML") == "text/html");
    CHECK(db.type_for_extension(".png") == "image/png" && db.type_for_extension(".jpg") == "image/jpeg");
    CHECK(db.type_for_extension(".pdf") == "application/pdf" && db.type_for_extension(".json") == "application/json");
    CHECK(db.type_for_extension(".mp3") == "audio/mpeg" && db.type_for_extension(".mp4") == "video/mp4");
    CHECK(db.type_for_extension(".zip") == "application/zip");
    CHECK(db.type_for_extension(".unknown_xyz_ext_123") == "application/octet-stream");
    CHECK(db.type_for_extension("") == "application/octet-stream");
    CHECK(db.type_for_extension(".ppm") == "image/x-portable-pixmap" && db.type_for_extension("dib") == "image/bmp");
    CHECK(db.type_for_extension("docx") == "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    CHECK(db.type_for_extension("cpp") == "text/x-c++src" && db.type_for_extension("yml") == "application/yaml");
    auto png = db.extensions_for_type("image/png");
    CHECK(!png.empty() && png.front() == "png");
    CHECK(contains(db.extensions_for_type("text/html"), "html") && contains(db.extensions_for_type("text/html"), "htm"));
    auto jpeg = db.extensions_for_type("IMAGE/JPEG");
    CHECK(jpeg.size() >= 3 && jpeg.front() == "jpg" && contains(jpeg, "jpeg"));
    CHECK(db.extensions_for_type("image/x-ms-bmp").front() == "bmp"); // through the alias
    CHECK(db.extensions_for_type("x/y").empty());
    CHECK(vfs::extension_to_mime(".GLB") == "model/gltf-binary" && vfs::mime_to_extension("font/x-type1") == "pfb");

    section("built-in: names, aliases, subclasses");
    CHECK(db.type_for_name("PHOTO.JPG") == "image/jpeg");
    CHECK(db.type_for_name("dir/sub/archive.tar.gz") == "application/gzip");
    CHECK(db.type_for_name("Makefile") == "text/x-makefile" && db.type_for_name("CMakeLists.txt") == "text/x-cmake");
    CHECK(db.type_for_name("no_extension").empty() && db.types_for_name(".hidden").empty());
    CHECK(db.canonical("image/x-ms-bmp") == "image/bmp");
    CHECK(db.canonical(" Text/XML; charset=utf-8") == "application/xml");
    CHECK(db.canonical("application/x-zip-compressed") == "application/zip");
    CHECK(db.canonical("x-unknown/thing") == "x-unknown/thing");
    CHECK(db.is_a("text/x-c++src", "text/plain") && db.is_a("text/x-c++src", "text/x-csrc"));
    CHECK(db.is_a("application/json", "text/plain") && db.is_a("application/geo+json", "application/json"));
    CHECK(db.is_a("application/vnd.oasis.opendocument.text", "application/zip"));
    CHECK(db.is_a("image/svg+xml", "application/xml") && db.is_a("image/svg+xml", "text/plain"));
    CHECK(db.is_a("image/png", "application/octet-stream") && !db.is_a("inode/directory", "application/octet-stream"));
    CHECK(!db.is_a("image/png", "text/plain") && !db.is_a("application/zip", "application/vnd.oasis.opendocument.text"));
    CHECK(db.is_a("image/x-ms-bmp", "image/bmp"));
}

void test_reconcile() {
    const auto& db = vfs::MimeDatabase::built_in();
    section("name vs content");
    auto ft = db.type_for_data("notes.txt", bytes(kPng));
    CHECK(ft.mime == "image/png" && ft.basis == vfs::TypeBasis::Content && ft.by_name == "text/plain");
    ft = db.type_for_data("report.docx", bytes(kZip));
    CHECK(ft.mime == db.type_for_extension("docx") && ft.basis == vfs::TypeBasis::Both && ft.by_content == "application/zip");
    ft = db.type_for_data("main.cpp", bytes("int main() { return 0; }\n"));
    CHECK(ft.mime == "text/x-c++src" && ft.basis == vfs::TypeBasis::Both);
    ft = db.type_for_data("movie.mp4", bytes("this is not a video\n"));
    CHECK(ft.mime == "text/plain" && ft.basis == vfs::TypeBasis::Content);
    ft = db.type_for_data("empty.txt", {});
    CHECK(ft.mime == "text/plain" && ft.basis == vfs::TypeBasis::Name && ft.by_content == "application/x-empty");
    ft = db.type_for_data("old.doc", bytes(std::string("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\0\0\0\0", 12)));
    CHECK(ft.mime == "application/msword" && ft.basis == vfs::TypeBasis::Name);
    ft = db.type_for_data("blob", bytes(kPng));
    CHECK(ft.mime == "image/png" && ft.basis == vfs::TypeBasis::Content && ft.by_name.empty());
    ft = db.type_for_data("README", bytes("plain words\n"));
    CHECK(ft.mime == "text/plain" && ft.basis == vfs::TypeBasis::Content);
    ft = db.type_for_data("", {}, false);
    CHECK(ft.mime == "application/octet-stream" && ft.basis == vfs::TypeBasis::None);
    ft = db.type_for_data("x.pdf", {}, false);
    CHECK(ft.mime == "application/pdf" && ft.basis == vfs::TypeBasis::Name && ft.by_content.empty());
}

void test_files(const Scratch& s) {
    const auto& db = vfs::MimeDatabase::built_in();
    section("files");
    CHECK(db.type_for_file(s.root()).mime == "inode/directory");
    CHECK(db.type_for_file(s / "missing.pdf").mime == "application/pdf");
    CHECK(db.type_for_file(s / "missing").basis == vfs::TypeBasis::None);
    write_file(s / p8("画像 ü.txt"), kPng + std::string(64, '\0'));
    CHECK(db.type_for_file(s / p8("画像 ü.txt")).mime == "image/png");
    write_file(s / "pic.ppm", "P6\n2 1\n255\n\xff\0\0\0\xff\0");
    CHECK(db.type_for_file(s / "pic.ppm").mime == "image/x-portable-pixmap");
    write_file(s / "frame", "P6\n# made by hand\n2 1\n255\n\xff\0\0\0\xff\0");
    CHECK(db.type_for_file(s / "frame").by_content == "image/x-portable-pixmap");
    write_file(s / "list.py", "#!/usr/bin/env python3\nprint(1)\n");
    CHECK(db.type_for_file(s / "list.py").mime == "text/x-python");
}

void write_smi(const fs::path& dir, const std::string& globs2, const std::string& aliases, const std::string& subclasses) {
    fs::create_directories(dir);
    write_file(dir / "globs2", globs2);
    if (!aliases.empty()) write_file(dir / "aliases", aliases);
    if (!subclasses.empty()) write_file(dir / "subclasses", subclasses);
}

void test_shared_mime_info(const Scratch& s) {
    section("shared-mime-info fixtures");
    fs::path hi = s / "hi" / "mime";
    fs::path lo = s / "lo" / "mime";
    write_smi(hi,
              "# high-priority dir\n"
              "50:application/x-override:*.ovr\n"
              "50:text/x-lowonly:__NOGLOBS__\n"
              "60:text/x-readme:README*\n",
              "application/x-old-override application/x-override\n", "");
    write_smi(lo,
              "50:application/x-compressed-tar:*.tar.gz\n"
              "50:application/gzip:*.gz\n"
              "50:text/x-c++src:*.C:cs\n"
              "50:text/x-csrc:*.c\n"
              "50:video/mp2t:*.ts\n"
              "50:text/vnd.trolltech.linguist:*.ts\n"
              "80:text/x-makefile:Makefile:cs\n"
              "50:text/x-makefile:*.mk\n"
              "40:text/x-lowonly:*.low\n"
              "50:application/x-override:*.ovr2\n"
              "45:application/x-override:*.ovr3\n"
              "50:image/x-weird:*.[0-9]w\n"
              "bad line without fields\n",
              "application/x-gzip application/gzip\napplication/x-old-override application/x-ignored\n",
              "application/x-compressed-tar application/gzip\ntext/vnd.trolltech.linguist application/xml\n");

    std::error_code ec;
    auto db = vfs::MimeDatabase::load_shared_mime_info({hi, lo}, ec);
    CHECK(db && !ec);
    if (!db) return;
    CHECK(db->backend() == "shared-mime-info");
    CHECK(db->type_for_name("a.tar.gz") == "application/x-compressed-tar"); // longest suffix
    CHECK(db->type_for_name("a.gz") == "application/gzip");
    CHECK(db->type_for_name("x.C") == "text/x-c++src" && db->type_for_name("x.c") == "text/x-csrc");
    CHECK(db->type_for_name("Makefile") == "text/x-makefile");
    CHECK(db->type_for_name("README.first") == "text/x-readme" && db->type_for_name("READ").empty());
    CHECK(db->type_for_name("song.7w") == "image/x-weird" && db->type_for_name("song.xw").empty());
    CHECK(db->type_for_name("f.low").empty()); // the high dir's __NOGLOBS__ hides the low dir's glob
    auto ts = db->types_for_name("app.ts");
    CHECK(ts.size() == 2 && contains(ts, "video/mp2t") && contains(ts, "text/vnd.trolltech.linguist"));
    CHECK(db->canonical("application/x-gzip") == "application/gzip");
    CHECK(db->canonical("application/x-old-override") == "application/x-override"); // high dir wins
    CHECK(db->is_a("application/x-compressed-tar", "application/gzip"));
    CHECK(db->is_a("text/vnd.trolltech.linguist", "text/plain"));
    auto ovr = db->extensions_for_type("application/x-override");
    CHECK(ovr.size() == 3 && ovr[0] == "ovr" && ovr[1] == "ovr2" && ovr[2] == "ovr3");
    CHECK(db->type_for_extension("png") == "image/png"); // not in the fixture: built-in answers
    // Ambiguous name resolved by content: Qt linguist XML vs an MPEG transport stream.
    auto ft = db->type_for_data("strings.ts", bytes("<?xml version=\"1.0\"?>\n<TS version=\"2.1\"></TS>\n"));
    CHECK(ft.mime == "text/vnd.trolltech.linguist" && ft.basis == vfs::TypeBasis::Both);
    ft = db->type_for_data("clip.ts", bytes(std::string("\x47\x40\x11\x10\0\0\xb0\x0d", 8) + std::string(200, '\xff')));
    CHECK(ft.mime == "video/mp2t" && ft.basis == vfs::TypeBasis::Name);

    std::error_code ec2;
    auto none = vfs::MimeDatabase::load_shared_mime_info({s / "nowhere"}, ec2);
    CHECK(!none && ec2);
}

void test_platform() {
    section("platform database");
    const auto& db = vfs::MimeDatabase::system();
    note(std::string("backend: ") + std::string(db.backend()));
#if defined(_WIN32)
    CHECK(db.backend() == "Windows registry");
#elif defined(__APPLE__)
    CHECK(db.backend() == "UTType");
#else
    std::error_code ec;
    bool have_smi = false;
    for (const auto& d : vfs::MimeDatabase::xdg_mime_dirs()) have_smi = have_smi || fs::exists(d / "globs2", ec);
    CHECK(db.backend() == (have_smi ? "shared-mime-info" : "built-in"));
    if (have_smi) {
        // Oracle: the globs2 line itself.
        std::string want;
        for (const auto& d : vfs::MimeDatabase::xdg_mime_dirs()) {
            std::ifstream in(d / "globs2");
            std::string line;
            while (want.empty() && std::getline(in, line)) {
                if (line.size() > 10 && line.ends_with(":*.odt")) want = line.substr(line.find(':') + 1, line.rfind(':') - line.find(':') - 1);
            }
            if (!want.empty()) break;
        }
        note("globs2 says *.odt is " + want);
        if (!want.empty()) CHECK(db.type_for_extension("odt") == db.canonical(want));
        CHECK(db.is_a(db.type_for_extension("odt"), "application/zip"));
    }
#endif
    CHECK(db.type_for_extension("txt") == "text/plain");
    CHECK(db.type_for_extension("png") == "image/png");
    CHECK(db.type_for_extension("pdf") == "application/pdf");
    CHECK(contains(db.extensions_for_type("image/png"), "png"));
    CHECK(contains(db.extensions_for_type("image/jpeg"), "jpg"));
    CHECK(db.type_for_extension(".no_such_ext_q7") == "application/octet-stream");
    // Sniffed and named answers come out in the same spelling.
    for (const char* ext : {"wav", "zip", "gz", "xml", "js", "bmp"}) {
        auto by_name = db.type_for_extension(ext);
        auto canon = db.canonical(vfs::MimeDatabase::built_in().type_for_extension(ext));
        CHECK_MSG(by_name == canon || db.is_a(by_name, canon) || db.is_a(canon, by_name),
                  std::string(ext) + ": " + by_name + " vs " + canon);
    }
    auto ft = db.type_for_data("photo.png", bytes(kPng));
    CHECK(ft.mime == "image/png" && ft.basis == vfs::TypeBasis::Both);
}

} // namespace

int main() {
    Scratch s("mime_db");
    test_builtin();
    test_reconcile();
    test_files(s);
    test_shared_mime_info(s);
    test_platform();
    return finish("test_mime_db");
}
