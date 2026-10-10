// MIME sniffing by magic bytes, extension tables, and file-based sniffing on unicode paths.
#include "brovfs/mime.h"
#include "harness.h"

#include <initializer_list>

using namespace t;

static std::string sniff(std::initializer_list<int> bytes) {
    std::vector<uint8_t> v;
    for (int b : bytes) v.push_back(static_cast<uint8_t>(b));
    return vfs::sniff_mime_type(v);
}

static std::string sniff_text(std::string_view s) {
    return vfs::sniff_mime_type(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}

static std::vector<uint8_t> padded(std::initializer_list<int> head, size_t total = 64) {
    std::vector<uint8_t> v;
    for (int b : head) v.push_back(static_cast<uint8_t>(b));
    v.resize(std::max(total, v.size()), 0);
    return v;
}

static void test_signatures() {
    section("images, audio, video");
    CHECK(sniff({0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0}) == "image/png");
    CHECK(sniff({0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10, 'J', 'F', 'I', 'F'}) == "image/jpeg");
    CHECK(sniff({'G', 'I', 'F', '8', '9', 'a', 1, 0, 1, 0}) == "image/gif");
    CHECK(vfs::sniff_mime_type(padded({'B', 'M', 0x36, 0, 0, 0, 0, 0, 0, 0, 0x36, 0, 0, 0, 40, 0, 0, 0})) == "image/bmp");
    CHECK(sniff({'R', 'I', 'F', 'F', 0x20, 0, 0, 0, 'W', 'E', 'B', 'P', 'V', 'P', '8', ' '}) == "image/webp");
    CHECK(sniff({'q', 'o', 'i', 'f', 0, 0, 0, 0x20}) == "image/qoi");
    CHECK(sniff({0, 0, 1, 0, 1, 0, 16, 16}) == "image/x-icon");
    CHECK(sniff({'R', 'I', 'F', 'F', 0x24, 0, 0, 0, 'W', 'A', 'V', 'E', 'f', 'm', 't', ' '}) == "audio/wav");
    CHECK(sniff({'f', 'L', 'a', 'C', 0, 0, 0, 0x22}) == "audio/flac");
    CHECK(sniff({'I', 'D', '3', 4, 0, 0, 0, 0}) == "audio/mpeg");
    CHECK(sniff({0, 0, 0, 0x20, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0, 2, 0}) == "video/mp4");
    // HEIF: the major brand, else the compatible brands of a structural mif1 file.
    CHECK(sniff({0, 0, 0, 0x14, 'f', 't', 'y', 'p', 'a', 'v', 'i', 'f', 0, 0, 0, 0, 'm', 'i', 'f', '1'}) == "image/avif");
    CHECK(sniff({0, 0, 0, 0x14, 'f', 't', 'y', 'p', 'h', 'e', 'i', 'c', 0, 0, 0, 0, 'm', 'i', 'f', '1'}) == "image/heic");
    CHECK(sniff({0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'm', 'i', 'f', '1', 0, 0, 0, 0, 'm', 'i', 'f', '1', 'a', 'v', 'i',
                 'f'}) == "image/avif");
    CHECK(sniff({0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'm', 'i', 'f', '1', 0, 0, 0, 0, 'm', 'i', 'f', '1', 'h', 'e', 'i',
                 'c'}) == "image/heic");
    CHECK(sniff({0, 0, 0, 0x14, 'f', 't', 'y', 'p', 'm', 'i', 'f', '1', 0, 0, 0, 0, 'm', 'i', 'f', '1'}) == "image/heif");
    // Brands past the box are not read.
    CHECK(sniff({0, 0, 0, 0x14, 'f', 't', 'y', 'p', 'm', 'i', 'f', '1', 0, 0, 0, 0, 'm', 'i', 'f', '1', 'a', 'v', 'i',
                 'f'}) == "image/heif");
    CHECK(sniff({'R', 'I', 'F', 'F', 0x40, 0, 0, 0, 'A', 'V', 'I', ' ', 'L', 'I', 'S', 'T'}) == "video/x-msvideo");
    CHECK(vfs::get_mime_category("image/png") == "image" && vfs::get_mime_category("audio/wav") == "audio");

    section("fonts and 3D models");
    CHECK(vfs::sniff_mime_type(padded({0x00, 0x01, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x80})) == "font/ttf");
    CHECK(vfs::sniff_mime_type(padded({'t', 'r', 'u', 'e', 0x00, 0x0B})) == "font/ttf");
    CHECK(vfs::sniff_mime_type(padded({'O', 'T', 'T', 'O', 0x00, 0x0C})) == "font/otf");
    CHECK(vfs::sniff_mime_type(padded({'t', 't', 'c', 'f', 0x00, 0x01})) == "font/collection");
    CHECK(vfs::sniff_mime_type(padded({'w', 'O', 'F', 'F', 0x00, 0x01, 0x00, 0x00})) == "font/woff");
    CHECK(vfs::sniff_mime_type(padded({'w', 'O', 'F', '2', 0x00, 0x01, 0x00, 0x00})) == "font/woff2");
    CHECK(vfs::sniff_mime_type(padded({'g', 'l', 'T', 'F', 2, 0, 0, 0, 0x40, 0, 0, 0})) == "model/gltf-binary");
    CHECK(vfs::get_mime_category("font/woff2") == "font" && vfs::get_mime_category("model/gltf-binary") == "model");
    CHECK(vfs::extension_to_mime(".GLB") == "model/gltf-binary" && vfs::extension_to_mime("woff2") == "font/woff2");
    CHECK(vfs::mime_to_extension("font/otf") == "otf");
    CHECK(sniff_text("%!PS-AdobeFont-1.0: C059-Bold 1.0\n") == "font/x-type1"); // PFA
    CHECK(sniff({0x80, 0x01, 0x10, 0x00, 0x00, 0x00, '%', '!', 'P', 'S', '-', 'A', 'd', 'o', 'b', 'e', 'F', 'o', 'n',
                 't', '-', '1', '.', '0'}) == "font/x-type1"); // PFB segment header
    CHECK(vfs::extension_to_mime("pfb") == "font/x-type1");

    section("false positives avoided");
    CHECK(sniff_text("BMW parts list\nwheels: 4\n") == "text/plain"); // starts with "BM", not a bitmap
    CHECK(vfs::sniff_mime_type(padded({0x00, 0x01, 0x00, 0x00, 0x00, 0x00})) != "font/ttf"); // zero tables
    CHECK(vfs::sniff_mime_type(padded({'g', 'l', 'T', 'F', 1, 0, 0, 0})) != "model/gltf-binary");
    CHECK(sniff_text("[Icon Theme]\nInherits=Adwaita\n") == "text/plain"); // INI, not JSON
    CHECK(sniff_text("{name} says hi\n") == "text/plain");
    CHECK(sniff_text("[1, 2, 3]") == "application/json" && sniff_text("[\n  {\"a\": true}\n]") == "application/json");
    CHECK(sniff_text("%!PS-Adobe-3.0\n") == "application/postscript");

    section("documents, archives, executables, text");
    CHECK(sniff_text("%PDF-1.7\n%...") == "application/pdf");
    CHECK(sniff({0x50, 0x4B, 0x03, 0x04, 0x14, 0x00}) == "application/zip");
    CHECK(sniff({0x1F, 0x8B, 0x08, 0x00}) == "application/gzip");
    CHECK(sniff({0x28, 0xB5, 0x2F, 0xFD, 0x00}) == "application/zstd");
    CHECK(sniff({0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}) == "application/x-7z-compressed");
    CHECK(sniff({0x7F, 'E', 'L', 'F', 2, 1, 1, 0}) == "application/x-elf");
    CHECK(sniff({0x00, 'a', 's', 'm', 1, 0, 0, 0}) == "application/wasm");
    CHECK(sniff_text("#!/usr/bin/env python3\nprint('hello')\n") == "text/x-python");
    CHECK(sniff_text("  { \"name\": \"brovfs\" }\n") == "application/json");
    CHECK(sniff_text("<!DOCTYPE html><html><body></body></html>") == "text/html");
    CHECK(sniff_text("This is a simple plain text file.") == "text/plain");
    CHECK(vfs::sniff_mime_type(std::span<const uint8_t>()) == "application/x-empty");
    CHECK(vfs::get_mime_category("application/pdf") == "document" && vfs::get_mime_category("application/zip") == "archive");
    CHECK(vfs::extension_to_mime("PDF") == "application/pdf" && vfs::extension_to_mime(".jpg") == "image/jpeg");
    CHECK(vfs::extension_to_mime("nope") == "application/octet-stream" && vfs::mime_to_extension("x/y") == "bin");
}

static void test_files(const Scratch& s) {
    section("file sniffing through unicode paths");
    fs::path f = s / p8("画像 ü.png");
    const char png[] = {'\x89', 'P', 'N', 'G', '\r', '\n', '\x1a', '\n', 0, 0, 0, 0};
    write_file(f, std::string(png, sizeof(png)));
    CHECK(vfs::sniff_mime_type_from_file(f) == "image/png");
    write_file(s / "empty.bin", "");
    CHECK(vfs::sniff_mime_type_from_file(s / "empty.bin") == "application/x-empty");
    CHECK(vfs::sniff_mime_type_from_file(s / "missing.bin") == "application/octet-stream");
}

int main() {
    Scratch s("mime");
    test_signatures();
    test_files(s);
    return finish("test_mime");
}
