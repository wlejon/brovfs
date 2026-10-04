#include "brovfs/mime.h"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#ifdef _WIN32
#include <crtdbg.h>
#include <cstdlib>
#endif

namespace fs = std::filesystem;

int main() {
#ifdef _WIN32
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif

    std::cout << "[test_mime] Testing image magic bytes..." << std::endl;
    // PNG
    const uint8_t png_data[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00};
    assert(bro::vfs::sniff_mime_type(png_data) == "image/png");
    assert(bro::vfs::get_mime_category("image/png") == "image");

    // JPEG
    const uint8_t jpeg_data[] = {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46};
    assert(bro::vfs::sniff_mime_type(jpeg_data) == "image/jpeg");

    // GIF
    const uint8_t gif_data[] = {'G', 'I', 'F', '8', '9', 'a', 0x01, 0x00, 0x01, 0x00};
    assert(bro::vfs::sniff_mime_type(gif_data) == "image/gif");

    // BMP
    const uint8_t bmp_data[] = {'B', 'M', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    assert(bro::vfs::sniff_mime_type(bmp_data) == "image/bmp");

    // WebP
    const uint8_t webp_data[] = {'R', 'I', 'F', 'F', 0x20, 0x00, 0x00, 0x00, 'W', 'E', 'B', 'P', 'V', 'P', '8', ' '};
    assert(bro::vfs::sniff_mime_type(webp_data) == "image/webp");

    // QOI
    const uint8_t qoi_data[] = {'q', 'o', 'i', 'f', 0x00, 0x00, 0x00, 0x20};
    assert(bro::vfs::sniff_mime_type(qoi_data) == "image/qoi");

    std::cout << "[test_mime] Testing audio and video magic bytes..." << std::endl;
    // WAV
    const uint8_t wav_data[] = {'R', 'I', 'F', 'F', 0x24, 0x00, 0x00, 0x00, 'W', 'A', 'V', 'E', 'f', 'm', 't', ' '};
    assert(bro::vfs::sniff_mime_type(wav_data) == "audio/wav");
    assert(bro::vfs::get_mime_category("audio/wav") == "audio");

    // FLAC
    const uint8_t flac_data[] = {'f', 'L', 'a', 'C', 0x00, 0x00, 0x00, 0x22};
    assert(bro::vfs::sniff_mime_type(flac_data) == "audio/flac");

    // MP3 (ID3)
    const uint8_t mp3_data[] = {'I', 'D', '3', 0x04, 0x00, 0x00, 0x00, 0x00};
    assert(bro::vfs::sniff_mime_type(mp3_data) == "audio/mpeg");

    // MP4
    const uint8_t mp4_data[] = {0x00, 0x00, 0x00, 0x20, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0x00, 0x00, 0x02, 0x00};
    assert(bro::vfs::sniff_mime_type(mp4_data) == "video/mp4");
    assert(bro::vfs::get_mime_category("video/mp4") == "video");

    // AVI
    const uint8_t avi_data[] = {'R', 'I', 'F', 'F', 0x40, 0x00, 0x00, 0x00, 'A', 'V', 'I', ' ', 'L', 'I', 'S', 'T'};
    assert(bro::vfs::sniff_mime_type(avi_data) == "video/x-msvideo");

    std::cout << "[test_mime] Testing documents, archives, executables..." << std::endl;
    // PDF
    const uint8_t pdf_data[] = "%PDF-1.7\n%...";
    assert(bro::vfs::sniff_mime_type(std::span<const uint8_t>(pdf_data, sizeof(pdf_data) - 1)) == "application/pdf");
    assert(bro::vfs::get_mime_category("application/pdf") == "document");

    // ZIP
    const uint8_t zip_data[] = {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00};
    assert(bro::vfs::sniff_mime_type(zip_data) == "application/zip");
    assert(bro::vfs::get_mime_category("application/zip") == "archive");

    // GZIP
    const uint8_t gz_data[] = {0x1F, 0x8B, 0x08, 0x00};
    assert(bro::vfs::sniff_mime_type(gz_data) == "application/gzip");

    // ZSTD
    const uint8_t zstd_data[] = {0x28, 0xB5, 0x2F, 0xFD, 0x00};
    assert(bro::vfs::sniff_mime_type(zstd_data) == "application/zstd");

    // 7-Zip
    const uint8_t seven_zip_data[] = {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
    assert(bro::vfs::sniff_mime_type(seven_zip_data) == "application/x-7z-compressed");

    // ELF
    const uint8_t elf_data[] = {0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00};
    assert(bro::vfs::sniff_mime_type(elf_data) == "application/x-elf");
    assert(bro::vfs::get_mime_category("application/x-elf") == "executable");

    // WASM
    const uint8_t wasm_data[] = {0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00};
    assert(bro::vfs::sniff_mime_type(wasm_data) == "application/wasm");

    // Shebang python
    const uint8_t py_script[] = "#!/usr/bin/env python3\nprint('hello')\n";
    assert(bro::vfs::sniff_mime_type(std::span<const uint8_t>(py_script, sizeof(py_script) - 1)) == "text/x-python");
    assert(bro::vfs::get_mime_category("text/x-python") == "code");

    // JSON
    const uint8_t json_data[] = "  { \"name\": \"brovfs\" }\n";
    assert(bro::vfs::sniff_mime_type(std::span<const uint8_t>(json_data, sizeof(json_data) - 1)) == "application/json");

    // HTML
    const uint8_t html_data[] = "<!DOCTYPE html><html><body></body></html>";
    assert(bro::vfs::sniff_mime_type(std::span<const uint8_t>(html_data, sizeof(html_data) - 1)) == "text/html");

    // Plain text
    const uint8_t txt_data[] = "This is a simple plain text file without any binary bytes.";
    assert(bro::vfs::sniff_mime_type(std::span<const uint8_t>(txt_data, sizeof(txt_data) - 1)) == "text/plain");

    std::cout << "[test_mime] Testing file-based sniffing..." << std::endl;
    fs::path temp_file = fs::current_path() / "test_scratch_mime.png";
    {
        std::ofstream out(temp_file, std::ios::binary);
        out.write(reinterpret_cast<const char*>(png_data), sizeof(png_data));
    }
    assert(bro::vfs::sniff_mime_type_from_file(temp_file.generic_string()) == "image/png");
    std::error_code ec;
    fs::remove(temp_file, ec);

    std::cout << "[test_mime] Testing extension lookup..." << std::endl;
    assert(bro::vfs::extension_to_mime("png") == "image/png");
    assert(bro::vfs::extension_to_mime(".jpg") == "image/jpeg");
    assert(bro::vfs::extension_to_mime("PDF") == "application/pdf");
    assert(bro::vfs::mime_to_extension("image/png") == "png");
    assert(bro::vfs::mime_to_extension("application/pdf") == "pdf");

    std::cout << "[test_mime] All MIME tests passed successfully!" << std::endl;
    return 0;
}
