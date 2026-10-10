// Magic-byte sniffing and type categories. Name <-> type tables live in mime_db.cpp /
// mime_builtin.cpp.
#include "brovfs/mime.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <vector>

namespace bro::vfs {

namespace {

bool starts_with(std::span<const uint8_t> data, std::span<const uint8_t> prefix) {
    if (data.size() < prefix.size()) return false;
    return std::memcmp(data.data(), prefix.data(), prefix.size()) == 0;
}

bool starts_with_str(std::span<const uint8_t> data, std::string_view prefix) {
    if (data.size() < prefix.size()) return false;
    return std::memcmp(data.data(), prefix.data(), prefix.size()) == 0;
}

bool contains_str(std::span<const uint8_t> data, std::string_view target) {
    if (data.size() < target.size()) return false;
    auto it = std::search(
        data.begin(), data.end(),
        target.begin(), target.end()
    );
    return it != data.end();
}

std::string to_lower(std::string_view s) {
    std::string result(s);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return result;
}

} // namespace

bool is_binary_buffer(std::span<const uint8_t> buffer) {
    if (buffer.empty()) return false;

    size_t printable = 0;
    size_t total = std::min<size_t>(buffer.size(), 512);

    for (size_t i = 0; i < total; ++i) {
        uint8_t c = buffer[i];
        if (c == 0x00) {
            return true; // Null byte strongly indicates binary
        }
        if ((c >= 0x20 && c <= 0x7E) || c == '\n' || c == '\r' || c == '\t' || c >= 0x80) {
            printable++;
        }
    }

    return (static_cast<double>(printable) / static_cast<double>(total)) < 0.85;
}

std::string sniff_mime_type(std::span<const uint8_t> data) {
    if (data.empty()) {
        return "application/x-empty";
    }

    // 1. Images
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    static const uint8_t PNG_MAGIC[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (starts_with(data, PNG_MAGIC)) return "image/png";

    // JPEG: FF D8 FF
    static const uint8_t JPEG_MAGIC[] = {0xFF, 0xD8, 0xFF};
    if (starts_with(data, JPEG_MAGIC)) return "image/jpeg";

    // GIF: GIF87a or GIF89a
    if (starts_with_str(data, "GIF87a") || starts_with_str(data, "GIF89a")) return "image/gif";

    // BMP: "BM", reserved words zero, DIB header size one of the known values.
    if (starts_with_str(data, "BM") && data.size() >= 18) {
        uint32_t dib = static_cast<uint32_t>(data[14]) | (static_cast<uint32_t>(data[15]) << 8) |
                       (static_cast<uint32_t>(data[16]) << 16) | (static_cast<uint32_t>(data[17]) << 24);
        bool reserved_zero = data[6] == 0 && data[7] == 0 && data[8] == 0 && data[9] == 0;
        if (reserved_zero && (dib == 12 || dib == 40 || dib == 52 || dib == 56 || dib == 64 || dib == 108 || dib == 124)) {
            return "image/bmp";
        }
    }

    // Fonts
    static const uint8_t TTF_MAGIC[] = {0x00, 0x01, 0x00, 0x00};
    if (data.size() >= 12 && (starts_with(data, TTF_MAGIC) || starts_with_str(data, "true"))) {
        // sfnt: numTables (big-endian u16 at 4) must be plausible to avoid false positives.
        uint16_t tables = static_cast<uint16_t>((data[4] << 8) | data[5]);
        if (tables > 0 && tables < 64) return "font/ttf";
    }
    if (starts_with_str(data, "OTTO")) return "font/otf";
    if (starts_with_str(data, "ttcf")) return "font/collection";
    if (starts_with_str(data, "wOFF")) return "font/woff";
    if (starts_with_str(data, "wOF2")) return "font/woff2";
    // Type 1: PFA is text "%!PS-AdobeFont" / "%!FontType1"; PFB wraps it in segments
    // (0x80 0x01, u32 length) so the text starts at offset 6.
    if (starts_with_str(data, "%!PS-AdobeFont") || starts_with_str(data, "%!FontType1")) return "font/x-type1";
    if (data.size() >= 6 + 11 && data[0] == 0x80 && data[1] == 0x01) {
        auto rest = data.subspan(6);
        if (starts_with_str(rest, "%!PS-AdobeFont") || starts_with_str(rest, "%!FontType1")) return "font/x-type1";
    }

    // 3D models: binary glTF ("glTF" + version 2 little-endian)
    if (data.size() >= 8 && starts_with_str(data, "glTF") && data[4] == 2 && data[5] == 0 && data[6] == 0 &&
        data[7] == 0) {
        return "model/gltf-binary";
    }

    // WebP: RIFF....WEBP
    if (data.size() >= 12 && starts_with_str(data, "RIFF") &&
        std::memcmp(data.data() + 8, "WEBP", 4) == 0) {
        return "image/webp";
    }

    // TIFF
    static const uint8_t TIFF_LE[] = {0x49, 0x49, 0x2A, 0x00};
    static const uint8_t TIFF_BE[] = {0x4D, 0x4D, 0x00, 0x2A};
    if (starts_with(data, TIFF_LE) || starts_with(data, TIFF_BE)) return "image/tiff";

    // ICO: 00 00 01 00
    static const uint8_t ICO_MAGIC[] = {0x00, 0x00, 0x01, 0x00};
    if (starts_with(data, ICO_MAGIC)) return "image/x-icon";

    // QOI: 71 6F 69 66 ("qoif")
    if (starts_with_str(data, "qoif")) return "image/qoi";

    // Netpbm: "P1".."P6", whitespace, then a dimension or a comment.
    if (data.size() >= 4 && data[0] == 'P' && data[1] >= '1' && data[1] <= '6' && std::isspace(data[2])) {
        size_t i = 2;
        while (i < data.size() && std::isspace(data[i])) i++;
        if (i < data.size() && (std::isdigit(data[i]) || data[i] == '#')) {
            switch (data[1]) {
                case '1': case '4': return "image/x-portable-bitmap";
                case '2': case '5': return "image/x-portable-graymap";
                default: return "image/x-portable-pixmap";
            }
        }
    }

    // 2. Audio & Video
    // WAV: RIFF....WAVE
    if (data.size() >= 12 && starts_with_str(data, "RIFF") &&
        std::memcmp(data.data() + 8, "WAVE", 4) == 0) {
        return "audio/wav";
    }

    // AVI: RIFF....AVI  or RIFF....AVIX
    if (data.size() >= 12 && starts_with_str(data, "RIFF") &&
        (std::memcmp(data.data() + 8, "AVI ", 4) == 0 || std::memcmp(data.data() + 8, "AVIX", 4) == 0)) {
        return "video/x-msvideo";
    }

    // FLAC: 66 4C 61 43 ("fLaC")
    if (starts_with_str(data, "fLaC")) return "audio/flac";

    // OGG / Opus: 4F 67 67 53 ("OggS")
    if (starts_with_str(data, "OggS")) {
        if (data.size() >= 36 && contains_str(data.subspan(0, std::min<size_t>(data.size(), 64)), "OpusHead")) {
            return "audio/opus";
        }
        return "audio/ogg";
    }

    // MP3: ID3 header or sync frame 0xFF 0xFB / 0xFF 0xF3 / 0xFF 0xF2
    if (starts_with_str(data, "ID3")) return "audio/mpeg";
    if (data.size() >= 2 && data[0] == 0xFF && (data[1] == 0xFB || data[1] == 0xF3 || data[1] == 0xF2)) {
        return "audio/mpeg";
    }

    // MIDI: MThd
    if (starts_with_str(data, "MThd")) return "audio/midi";

    // MKV / WebM: 1A 45 DF A3 (EBML)
    static const uint8_t EBML_MAGIC[] = {0x1A, 0x45, 0xDF, 0xA3};
    if (starts_with(data, EBML_MAGIC)) {
        if (contains_str(data.subspan(0, std::min<size_t>(data.size(), 64)), "webm")) {
            return "video/webm";
        }
        return "video/x-matroska";
    }

    // FLV: FLV\x01
    static const uint8_t FLV_MAGIC[] = {0x46, 0x4C, 0x56, 0x01};
    if (starts_with(data, FLV_MAGIC)) return "video/x-flv";

    // ISO Media (MP4, AVIF, HEIC, MOV, M4A): offset 4 "ftyp"
    if (data.size() >= 12 && std::memcmp(data.data() + 4, "ftyp", 4) == 0) {
        std::string_view brand(reinterpret_cast<const char*>(data.data() + 8), 4);
        if (brand == "avif" || brand == "avis") return "image/avif";
        if (brand == "heic" || brand == "heix" || brand == "heim" || brand == "heis" || brand == "hevc" ||
            brand == "hevx") {
            return "image/heic";
        }
        if (brand == "mif1" || brand == "msf1" || brand == "miaf") {
            // A structural brand: the compatible brands (after minor_version) name the codec.
            uint32_t box = (uint32_t(data[0]) << 24) | (uint32_t(data[1]) << 16) | (uint32_t(data[2]) << 8) | data[3];
            size_t end = std::min<size_t>(data.size(), box < 16 ? 16 : box);
            bool heic = false;
            for (size_t p = 16; p + 4 <= end; p += 4) {
                std::string_view c(reinterpret_cast<const char*>(data.data() + p), 4);
                if (c == "avif" || c == "avis") return "image/avif";
                if (c == "heic" || c == "heix" || c == "heim" || c == "heis" || c == "hevc" || c == "hevx") heic = true;
            }
            return heic ? "image/heic" : "image/heif";
        }
        if (brand == "M4A " || brand == "M4B ") return "audio/mp4";
        if (brand == "qt  ") return "video/quicktime";
        return "video/mp4";
    }

    // 3. Documents
    // PDF: %PDF-
    if (starts_with_str(data, "%PDF-")) return "application/pdf";

    // PostScript: %!PS
    if (starts_with_str(data, "%!PS")) return "application/postscript";

    // RTF: {\rtf1
    if (starts_with_str(data, "{\\rtf1")) return "application/rtf";

    // 4. Archives & Compressed formats
    // ZIP: PK\x03\x04
    static const uint8_t ZIP_MAGIC[] = {0x50, 0x4B, 0x03, 0x04};
    if (starts_with(data, ZIP_MAGIC)) {
        // Check for EPUB
        if (contains_str(data.subspan(0, std::min<size_t>(data.size(), 128)), "mimetypeapplication/epub+zip")) {
            return "application/epub+zip";
        }
        return "application/zip";
    }

    // 7-Zip: 37 7A BC AF 27 1C
    static const uint8_t SEVEN_ZIP_MAGIC[] = {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
    if (starts_with(data, SEVEN_ZIP_MAGIC)) return "application/x-7z-compressed";

    // GZIP: 1F 8B
    static const uint8_t GZIP_MAGIC[] = {0x1F, 0x8B};
    if (starts_with(data, GZIP_MAGIC)) return "application/gzip";

    // Zstandard: 28 B5 2F FD
    static const uint8_t ZSTD_MAGIC[] = {0x28, 0xB5, 0x2F, 0xFD};
    if (starts_with(data, ZSTD_MAGIC)) return "application/zstd";

    // BZIP2: 42 5A 68 ("BZh")
    if (starts_with_str(data, "BZh")) return "application/x-bzip2";

    // XZ: FD 37 7A 58 5A 00
    static const uint8_t XZ_MAGIC[] = {0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00};
    if (starts_with(data, XZ_MAGIC)) return "application/x-xz";

    // RAR: 52 61 72 21 1A 07
    static const uint8_t RAR_MAGIC[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07};
    if (starts_with(data, RAR_MAGIC)) return "application/vnd.rar";

    // TAR: "ustar" at offset 257
    if (data.size() >= 262 && std::memcmp(data.data() + 257, "ustar", 5) == 0) {
        return "application/x-tar";
    }

    // 5. Executables & Binaries
    // Linux ELF: 7F 45 4C 46 ("\x7FELF")
    static const uint8_t ELF_MAGIC[] = {0x7F, 0x45, 0x4C, 0x46};
    if (starts_with(data, ELF_MAGIC)) return "application/x-elf";

    // WebAssembly: 00 61 73 6D ("\x00asm")
    static const uint8_t WASM_MAGIC[] = {0x00, 0x61, 0x73, 0x6D};
    if (starts_with(data, WASM_MAGIC)) return "application/wasm";

    // Mach-O
    static const uint8_t MACHO_32[] = {0xFE, 0xED, 0xFA, 0xCE};
    static const uint8_t MACHO_64[] = {0xFE, 0xED, 0xFA, 0xCF};
    static const uint8_t MACHO_32_REV[] = {0xCE, 0xFA, 0xED, 0xFE};
    static const uint8_t MACHO_64_REV[] = {0xCF, 0xFA, 0xED, 0xFE};
    static const uint8_t MACHO_FAT[] = {0xCA, 0xFE, 0xBA, 0xBE};
    if (starts_with(data, MACHO_32) || starts_with(data, MACHO_64) ||
        starts_with(data, MACHO_32_REV) || starts_with(data, MACHO_64_REV) ||
        starts_with(data, MACHO_FAT)) {
        return "application/x-mach-binary";
    }

    // Windows PE (EXE / DLL): MZ header and check PE signature
    if (starts_with_str(data, "MZ")) {
        if (data.size() >= 0x40) {
            uint32_t pe_offset = static_cast<uint32_t>(data[0x3C]) |
                                 (static_cast<uint32_t>(data[0x3D]) << 8) |
                                 (static_cast<uint32_t>(data[0x3E]) << 16) |
                                 (static_cast<uint32_t>(data[0x3F]) << 24);
            if (pe_offset + 4 <= data.size()) {
                if (std::memcmp(data.data() + pe_offset, "PE\x00\x00", 4) == 0) {
                    return "application/vnd.microsoft.portable-executable";
                }
            }
        }
        return "application/x-dosexec";
    }

    // 6. Scripts / Text / Web
    // Shebang: #!
    if (starts_with_str(data, "#!")) {
        size_t newline = 0;
        while (newline < data.size() && data[newline] != '\n' && data[newline] != '\r') {
            newline++;
        }
        std::string_view line(reinterpret_cast<const char*>(data.data()), newline);
        if (line.find("python") != std::string_view::npos) return "text/x-python";
        if (line.find("node") != std::string_view::npos || line.find("deno") != std::string_view::npos) return "application/javascript";
        if (line.find("perl") != std::string_view::npos) return "text/x-perl";
        if (line.find("ruby") != std::string_view::npos) return "text/x-ruby";
        return "application/x-shellscript";
    }

    // XML: <?xml or <svg
    if (starts_with_str(data, "<?xml")) {
        if (contains_str(data.subspan(0, std::min<size_t>(data.size(), 256)), "<svg")) {
            return "image/svg+xml";
        }
        return "application/xml";
    }

    if (starts_with_str(data, "<svg") || contains_str(data.subspan(0, std::min<size_t>(data.size(), 256)), "<svg")) {
        return "image/svg+xml";
    }

    // HTML: <!DOCTYPE html or <html
    std::string_view sample(reinterpret_cast<const char*>(data.data()), std::min<size_t>(data.size(), 128));
    std::string sample_lower = to_lower(sample);
    if (sample_lower.find("<!doctype html") != std::string::npos || sample_lower.find("<html") != std::string::npos) {
        return "text/html";
    }

    // JSON: { or [ followed by a token that can start a member / value (so an INI
    // "[Section]" header or a "{name}" template is not JSON).
    auto skip_ws = [&](size_t i) {
        while (i < data.size() && std::isspace(data[i])) i++;
        return i;
    };
    size_t non_ws = skip_ws(0);
    if (non_ws < data.size() && (data[non_ws] == '{' || data[non_ws] == '[')) {
        size_t next = skip_ws(non_ws + 1);
        if (next >= data.size()) return "application/json";
        char c = static_cast<char>(data[next]);
        bool ok = data[non_ws] == '{' ? (c == '"' || c == '}')
                                      : (c == '"' || c == '{' || c == '[' || c == ']' || c == '-' ||
                                         (c >= '0' && c <= '9') || c == 't' || c == 'f' || c == 'n');
        if (ok) return "application/json";
    }

    // Check if plain text or binary
    if (is_binary_buffer(data)) {
        return "application/octet-stream";
    }

    return "text/plain";
}

std::string sniff_mime_type_from_file(const std::filesystem::path& path, size_t max_read_bytes) {
    // std::filesystem::path opens with the wide API on Windows: Unicode names work.
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return "application/octet-stream";
    }

    size_t to_read = (max_read_bytes > 0) ? max_read_bytes : 512;
    std::vector<uint8_t> buffer(to_read);
    file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    std::streamsize bytes_read = file.gcount();
    if (bytes_read <= 0) {
        return "application/x-empty";
    }

    return sniff_mime_type(std::span<const uint8_t>(buffer.data(), static_cast<size_t>(bytes_read)));
}

std::string get_mime_category(std::string_view mime_type) {
    if (mime_type.starts_with("image/")) return "image";
    if (mime_type.starts_with("audio/")) return "audio";
    if (mime_type.starts_with("video/")) return "video";
    if (mime_type.starts_with("font/")) return "font";
    if (mime_type.starts_with("model/")) return "model";

    if (mime_type == "application/pdf" || mime_type == "application/rtf" ||
        mime_type == "application/postscript" || mime_type == "application/epub+zip" ||
        mime_type == "application/msword" || mime_type == "application/vnd.ms-excel" ||
        mime_type == "application/vnd.ms-powerpoint" ||
        mime_type.starts_with("application/vnd.openxmlformats-officedocument.") ||
        mime_type.starts_with("application/vnd.oasis.opendocument.")) {
        return "document";
    }

    if (mime_type == "application/zip" || mime_type == "application/gzip" ||
        mime_type == "application/zstd" || mime_type == "application/x-7z-compressed" ||
        mime_type == "application/x-tar" || mime_type == "application/x-bzip2" ||
        mime_type == "application/x-xz" || mime_type == "application/vnd.rar") {
        return "archive";
    }

    if (mime_type == "application/vnd.microsoft.portable-executable" ||
        mime_type == "application/x-elf" || mime_type == "application/x-mach-binary" ||
        mime_type == "application/wasm" || mime_type == "application/x-dosexec") {
        return "executable";
    }

    if (mime_type == "application/x-shellscript" || mime_type == "text/x-python" ||
        mime_type == "application/javascript" || mime_type == "text/x-perl" ||
        mime_type == "text/x-ruby") {
        return "code";
    }

    if (mime_type.starts_with("text/") || mime_type == "application/json" || mime_type == "application/xml") {
        return "text";
    }

    return "binary";
}

} // namespace bro::vfs
