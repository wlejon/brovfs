// The built-in type table: the fallback behind every platform database and, alone, the
// deterministic MimeDatabase::built_in(). Names follow shared-mime-info / IANA where they agree;
// the first extension listed for a type is its preferred one.
#include "src/mime_db.h"

namespace bro::vfs::detail {

namespace {

struct Ext {
    const char* ext;
    const char* mime;
};

constexpr Ext kExtensions[] = {
    // Images
    {"png", "image/png"},
    {"jpg", "image/jpeg"}, {"jpeg", "image/jpeg"}, {"jpe", "image/jpeg"},
    {"gif", "image/gif"},
    {"webp", "image/webp"},
    {"bmp", "image/bmp"}, {"dib", "image/bmp"},
    {"tiff", "image/tiff"}, {"tif", "image/tiff"},
    {"svg", "image/svg+xml"},
    {"ico", "image/x-icon"},
    {"avif", "image/avif"},
    {"heic", "image/heic"},
    {"heif", "image/heif"},
    {"jxl", "image/jxl"},
    {"qoi", "image/qoi"},
    {"psd", "image/vnd.adobe.photoshop"},
    {"tga", "image/x-tga"},
    {"ppm", "image/x-portable-pixmap"},
    {"pgm", "image/x-portable-graymap"},
    {"pbm", "image/x-portable-bitmap"},
    {"pnm", "image/x-portable-anymap"},
    {"hdr", "image/vnd.radiance"},
    // Audio
    {"mp3", "audio/mpeg"},
    {"wav", "audio/wav"},
    {"flac", "audio/flac"},
    {"ogg", "audio/ogg"}, {"oga", "audio/ogg"},
    {"opus", "audio/opus"},
    {"m4a", "audio/mp4"},
    {"aac", "audio/aac"},
    {"mid", "audio/midi"}, {"midi", "audio/midi"},
    // Video
    {"mp4", "video/mp4"}, {"m4v", "video/mp4"},
    {"mkv", "video/x-matroska"},
    {"webm", "video/webm"},
    {"avi", "video/x-msvideo"},
    {"mov", "video/quicktime"},
    {"wmv", "video/x-ms-wmv"},
    {"flv", "video/x-flv"},
    // Documents
    {"pdf", "application/pdf"},
    {"epub", "application/epub+zip"},
    {"rtf", "application/rtf"},
    {"ps", "application/postscript"},
    {"doc", "application/msword"},
    {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"xls", "application/vnd.ms-excel"},
    {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"ppt", "application/vnd.ms-powerpoint"},
    {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"odt", "application/vnd.oasis.opendocument.text"},
    {"ods", "application/vnd.oasis.opendocument.spreadsheet"},
    {"odp", "application/vnd.oasis.opendocument.presentation"},
    // Archives
    {"zip", "application/zip"},
    {"7z", "application/x-7z-compressed"},
    {"tar", "application/x-tar"},
    {"gz", "application/gzip"},
    {"zst", "application/zstd"},
    {"bz2", "application/x-bzip2"},
    {"xz", "application/x-xz"},
    {"rar", "application/vnd.rar"},
    {"jar", "application/java-archive"},
    // Executables
    {"exe", "application/vnd.microsoft.portable-executable"},
    {"dll", "application/vnd.microsoft.portable-executable"},
    {"elf", "application/x-elf"}, {"so", "application/x-elf"},
    {"wasm", "application/wasm"},
    // Structured text, web and code
    {"json", "application/json"},
    {"xml", "application/xml"},
    {"html", "text/html"}, {"htm", "text/html"},
    {"css", "text/css"},
    {"scss", "text/x-scss"},
    {"js", "application/javascript"}, {"mjs", "application/javascript"}, {"cjs", "application/javascript"},
    {"jsx", "application/javascript"},
    {"ts", "application/typescript"}, {"tsx", "application/typescript"},
    {"py", "text/x-python"},
    {"sh", "application/x-shellscript"}, {"bash", "application/x-shellscript"}, {"zsh", "application/x-shellscript"},
    {"bat", "application/x-bat"},
    {"ps1", "application/x-powershell"},
    {"pl", "text/x-perl"},
    {"rb", "text/x-ruby"},
    {"c", "text/x-csrc"},
    {"h", "text/x-chdr"},
    {"cpp", "text/x-c++src"}, {"cxx", "text/x-c++src"}, {"cc", "text/x-c++src"},
    {"hpp", "text/x-c++hdr"}, {"hxx", "text/x-c++hdr"},
    {"rs", "text/rust"},
    {"go", "text/x-go"},
    {"java", "text/x-java"},
    {"kt", "text/x-kotlin"},
    {"lua", "text/x-lua"},
    {"sql", "application/sql"},
    {"cmake", "text/x-cmake"},
    {"diff", "text/x-patch"}, {"patch", "text/x-patch"},
    {"yaml", "application/yaml"}, {"yml", "application/yaml"},
    {"toml", "application/toml"},
    {"csv", "text/csv"},
    {"md", "text/markdown"}, {"markdown", "text/markdown"},
    {"txt", "text/plain"}, {"text", "text/plain"}, {"log", "text/plain"}, {"ini", "text/plain"},
    {"conf", "text/plain"},
    // Fonts
    {"ttf", "font/ttf"},
    {"otf", "font/otf"},
    {"ttc", "font/collection"},
    {"woff", "font/woff"},
    {"woff2", "font/woff2"},
    {"pfb", "font/x-type1"}, {"pfa", "font/x-type1"}, {"t1", "font/x-type1"},
    // 3D models
    {"glb", "model/gltf-binary"},
    {"gltf", "model/gltf+json"},
};

struct Literal {
    const char* name;
    const char* mime;
};

constexpr Literal kLiterals[] = {
    {"makefile", "text/x-makefile"},
    {"gnumakefile", "text/x-makefile"},
    {"cmakelists.txt", "text/x-cmake"},
};

struct Pair {
    const char* from;
    const char* to;
};

// Spellings other databases and older software use -> the built-in name.
constexpr Pair kAliases[] = {
    {"image/x-png", "image/png"},
    {"image/pjpeg", "image/jpeg"},
    {"image/jpg", "image/jpeg"},
    {"image/x-ms-bmp", "image/bmp"},
    {"image/x-bmp", "image/bmp"},
    {"image/vnd.microsoft.icon", "image/x-icon"},
    {"image/x-photoshop", "image/vnd.adobe.photoshop"},
    {"image/x-targa", "image/x-tga"},
    {"audio/x-wav", "audio/wav"},
    {"audio/wave", "audio/wav"},
    {"audio/vnd.wave", "audio/wav"},
    {"audio/mp3", "audio/mpeg"},
    {"audio/x-mp3", "audio/mpeg"},
    {"audio/mid", "audio/midi"},
    {"audio/x-midi", "audio/midi"},
    {"audio/x-flac", "audio/flac"},
    {"audio/x-m4a", "audio/mp4"},
    {"audio/x-aac", "audio/aac"},
    {"video/avi", "video/x-msvideo"},
    {"video/msvideo", "video/x-msvideo"},
    {"application/x-zip-compressed", "application/zip"},
    {"application/x-zip", "application/zip"},
    {"application/x-gzip", "application/gzip"},
    {"application/x-rar-compressed", "application/vnd.rar"},
    {"application/x-rar", "application/vnd.rar"},
    {"application/x-zstd", "application/zstd"},
    {"application/x-msdownload", "application/vnd.microsoft.portable-executable"},
    {"application/x-ms-dos-executable", "application/vnd.microsoft.portable-executable"},
    {"application/x-executable", "application/x-elf"},
    {"application/x-sharedlib", "application/x-elf"},
    {"text/xml", "application/xml"},
    {"text/javascript", "application/javascript"},
    {"application/x-javascript", "application/javascript"},
    {"text/x-javascript", "application/javascript"},
    {"application/ecmascript", "application/javascript"},
    {"application/x-typescript", "application/typescript"},
    {"text/x-typescript", "application/typescript"},
    {"application/x-sh", "application/x-shellscript"},
    {"text/x-sh", "application/x-shellscript"},
    {"text/x-shellscript", "application/x-shellscript"},
    {"application/x-font-ttf", "font/ttf"},
    {"font/sfnt", "font/ttf"},
    {"application/x-font-otf", "font/otf"},
    {"application/font-woff", "font/woff"},
    {"application/x-font-woff", "font/woff"},
    {"application/x-font-type1", "font/x-type1"},
    {"text/x-c", "text/x-csrc"},
    {"text/x-c++", "text/x-c++src"},
    {"text/x-python3", "text/x-python"},
    {"application/x-yaml", "application/yaml"},
    {"text/yaml", "application/yaml"},
    {"text/x-yaml", "application/yaml"},
    {"application/x-toml", "application/toml"},
    {"text/x-markdown", "text/markdown"},
    {"application/x-pdf", "application/pdf"},
};

// child -> parent. text/* -> text/plain and the +xml / +json / +zip suffixes are implicit.
constexpr Pair kParents[] = {
    {"application/json", "application/javascript"},
    {"application/javascript", "text/plain"},
    {"application/typescript", "text/plain"},
    {"application/xml", "text/plain"},
    {"application/x-shellscript", "text/plain"},
    {"application/yaml", "text/plain"},
    {"application/toml", "text/plain"},
    {"application/sql", "text/plain"},
    {"application/x-powershell", "text/plain"},
    {"application/x-bat", "text/plain"},
    {"application/rtf", "text/plain"},
    {"application/postscript", "text/plain"},
    {"model/gltf+json", "application/json"},
    {"image/svg+xml", "application/xml"},
    {"application/epub+zip", "application/zip"},
    {"application/java-archive", "application/zip"},
    {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip"},
    {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/zip"},
    {"application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/zip"},
    {"application/vnd.oasis.opendocument.text", "application/zip"},
    {"application/vnd.oasis.opendocument.spreadsheet", "application/zip"},
    {"application/vnd.oasis.opendocument.presentation", "application/zip"},
    {"image/heic", "image/heif"},
    {"text/x-c++src", "text/x-csrc"},
    {"text/x-c++hdr", "text/x-chdr"},
    {"text/x-chdr", "text/x-csrc"},
};

} // namespace

const TypeTable& builtin_table() {
    static const TypeTable table = [] {
        TypeTable t;
        for (const auto& l : kLiterals) t.add_glob(l.name, l.mime, 50, false);
        for (const auto& e : kExtensions) t.add_glob(std::string("*.") + e.ext, e.mime, 50, false);
        for (const auto& a : kAliases) t.add_alias(a.from, a.to);
        for (const auto& p : kParents) t.add_parent(p.from, p.to);
        return t;
    }();
    return table;
}

} // namespace bro::vfs::detail
