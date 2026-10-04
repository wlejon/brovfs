#include "brovfs/path.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace bro::vfs {

namespace fs = std::filesystem;

#ifdef _WIN32

// WTF-8: UTF-8 that also encodes lone surrogates (as 3-byte sequences), so any NTFS name
// survives a round trip through std::string.
std::string utf8_from_wide(std::wstring_view w) {
    std::string out;
    out.reserve(w.size() * 3);
    for (size_t i = 0; i < w.size(); ++i) {
        uint32_t c = static_cast<uint16_t>(w[i]);
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < w.size()) {
            uint32_t lo = static_cast<uint16_t>(w[i + 1]);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            }
        }
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        } else if (c < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else if (c < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (c >> 12)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (c >> 18)));
            out.push_back(static_cast<char>(0x80 | ((c >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return out;
}

std::wstring wide_from_utf8(std::string_view s) {
    std::wstring out;
    out.reserve(s.size());
    size_t i = 0;
    auto bad = [&] { out.push_back(L'\xFFFD'); ++i; };
    while (i < s.size()) {
        unsigned char b0 = static_cast<unsigned char>(s[i]);
        if (b0 < 0x80) { out.push_back(static_cast<wchar_t>(b0)); ++i; continue; }
        int n = 0;
        uint32_t c = 0;
        if ((b0 & 0xE0) == 0xC0) { n = 1; c = b0 & 0x1F; }
        else if ((b0 & 0xF0) == 0xE0) { n = 2; c = b0 & 0x0F; }
        else if ((b0 & 0xF8) == 0xF0) { n = 3; c = b0 & 0x07; }
        else { bad(); continue; }
        bool ok = i + static_cast<size_t>(n) < s.size();
        for (int k = 1; ok && k <= n; ++k) {
            unsigned char b = static_cast<unsigned char>(s[i + static_cast<size_t>(k)]);
            if ((b & 0xC0) != 0x80) { ok = false; break; }
            c = (c << 6) | (b & 0x3F);
        }
        if (!ok) { bad(); continue; }
        i += static_cast<size_t>(n) + 1;
        if (c >= 0x10000) {
            c -= 0x10000;
            out.push_back(static_cast<wchar_t>(0xD800 + (c >> 10)));
            out.push_back(static_cast<wchar_t>(0xDC00 + (c & 0x3FF)));
        } else {
            out.push_back(static_cast<wchar_t>(c)); // includes WTF-8 lone surrogates
        }
    }
    return out;
}

fs::path path_from_utf8(std::string_view utf8) { return fs::path(wide_from_utf8(utf8)); }
std::string path_to_utf8(const fs::path& p) { return utf8_from_wide(p.native()); }

std::wstring win_extended_path(const fs::path& in) {
    std::wstring s = in.native();
    for (auto& ch : s) {
        if (ch == L'/') ch = L'\\';
    }
    if (s.rfind(L"\\\\?\\", 0) == 0 || s.rfind(L"\\\\.\\", 0) == 0) return s;
    fs::path p(s);
    if (!p.is_absolute()) {
        std::error_code ec;
        fs::path abs = fs::absolute(p, ec);
        if (!ec) p = abs;
    }
    // Lexical only: no Win32 stripping of trailing dots / spaces.
    std::wstring n = p.lexically_normal().native();
    for (auto& ch : n) {
        if (ch == L'/') ch = L'\\';
    }
    // Drop a trailing separator unless it is the root ("C:\").
    while (n.size() > 3 && n.back() == L'\\') n.pop_back();
    if (n.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + n.substr(2);
    return L"\\\\?\\" + n;
}

#else

fs::path path_from_utf8(std::string_view utf8) { return fs::path(std::string(utf8)); }
std::string path_to_utf8(const fs::path& p) { return p.native(); }

#endif

fs::path strip_trailing_separators(const fs::path& p) {
    fs::path r = p;
    while (!r.empty() && !r.has_filename() && r.has_relative_path()) {
        r = r.parent_path();
    }
    return r;
}

fs::path leaf_name(const fs::path& p) {
    return strip_trailing_separators(p).filename();
}

} // namespace bro::vfs
