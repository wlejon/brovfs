#include "brovfs/collate.h"

#include <cstdint>
#include <cstring>

namespace bro::vfs {

namespace {

bool is_digit(char c) { return c >= '0' && c <= '9'; }

// One code point from UTF-8; an invalid byte stands for itself (U+DC00 + byte, like PEP 383).
uint32_t decode(std::string_view s, size_t& i) {
    const auto b0 = static_cast<unsigned char>(s[i]);
    auto cont = [&](size_t k) { return i + k < s.size() && (static_cast<unsigned char>(s[i + k]) & 0xC0) == 0x80; };
    auto at = [&](size_t k) { return static_cast<uint32_t>(static_cast<unsigned char>(s[i + k]) & 0x3F); };
    uint32_t cp = 0;
    size_t n = 1;
    if (b0 < 0x80) {
        cp = b0;
    } else if ((b0 & 0xE0) == 0xC0 && b0 >= 0xC2 && cont(1)) {
        cp = ((b0 & 0x1Fu) << 6) | at(1);
        n = 2;
    } else if ((b0 & 0xF0) == 0xE0 && cont(1) && cont(2)) {
        cp = ((b0 & 0x0Fu) << 12) | (at(1) << 6) | at(2);
        n = cp >= 0x800 ? 3 : 1;
    } else if ((b0 & 0xF8) == 0xF0 && cont(1) && cont(2) && cont(3)) {
        cp = ((b0 & 0x07u) << 18) | (at(1) << 12) | (at(2) << 6) | at(3);
        n = cp >= 0x10000 && cp <= 0x10FFFF ? 4 : 1;
    }
    if (n == 1 && b0 >= 0x80) cp = 0xDC00 + b0;
    i += n;
    return cp;
}

// Simple case folding for the scripts file names most often use.
uint32_t fold(uint32_t c) {
    if (c >= 'A' && c <= 'Z') return c + 32;
    if (c < 0xC0) return c;
    if (c <= 0xDE) return c == 0xD7 ? c : c + 32;                         // Latin-1
    if (c >= 0x100 && c <= 0x17F) {                                       // Latin Extended-A
        if ((c <= 0x137 || (c >= 0x14A && c <= 0x177)) && c % 2 == 0) return c + 1;
        if (((c >= 0x139 && c <= 0x148) || (c >= 0x179 && c <= 0x17E)) && c % 2 == 1) return c + 1;
        if (c == 0x178) return 0xFF;
        return c;
    }
    if (c >= 0x391 && c <= 0x3A9 && c != 0x3A2) return c + 32;            // Greek
    if (c >= 0x410 && c <= 0x42F) return c + 32;                          // Cyrillic
    if (c >= 0x400 && c <= 0x40F) return c + 80;
    return c;
}

} // namespace

int natural_compare(std::string_view a, std::string_view b) noexcept {
    size_t i = 0, j = 0;
    int tie = 0; // first difference in leading zeros
    while (i < a.size() && j < b.size()) {
        if (is_digit(a[i]) && is_digit(b[j])) {
            size_t za = i, zb = j;
            while (za < a.size() && a[za] == '0') ++za;
            while (zb < b.size() && b[zb] == '0') ++zb;
            size_t ea = za, eb = zb;
            while (ea < a.size() && is_digit(a[ea])) ++ea;
            while (eb < b.size() && is_digit(b[eb])) ++eb;
            const size_t la = ea - za, lb = eb - zb;
            if (la != lb) return la < lb ? -1 : 1;
            if (la > 0) {
                int c = std::memcmp(a.data() + za, b.data() + zb, la);
                if (c != 0) return c < 0 ? -1 : 1;
            }
            if (tie == 0 && za - i != zb - j) tie = za - i < zb - j ? -1 : 1;
            i = ea;
            j = eb;
            continue;
        }
        const uint32_t ca = fold(decode(a, i));
        const uint32_t cb = fold(decode(b, j));
        if (ca != cb) return ca < cb ? -1 : 1;
    }
    if (i < a.size()) return 1;
    if (j < b.size()) return -1;
    if (tie != 0) return tie;
    int c = a.compare(b);
    return c < 0 ? -1 : c > 0 ? 1 : 0;
}

} // namespace bro::vfs
