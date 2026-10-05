#pragma once
// Name ordering for file views.

#include <string_view>

namespace bro::vfs {

// "Natural" order of two file names (UTF-8 / raw bytes), as file managers sort:
//  * runs of ASCII digits compare by numeric value ("file2" < "file10"), of any length (no
//    overflow); equal values with more leading zeros sort after ("a1" < "a01");
//  * letters compare case-insensitively (ASCII and Latin-1 Supplement / Latin Extended-A /
//    Greek / Cyrillic simple case folding); other code points compare by code point;
//  * names that compare equal so far are ordered by their bytes, so the order is total and
//    deterministic ("a" vs "A" is never a tie).
// Not locale collation (no accent folding, no ICU): stable across machines.
// Returns <0, 0 or >0. Zero only for byte-identical names.
[[nodiscard]] int natural_compare(std::string_view a, std::string_view b) noexcept;

// Strict weak order for std::sort and friends.
struct NaturalLess {
    bool operator()(std::string_view a, std::string_view b) const noexcept { return natural_compare(a, b) < 0; }
};

} // namespace bro::vfs
