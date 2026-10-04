#pragma once

#include <filesystem>
#include <string>
#include <string_view>

// Path encoding. Every brovfs API takes std::filesystem::path, which is wide on Windows and
// raw bytes on POSIX. Build paths from UTF-8 with path_from_utf8 (never fs::path(std::string)
// on Windows: that uses the ANSI code page). On Windows the conversion is WTF-8, so a name
// with an unpaired surrogate round-trips losslessly.
namespace bro::vfs {

[[nodiscard]] std::filesystem::path path_from_utf8(std::string_view utf8);
[[nodiscard]] std::string path_to_utf8(const std::filesystem::path& p);

#ifdef _WIN32
[[nodiscard]] std::wstring wide_from_utf8(std::string_view utf8);
[[nodiscard]] std::string utf8_from_wide(std::wstring_view wide);
// Absolute, lexically normalised, `\\?\` (or `\\?\UNC\`) prefixed: immune to MAX_PATH and to
// Win32 trailing-dot/space stripping. Used at every syscall boundary.
[[nodiscard]] std::wstring win_extended_path(const std::filesystem::path& p);
#endif

// "a/b/" -> "a/b"; leaves roots ("/", "C:\") alone.
[[nodiscard]] std::filesystem::path strip_trailing_separators(const std::filesystem::path& p);
// The last component, ignoring trailing separators. Empty for roots.
[[nodiscard]] std::filesystem::path leaf_name(const std::filesystem::path& p);

} // namespace bro::vfs
