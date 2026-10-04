#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

namespace bro::vfs {

// Sniff a MIME type from magic bytes (the first 512 bytes are enough for every signature).
[[nodiscard]] std::string sniff_mime_type(std::span<const uint8_t> buffer);

// Read up to max_read_bytes from the file and sniff. Unreadable -> "application/octet-stream",
// empty -> "application/x-empty".
[[nodiscard]] std::string sniff_mime_type_from_file(const std::filesystem::path& path, size_t max_read_bytes = 512);

// "image", "audio", "video", "font", "model", "document", "archive", "executable", "code",
// "text" or "binary".
[[nodiscard]] std::string get_mime_category(std::string_view mime_type);

// Extension (with or without leading dot, case-insensitive) -> MIME; unknown ->
// "application/octet-stream".
[[nodiscard]] std::string extension_to_mime(std::string_view ext);

// MIME -> canonical extension without dot; unknown -> "bin".
[[nodiscard]] std::string mime_to_extension(std::string_view mime_type);

// NUL bytes or a low printable ratio in the first 512 bytes.
[[nodiscard]] bool is_binary_buffer(std::span<const uint8_t> buffer);

} // namespace bro::vfs
