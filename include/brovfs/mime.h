#pragma once

#include <span>
#include <string>
#include <string_view>

namespace bro::vfs {

// Sniff MIME type from an in-memory buffer (inspecting magic bytes up to 512 bytes)
[[nodiscard]] std::string sniff_mime_type(std::span<const uint8_t> buffer);

// Sniff MIME type by reading magic bytes directly from a file
[[nodiscard]] std::string sniff_mime_type_from_file(const std::string& path, size_t max_read_bytes = 512);

// Return category (e.g. "image", "audio", "video", "document", "archive", "executable", "code", "text", "font")
[[nodiscard]] std::string get_mime_category(std::string_view mime_type);

// Look up MIME type based on file extension (with or without leading dot, case-insensitive)
[[nodiscard]] std::string extension_to_mime(std::string_view ext);

// Look up the canonical file extension for a MIME type (without leading dot)
[[nodiscard]] std::string mime_to_extension(std::string_view mime_type);

// Check if a buffer likely contains binary data (presence of null bytes or high non-printable byte frequency)
[[nodiscard]] bool is_binary_buffer(std::span<const uint8_t> buffer);

} // namespace bro::vfs
