#pragma once

#include <string>

namespace bro::vfs {

struct ReflinkResult {
    bool success = false;
    bool was_reflink = false; // true if zero-cost CoW clone succeeded, false if standard copy fallback was used
    std::string error_message;
};

// Attempt to perform a zero-cost copy-on-write clone of src to dst.
// If allow_fallback is true and CoW clone is unsupported or fails, falls back to fast stream copy.
ReflinkResult clone_file(const std::string& src, const std::string& dst, bool allow_fallback = true);

// Check if reflink CoW cloning is likely supported on the filesystem containing path
[[nodiscard]] bool is_reflink_supported(const std::string& path);

} // namespace bro::vfs
