#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace bro::vfs {

struct VolumeInfo {
    std::filesystem::path mount_point; // "C:\" or "/"
    std::string volume_label;          // UTF-8; Windows label, or the device on POSIX
    std::string fs_type;               // "NTFS", "ReFS", "ext4", "btrfs", ...
    uint64_t total_bytes = 0;
    uint64_t free_bytes = 0;
    uint64_t available_bytes = 0;      // available to this (unprivileged) user
    bool is_read_only = false;
    bool is_removable = false;
    bool is_network = false;

    [[nodiscard]] double used_percentage() const noexcept {
        if (total_bytes == 0) return 0.0;
        uint64_t used = total_bytes > free_bytes ? total_bytes - free_bytes : 0;
        return static_cast<double>(used) / static_cast<double>(total_bytes) * 100.0;
    }
};

[[nodiscard]] std::vector<VolumeInfo> list_volumes();

// The volume holding `path` (by device on POSIX, by volume root on Windows); a path that does
// not exist yet resolves through its nearest existing ancestor. nullopt if none.
[[nodiscard]] std::optional<VolumeInfo> get_volume_for_path(const std::filesystem::path& path);

} // namespace bro::vfs
