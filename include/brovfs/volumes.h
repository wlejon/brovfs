#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bro::vfs {

struct VolumeInfo {
    std::string mount_point;      // e.g. "C:\\" or "/"
    std::string volume_label;     // e.g. "Local Disk", "System"
    std::string fs_type;          // e.g. "NTFS", "FAT32", "ext4", "btrfs"
    uint64_t total_bytes = 0;
    uint64_t free_bytes = 0;
    uint64_t available_bytes = 0; // Available to non-privileged user
    bool is_read_only = false;
    bool is_removable = false;
    bool is_network = false;

    [[nodiscard]] double used_percentage() const noexcept {
        if (total_bytes == 0) return 0.0;
        uint64_t used = (total_bytes > free_bytes) ? (total_bytes - free_bytes) : 0;
        return (static_cast<double>(used) / static_cast<double>(total_bytes)) * 100.0;
    }
};

// Enumerate all mounted drives/volumes on the system
[[nodiscard]] std::vector<VolumeInfo> list_volumes();

// Find volume information corresponding to a given filesystem path
[[nodiscard]] std::optional<VolumeInfo> get_volume_for_path(const std::string& path);

} // namespace bro::vfs
