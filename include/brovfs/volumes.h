#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
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

// ---------------------------------------------------------------- volume add / remove events

enum class VolumeEventKind : uint8_t { Added = 0, Removed, Changed };

struct VolumeEvent {
    VolumeEventKind kind = VolumeEventKind::Added;
    VolumeInfo volume;   // Removed: the volume as last seen
};

struct VolumeMonitorOptions {
    // Backstop re-enumeration period. The platform notification makes events prompt; the
    // poll catches what it does not report (and is all there is when it failed to start).
    std::chrono::milliseconds poll_interval{3000};
};

// Watches the set list_volumes() returns and reports changes to it: a volume added or removed
// (keyed by mount point), or Changed when its label, file system, size, read-only, removable
// or network flag changes (free space does not count). Each notification re-enumerates at once
// and again shortly after, since the OS may notify before a mount is complete.
//   Windows  WM_DEVICECHANGE on a hidden top-level window (drive letters: media arrival and
//            removal, and DefineDosDevice / subst when the definer broadcasts it, as the API
//            asks; otherwise the poll).
//   Linux    poll() on /proc/self/mountinfo (POLLPRI on any mount-table change in this mount
//            namespace). udisks2 is not used: it only knows the drives it manages, and every
//            mount it makes appears in mountinfo anyway.
//   macOS    DiskArbitration appeared / disappeared / volume-path-changed callbacks.
// The callback runs on the monitor's thread, never concurrently with itself; it must not
// destroy the monitor. Construction enumerates once (no events for what exists already).
class VolumeMonitor {
public:
    using Callback = std::function<void(const std::vector<VolumeEvent>&)>;
    explicit VolumeMonitor(Callback callback, VolumeMonitorOptions options = VolumeMonitorOptions());
    ~VolumeMonitor();
    VolumeMonitor(const VolumeMonitor&) = delete;
    VolumeMonitor& operator=(const VolumeMonitor&) = delete;

    [[nodiscard]] std::vector<VolumeInfo> volumes() const; // as of the last enumeration
    void refresh();                                          // re-enumerate now (asynchronously)
    // Whether the platform notification is running; when false, `notification_error()` says
    // why and only the poll reports changes.
    [[nodiscard]] bool notifications_active() const noexcept;
    [[nodiscard]] std::string notification_error() const;

    struct Impl;

private:
    std::unique_ptr<Impl> impl_;
};

} // namespace bro::vfs
