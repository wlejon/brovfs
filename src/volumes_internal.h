#pragma once

#include "brovfs/volumes.h"
#include <vector>

namespace bro::vfs::detail {

std::vector<VolumeInfo> list_volumes_platform();

// Platform volume notification for VolumeMonitor: calls `trigger` (from any thread) whenever
// the volume set may have changed, until destroyed. Destruction waits for any running call.
class VolumeNotifier {
public:
    virtual ~VolumeNotifier() = default;
};
std::unique_ptr<VolumeNotifier> start_volume_notifier(std::function<void()> trigger, std::string& error);

} // namespace bro::vfs::detail
