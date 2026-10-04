#include "brovfs/volumes.h"
#include "brovfs/types.h"
#include "src/volumes_internal.h"
#include <algorithm>
#include <filesystem>

namespace bro::vfs {

namespace fs = std::filesystem;

namespace {

std::string normalize_mount_key(std::string_view p) {
    std::string s = normalize_path(p);
#ifdef _WIN32
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
#endif
    return s;
}

} // namespace

std::vector<VolumeInfo> list_volumes() {
    return detail::list_volumes_platform();
}

std::optional<VolumeInfo> get_volume_for_path(const std::string& path) {
    auto volumes = list_volumes();
    if (volumes.empty()) {
        return std::nullopt;
    }

    std::error_code ec;
    fs::path abs_p = fs::absolute(fs::path(path), ec);
    std::string norm_target = normalize_mount_key(abs_p.generic_string());

    std::optional<VolumeInfo> best_match;
    size_t best_len = 0;

    for (const auto& vol : volumes) {
        std::string norm_mount = normalize_mount_key(vol.mount_point);
        if (norm_target.rfind(norm_mount, 0) == 0) {
            if (norm_mount.size() > best_len) {
                best_len = norm_mount.size();
                best_match = vol;
            }
        }
    }

    if (!best_match && !volumes.empty()) {
        return volumes.front();
    }

    return best_match;
}

} // namespace bro::vfs
