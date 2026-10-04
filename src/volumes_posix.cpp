#ifndef _WIN32

#include "src/volumes_internal.h"
#include <sys/statvfs.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_set>

namespace bro::vfs::detail {

namespace {

bool is_pseudo_fs(const std::string& fs_type) {
    static const std::unordered_set<std::string> pseudo_types = {
        "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "securityfs", "cgroup", "cgroup2",
        "pstore", "bpf", "debugfs", "tracefs", "hugetlbfs", "mqueue", "autofs", "fusectl",
        "configfs", "binfmt_misc", "efivarfs", "ramfs", "overlay"
    };
    return pseudo_types.count(fs_type) > 0;
}

} // namespace

std::vector<VolumeInfo> list_volumes_platform() {
    std::vector<VolumeInfo> volumes;

    std::ifstream mounts_file("/proc/mounts");
    if (!mounts_file.is_open()) {
        mounts_file.open("/etc/mtab");
    }

    if (!mounts_file.is_open()) {
        // Fallback for root filesystem if no mount table found
        struct statvfs st;
        if (statvfs("/", &st) == 0) {
            VolumeInfo info;
            info.mount_point = "/";
            info.volume_label = "root";
            info.fs_type = "rootfs";
            info.total_bytes = static_cast<uint64_t>(st.f_blocks) * st.f_frsize;
            info.free_bytes = static_cast<uint64_t>(st.f_bfree) * st.f_frsize;
            info.available_bytes = static_cast<uint64_t>(st.f_bavail) * st.f_frsize;
            info.is_read_only = (st.f_flag & ST_RDONLY) != 0;
            volumes.push_back(info);
        }
        return volumes;
    }

    std::string line;
    std::unordered_set<std::string> seen_mounts;

    while (std::getline(mounts_file, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream ss(line);
        std::string device, mount_point, fs_type, options;
        if (!(ss >> device >> mount_point >> fs_type >> options)) {
            continue;
        }
        // /proc/mounts escapes space, tab, newline and backslash as \ooo.
        std::string decoded;
        for (size_t i = 0; i < mount_point.size(); ++i) {
            if (mount_point[i] == '\\' && i + 3 < mount_point.size()) {
                decoded.push_back(static_cast<char>(std::stoi(mount_point.substr(i + 1, 3), nullptr, 8)));
                i += 3;
            } else {
                decoded.push_back(mount_point[i]);
            }
        }
        mount_point = decoded;
        bool ro_option = false;
        {
            std::istringstream opts(options);
            std::string opt;
            while (std::getline(opts, opt, ',')) ro_option |= opt == "ro";
        }

        if (is_pseudo_fs(fs_type)) {
            continue;
        }

        if (seen_mounts.count(mount_point) > 0) {
            continue;
        }
        seen_mounts.insert(mount_point);

        struct statvfs st;
        if (statvfs(mount_point.c_str(), &st) != 0) {
            continue;
        }

        VolumeInfo info;
        info.mount_point = mount_point;
        info.volume_label = device;
        info.fs_type = fs_type;
        info.total_bytes = static_cast<uint64_t>(st.f_blocks) * st.f_frsize;
        info.free_bytes = static_cast<uint64_t>(st.f_bfree) * st.f_frsize;
        info.available_bytes = static_cast<uint64_t>(st.f_bavail) * st.f_frsize;
        info.is_read_only = (st.f_flag & ST_RDONLY) != 0 || ro_option;

        if (device.find("/dev/sd") != std::string::npos || device.find("/dev/mmcblk") != std::string::npos) {
            if (mount_point.find("/media/") != std::string::npos || mount_point.find("/run/media/") != std::string::npos) {
                info.is_removable = true;
            }
        }

        volumes.push_back(std::move(info));
    }

    return volumes;
}

} // namespace bro::vfs::detail

#endif // !_WIN32
