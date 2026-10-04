#include "brovfs/volumes.h"
#include <cassert>
#include <filesystem>
#include <iostream>

#ifdef _WIN32
#include <crtdbg.h>
#include <cstdlib>
#endif

namespace fs = std::filesystem;

int main() {
#ifdef _WIN32
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
    std::cout << "[test_volumes] Querying mounted volumes..." << std::endl;
    auto volumes = bro::vfs::list_volumes();

    std::cout << "[test_volumes] Detected " << volumes.size() << " volume(s):" << std::endl;
    for (const auto& v : volumes) {
        std::cout << "  Mount: " << v.mount_point
                  << " | Label: " << v.volume_label
                  << " | FS: " << v.fs_type
                  << " | Total: " << (v.total_bytes / (1024 * 1024 * 1024)) << " GB"
                  << " | Free: " << (v.free_bytes / (1024 * 1024 * 1024)) << " GB"
                  << " | Used: " << v.used_percentage() << "%"
                  << " | Removable: " << (v.is_removable ? "yes" : "no")
                  << " | ReadOnly: " << (v.is_read_only ? "yes" : "no")
                  << std::endl;
    }

    assert(!volumes.empty());

    bool found_valid = false;
    for (const auto& v : volumes) {
        assert(!v.mount_point.empty());
        if (v.total_bytes > 0) {
            found_valid = true;
            assert(v.free_bytes <= v.total_bytes);
            assert(v.available_bytes <= v.total_bytes);
            assert(v.used_percentage() >= 0.0 && v.used_percentage() <= 100.0);
        }
    }
    assert(found_valid);

    std::cout << "[test_volumes] Testing get_volume_for_path on current directory..." << std::endl;
    auto curr_vol = bro::vfs::get_volume_for_path(fs::current_path().string());
    assert(curr_vol.has_value());
    assert(curr_vol->total_bytes > 0);
    std::cout << "[test_volumes] Current directory volume: " << curr_vol->mount_point << std::endl;

    std::cout << "[test_volumes] All volume tests passed successfully!" << std::endl;
    return 0;
}
