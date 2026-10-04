// Volume enumeration and path -> volume lookup.
#include "brovfs/volumes.h"
#include "harness.h"

using namespace t;

int main() {
    Scratch s("volumes");
    section("list_volumes");
    auto volumes = vfs::list_volumes();
    CHECK(!volumes.empty());
    bool sized = false;
    for (const auto& v : volumes) {
        note(u8(v.mount_point) + " fs=" + v.fs_type + " label=" + v.volume_label +
             " total=" + std::to_string(v.total_bytes >> 30) + "G ro=" + (v.is_read_only ? "1" : "0"));
        CHECK(!v.mount_point.empty());
        if (v.total_bytes > 0) {
            sized = true;
            CHECK(v.free_bytes <= v.total_bytes && v.available_bytes <= v.total_bytes);
            CHECK(v.used_percentage() >= 0.0 && v.used_percentage() <= 100.0);
        }
    }
    CHECK(sized);

    section("get_volume_for_path");
    auto here = vfs::get_volume_for_path(s.root());
    CHECK(here.has_value() && here->total_bytes > 0);
    if (here) {
        note("scratch is on " + u8(here->mount_point));
        // The chosen mount must contain the path (not a same-device bind mount elsewhere).
        std::error_code ec;
        auto rel = fs::canonical(s.root(), ec).lexically_relative(here->mount_point);
        CHECK_MSG(!rel.empty() && *rel.begin() != "..", u8(rel));
        CHECK(!here->is_read_only);
    }
    auto future = vfs::get_volume_for_path(s / "does" / "not" / "exist");
    CHECK(future.has_value() && here && future->mount_point == here->mount_point);
    return finish("test_volumes");
}
