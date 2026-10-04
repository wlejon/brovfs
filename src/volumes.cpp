#include "brovfs/volumes.h"

#include "brovfs/path.h"
#include "src/sys.h"
#include "src/volumes_internal.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace bro::vfs {

namespace fs = std::filesystem;

std::vector<VolumeInfo> list_volumes() { return detail::list_volumes_platform(); }

std::optional<VolumeInfo> get_volume_for_path(const fs::path& path) {
    auto volumes = list_volumes();
#ifdef _WIN32
    std::wstring w = win_extended_path(path);
    std::vector<wchar_t> root(w.size() + 2);
    if (!GetVolumePathNameW(w.c_str(), root.data(), static_cast<DWORD>(root.size()))) return std::nullopt;
    std::wstring r = root.data();
    if (r.rfind(L"\\\\?\\", 0) == 0) r = r.substr(4);
    for (auto& v : volumes) {
        const std::wstring& m = v.mount_point.native();
        if (CompareStringOrdinal(m.c_str(), static_cast<int>(m.size()), r.c_str(), static_cast<int>(r.size()), TRUE) ==
            CSTR_EQUAL) {
            return v;
        }
    }
    return std::nullopt;
#else
    sys::Stat st;
    std::error_code ec;
    fs::path probe = fs::absolute(path, ec);
    while (!sys::stat_follow(probe, st, ec)) { // a path that does not exist yet: its nearest ancestor
        fs::path parent = probe.parent_path();
        if (parent.empty() || parent == probe) return std::nullopt;
        probe = parent;
    }
    // Bind mounts share a device: prefer the deepest same-device mount that contains the
    // canonical path, and only then any same-device mount.
    fs::path real = fs::canonical(probe, ec);
    if (ec) real = probe;
    auto contains = [&](const fs::path& mount) {
        auto rel = real.lexically_relative(mount);
        return !rel.empty() && *rel.begin() != "..";
    };
    std::optional<VolumeInfo> best;
    bool best_contains = false;
    for (auto& v : volumes) {
        sys::Stat ms;
        if (!sys::stat_follow(v.mount_point, ms, ec) || ms.id.device != st.id.device) continue;
        bool c = contains(v.mount_point);
        bool deeper = !best || v.mount_point.native().size() > best->mount_point.native().size();
        if (!best || (c && !best_contains) || (c == best_contains && deeper)) {
            best = v;
            best_contains = c;
        }
    }
    return best;
#endif
}

} // namespace bro::vfs
