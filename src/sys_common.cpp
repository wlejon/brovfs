#include "src/sys.h"

#include <chrono>
#include <cstdio>
#include <random>

namespace bro::vfs::sys {

std::atomic<bool> g_force_cross_device{false};
std::atomic<int> g_open_dirs{0};
std::atomic<int> g_open_dirs_peak{0};

void count_dir_open() noexcept {
    int now = g_open_dirs.fetch_add(1, std::memory_order_relaxed) + 1;
    int peak = g_open_dirs_peak.load(std::memory_order_relaxed);
    while (now > peak && !g_open_dirs_peak.compare_exchange_weak(peak, now, std::memory_order_relaxed)) {
    }
}

void count_dir_close() noexcept { g_open_dirs.fetch_sub(1, std::memory_order_relaxed); }

bool exists_nofollow(const fs::path& p) {
    Stat st;
    std::error_code ec;
    return lstat(p, st, ec);
}

bool make_dirs(const fs::path& p, std::error_code& ec) {
    Stat st;
    std::error_code sec;
    if (stat_follow(p, st, sec)) {
        if (st.kind == FileKind::Directory) return true;
        ec = std::make_error_code(std::errc::not_a_directory);
        return false;
    }
    fs::path parent = p.parent_path();
    if (!parent.empty() && parent != p && !make_dirs(parent, ec)) return false;
    if (make_dir_default(p, ec)) return true;
    if (is_exists_error(ec) && stat_follow(p, st, sec) && st.kind == FileKind::Directory) {
        ec.clear();
        return true;
    }
    return false;
}

fs::path temp_sibling(const fs::path& dir) {
    thread_local std::mt19937_64 rng([] {
        std::random_device rd;
        return (static_cast<uint64_t>(rd()) << 32) ^ rd() ^
               static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    }());
    char name[48];
    std::snprintf(name, sizeof(name), ".brovfs-%016llx.tmp", static_cast<unsigned long long>(rng()));
    return dir / name;
}

int64_t now_unix_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

} // namespace bro::vfs::sys
