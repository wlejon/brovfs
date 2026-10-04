// Test harness: checks are plain function calls (live in Release), failures are counted and
// printed, main() returns non-zero on any failure. Every test works only inside a scratch
// directory it creates and removes.
#pragma once

#include "brovfs/file_ops.h"
#include "brovfs/path.h"
#include "brovfs/scanner.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace t {

namespace fs = std::filesystem;
namespace vfs = bro::vfs;

inline int g_checks = 0;
inline int g_failures = 0;
inline std::string g_section;

inline void section(const std::string& name) {
    g_section = name;
    std::cout << "== " << name << "\n" << std::flush;
}
inline void note(const std::string& s) { std::cout << "   note: " << s << "\n" << std::flush; }

inline bool check(bool ok, const std::string& what, const char* file, int line) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::cout << "   FAIL [" << g_section << "] " << what << "  (" << file << ":" << line << ")\n" << std::flush;
    }
    return ok;
}
#define CHECK(cond) ::t::check(static_cast<bool>(cond), #cond, __FILE__, __LINE__)
#define CHECK_MSG(cond, msg) ::t::check(static_cast<bool>(cond), std::string(#cond) + " -- " + (msg), __FILE__, __LINE__)

inline int finish(const char* name) {
    std::cout << name << ": " << (g_checks - g_failures) << "/" << g_checks << " checks passed\n";
    return g_failures == 0 ? 0 : 1;
}

inline std::string u8(const fs::path& p) { return vfs::path_to_utf8(p); }
inline fs::path p8(const std::string& s) { return vfs::path_from_utf8(s); }

inline std::string describe(const vfs::OpResult& r) {
    std::string s = std::string(vfs::to_string(r.outcome)) + " files=" + std::to_string(r.files_done) +
                    " dirs=" + std::to_string(r.dirs_done) + " links=" + std::to_string(r.links_done) +
                    " skipped=" + std::to_string(r.skipped) + " errors=" + std::to_string(r.errors.size());
    for (size_t i = 0; i < r.errors.size() && i < 5; ++i) s += "\n      " + r.errors[i].message();
    return s;
}

// Long-path-safe std::filesystem path (Windows needs \\?\ for >260 chars).
inline fs::path L(const fs::path& p) {
#ifdef _WIN32
    return fs::path(vfs::win_extended_path(p));
#else
    return p;
#endif
}

inline void write_file(const fs::path& p, const std::string& content) {
    std::error_code ec;
    fs::create_directories(L(p.parent_path()), ec);
    std::ofstream out(L(p), std::ios::binary | std::ios::trunc);
    out << content;
}

inline std::string read_file(const fs::path& p) {
    std::ifstream in(L(p), std::ios::binary);
    if (!in) return "<missing>";
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

inline void write_big(const fs::path& p, uint64_t bytes, char seed = 'a') {
    std::error_code ec;
    fs::create_directories(L(p.parent_path()), ec);
    std::ofstream out(L(p), std::ios::binary | std::ios::trunc);
    std::string chunk(1 << 20, '\0');
    for (size_t i = 0; i < chunk.size(); ++i) chunk[i] = static_cast<char>(seed + (i * 7 + i / 4093) % 23);
    for (uint64_t left = bytes; left;) {
        uint64_t n = std::min<uint64_t>(left, chunk.size());
        out.write(chunk.data(), static_cast<std::streamsize>(n));
        left -= n;
    }
}

inline bool same_content(const fs::path& a, const fs::path& b) {
    std::ifstream ia(L(a), std::ios::binary), ib(L(b), std::ios::binary);
    if (!ia || !ib) return false;
    std::vector<char> ba(1 << 20), bb(1 << 20);
    for (;;) {
        ia.read(ba.data(), static_cast<std::streamsize>(ba.size()));
        ib.read(bb.data(), static_cast<std::streamsize>(bb.size()));
        if (ia.gcount() != ib.gcount()) return false;
        if (std::memcmp(ba.data(), bb.data(), static_cast<size_t>(ia.gcount())) != 0) return false;
        if (ia.gcount() == 0) return true;
    }
}

inline bool path_exists(const fs::path& p) {
    std::error_code ec;
    return fs::exists(fs::symlink_status(L(p), ec));
}

inline uintmax_t size_of(const fs::path& p) {
    std::error_code ec;
    auto s = fs::file_size(L(p), ec);
    return ec ? 0 : s;
}

// Oracle: count of entries under root by std::filesystem (no link following).
inline size_t count_tree(const fs::path& root) {
    size_t n = 0;
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(L(root), fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        ++n;
    }
    return n;
}

inline bool has_error(const vfs::OpResult& r, std::error_code code) {
    for (auto& e : r.errors) {
        if (e.code == code) return true;
    }
    return false;
}

inline double now_ms() {
    using namespace std::chrono;
    return duration<double, std::milli>(steady_clock::now().time_since_epoch()).count();
}

inline fs::path scratch_base() {
    if (const char* e = std::getenv("BROVFS_TEST_SCRATCH"); e && *e) return p8(e);
    return fs::current_path() / "brovfs-scratch";
}

// A directory on a different device than `than`, or empty.
inline fs::path other_volume_base(const fs::path& than) {
    std::vector<fs::path> candidates;
    if (const char* e = std::getenv("BROVFS_TEST_SCRATCH2"); e && *e) candidates.push_back(p8(e));
#ifdef _WIN32
    std::error_code tec;
    candidates.push_back(fs::temp_directory_path(tec) / "brovfs-scratch2");
#else
    candidates.push_back("/dev/shm/brovfs-scratch2");
#endif
    vfs::FileEntry a;
    std::error_code ec;
    if (!vfs::stat_entry(than, a, ec)) return {};
    for (auto& c : candidates) {
        fs::create_directories(c, ec);
        vfs::FileEntry b;
        if (vfs::stat_entry(c, b, ec) && b.id.device != a.id.device) return c;
    }
    return {};
}

class Scratch {
public:
    explicit Scratch(const std::string& name, fs::path base = fs::path()) {
        if (base.empty()) base = scratch_base();
        std::random_device rd;
        root_ = base / (name + "-" + std::to_string(rd() % 1000000));
        std::error_code ec;
        fs::create_directories(root_, ec);
        root_ = fs::absolute(root_, ec);
    }
    ~Scratch() { cleanup(); }
    Scratch(const Scratch&) = delete;
    Scratch& operator=(const Scratch&) = delete;
    const fs::path& root() const { return root_; }
    fs::path operator/(const fs::path& rel) const { return root_ / rel; }
    void cleanup() {
        if (root_.empty()) return;
#ifndef _WIN32
        // Restore permissions a test may have revoked, so cleanup can descend.
        std::error_code ec;
        for (auto it = fs::recursive_directory_iterator(root_, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) break;
            if (it->is_directory(ec) && !it->is_symlink(ec)) {
                fs::permissions(it->path(), fs::perms::owner_all, fs::perm_options::add, ec);
            }
        }
#endif
        // Links inside scratch point inside scratch; vfs::remove never follows them anyway.
        vfs::remove({root_});
        root_.clear();
    }

private:
    fs::path root_;
};

#ifdef _WIN32
inline int run_cmd(const std::wstring& cmd) {
    std::wstring full = L"cmd /c \"" + cmd + L"\" >nul 2>&1";
    return _wsystem(full.c_str());
}
inline bool make_junction(const fs::path& link, const fs::path& target) {
    return run_cmd(L"mklink /J \"" + link.wstring() + L"\" \"" + target.wstring() + L"\"") == 0 && path_exists(link);
}
#endif

inline bool make_dir_symlink(const fs::path& link, const fs::path& target) {
    std::error_code ec;
    fs::create_directory_symlink(target, link, ec);
    return !ec;
}

inline bool is_root_user() {
#ifdef _WIN32
    return false;
#else
    return ::geteuid() == 0;
#endif
}

} // namespace t
