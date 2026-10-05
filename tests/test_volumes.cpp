// Volume enumeration, path -> volume lookup, and VolumeMonitor add / change / remove events
// from a real (scratch-scoped) volume: a subst drive on Windows, a bind mount in a private
// mount namespace on Linux, an attached disk image on macOS.
#include "brovfs/volumes.h"
#include "harness.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

#ifdef __linux__
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

using namespace t;

namespace {

// Collects monitor events; waits for one matching a predicate.
struct Events {
    std::mutex mu;
    std::condition_variable cv;
    std::vector<vfs::VolumeEvent> all;
    void add(const std::vector<vfs::VolumeEvent>& ev) {
        {
            std::lock_guard<std::mutex> lk(mu);
            all.insert(all.end(), ev.begin(), ev.end());
        }
        cv.notify_all();
    }
    // Waits for an event of `kind` at `mount`; returns it (with how long it took).
    bool wait(vfs::VolumeEventKind kind, const fs::path& mount, int timeout_ms, vfs::VolumeEvent* out = nullptr,
              double* took_ms = nullptr) {
        double t0 = now_ms();
        std::unique_lock<std::mutex> lk(mu);
        bool ok = cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] {
            for (auto& e : all) {
                if (e.kind == kind && e.volume.mount_point == mount) {
                    if (out) *out = e;
                    return true;
                }
            }
            return false;
        });
        if (took_ms) *took_ms = now_ms() - t0;
        return ok;
    }
};

// The poll is set far beyond the waits below, so prompt events prove the notification path.
vfs::VolumeMonitorOptions slow_poll() {
    vfs::VolumeMonitorOptions o;
    o.poll_interval = std::chrono::minutes(10);
    return o;
}

void test_list_and_lookup(const Scratch& s) {
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
#ifdef __APPLE__
        // /Users is firmlinked from the Data volume: the path is reached through "/", and the
        // same object lives under the Data volume's own mount point.
        if (!rel.empty() && *rel.begin() == "..") {
            fs::path via = here->mount_point / fs::canonical(s.root(), ec).relative_path();
            CHECK_MSG(vfs::same_file(via, s.root(), ec), u8(via));
            rel = fs::path("firmlinked");
        }
#endif
        CHECK_MSG(!rel.empty() && *rel.begin() != "..", u8(rel));
        CHECK(!here->is_read_only);
    }
    auto future = vfs::get_volume_for_path(s / "does" / "not" / "exist");
    CHECK(future.has_value() && here && future->mount_point == here->mount_point);
}

#ifdef _WIN32
// subst.exe defines a drive letter for this logon session and broadcasts WM_DEVICECHANGE.
void test_monitor(const Scratch& s) {
    section("VolumeMonitor: a subst drive appears and disappears");
    DWORD used = GetLogicalDrives();
    wchar_t letter = 0;
    for (wchar_t c = L'Z'; c >= L'M'; --c) {
        if (!(used & (1u << (c - L'A')))) {
            letter = c;
            break;
        }
    }
    if (!letter) {
        note("no free drive letter; skipped");
        return;
    }
    fs::path target = s / "substed";
    fs::create_directories(L(target));
    std::wstring drive = std::wstring(1, letter) + L":";
    fs::path mount = drive + L"\\";
    Events ev;
    vfs::VolumeMonitor mon([&](const std::vector<vfs::VolumeEvent>& e) { ev.add(e); }, slow_poll());
    CHECK_MSG(mon.notifications_active(), mon.notification_error());
    struct Undefine {
        std::wstring d;
        bool on = false;
        ~Undefine() {
            if (on) run_cmd(L"subst " + d + L" /d");
        }
    } guard{drive};
    guard.on = run_cmd(L"subst " + drive + L" \"" + target.wstring() + L"\"") == 0;
    CHECK(guard.on);
    if (!guard.on) return;
    double took = 0;
    vfs::VolumeEvent added;
    bool prompt = ev.wait(vfs::VolumeEventKind::Added, mount, 8000, &added, &took);
    if (!prompt) {
        // subst did not broadcast here: the event must still come from an explicit refresh.
        note("no WM_DEVICECHANGE from subst; checking refresh()");
        mon.refresh();
        prompt = ev.wait(vfs::VolumeEventKind::Added, mount, 5000, &added, &took);
    } else {
        note("Added after " + std::to_string(static_cast<int>(took)) + " ms");
    }
    CHECK_MSG(prompt, "no Added event for " + u8(mount));
    CHECK(added.volume.fs_type.size() > 0 && added.volume.total_bytes > 0);
    bool listed = false;
    for (auto& v : mon.volumes()) listed |= v.mount_point == mount;
    CHECK(listed);
    guard.on = false;
    CHECK(run_cmd(L"subst " + drive + L" /d") == 0);
    bool removed = ev.wait(vfs::VolumeEventKind::Removed, mount, 8000, nullptr, &took);
    if (!removed) {
        mon.refresh();
        removed = ev.wait(vfs::VolumeEventKind::Removed, mount, 5000);
    }
    CHECK_MSG(removed, "no Removed event for " + u8(mount));
}
#elif defined(__linux__)
bool write_proc(const char* file, const std::string& text) {
    int fd = ::open(file, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size());
    ::close(fd);
    return ok;
}

// In a child with its own user + mount namespace (nothing outside it sees these mounts): bind
// mount a scratch directory, remount it read-only, unmount it.
int monitor_child(const fs::path& base) {
    uid_t uid = ::getuid();
    gid_t gid = ::getgid();
    if (::unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) return 77;
    write_proc("/proc/self/setgroups", "deny");
    if (!write_proc("/proc/self/uid_map", "0 " + std::to_string(uid) + " 1") ||
        !write_proc("/proc/self/gid_map", "0 " + std::to_string(gid) + " 1") ||
        ::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
        return 77;
    }
    g_checks = g_failures = 0;
    fs::path src = base / "bind-src";
    fs::path mnt = base / "bind-mnt";
    fs::create_directories(src);
    fs::create_directories(mnt);
    Events ev;
    vfs::VolumeMonitor mon([&](const std::vector<vfs::VolumeEvent>& e) { ev.add(e); }, slow_poll());
    CHECK_MSG(mon.notifications_active(), mon.notification_error());
    CHECK(::mount(src.c_str(), mnt.c_str(), nullptr, MS_BIND, nullptr) == 0);
    double took = 0;
    vfs::VolumeEvent e;
    CHECK(ev.wait(vfs::VolumeEventKind::Added, mnt, 5000, &e, &took));
    note("Added after " + std::to_string(static_cast<int>(took)) + " ms");
    CHECK(!e.volume.is_read_only);
    CHECK(::mount(nullptr, mnt.c_str(), nullptr, MS_REMOUNT | MS_BIND | MS_RDONLY, nullptr) == 0);
    CHECK(ev.wait(vfs::VolumeEventKind::Changed, mnt, 5000, &e) && e.volume.is_read_only);
    CHECK(::umount2(mnt.c_str(), 0) == 0);
    CHECK(ev.wait(vfs::VolumeEventKind::Removed, mnt, 5000));
    return g_failures == 0 ? 0 : 1;
}

void test_monitor(const Scratch& s) {
    section("VolumeMonitor: bind mount added, remounted read-only, removed (private namespace)");
    std::cout << std::flush;
    pid_t pid = ::fork();
    if (pid == 0) ::_exit(monitor_child(s.root()));
    int status = 0;
    ::waitpid(pid, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 255;
    if (code == 77) {
        note("unprivileged user + mount namespaces unavailable; skipped");
        return;
    }
    CHECK_MSG(code == 0, "child exit " + std::to_string(code));
}
#elif defined(__APPLE__)
int run(const std::string& cmd) { return std::system(cmd.c_str()); }

// A disk image attached at a scratch mount point (browsable, so list_volumes lists it).
void test_monitor(const Scratch& s) {
    section("VolumeMonitor: a disk image attached and detached");
    fs::path img = s / "mon.dmg";
    fs::path mnt = s / "mon-mnt";
    fs::create_directories(mnt);
    if (run("hdiutil create -quiet -size 8m -fs APFS -volname brovfsmon '" + img.native() + "'") != 0) {
        CHECK_MSG(false, "hdiutil create failed");
        return;
    }
    Events ev;
    vfs::VolumeMonitor mon([&](const std::vector<vfs::VolumeEvent>& e) { ev.add(e); }, slow_poll());
    CHECK_MSG(mon.notifications_active(), mon.notification_error());
    bool attached = run("hdiutil attach -quiet -noautoopen -mountpoint '" + mnt.native() + "' '" + img.native() + "'") == 0;
    CHECK(attached);
    if (!attached) return;
    fs::path real = fs::canonical(mnt); // the kernel reports /private/var..., not /var...
    double took = 0;
    vfs::VolumeEvent e;
    bool added = ev.wait(vfs::VolumeEventKind::Added, real, 8000, &e, &took) ||
                 ev.wait(vfs::VolumeEventKind::Added, mnt, 10, &e, &took);
    CHECK_MSG(added, "no Added event for " + u8(real));
    if (added) note("Added after " + std::to_string(static_cast<int>(took)) + " ms, fs=" + e.volume.fs_type);
    CHECK(run("hdiutil detach -quiet -force '" + mnt.native() + "'") == 0);
    CHECK(ev.wait(vfs::VolumeEventKind::Removed, e.volume.mount_point, 8000));
}
#else
void test_monitor(const Scratch&) {}
#endif

void test_monitor_lifecycle() {
    section("VolumeMonitor: start / refresh / stop with no change reports nothing");
    Events ev;
    {
        vfs::VolumeMonitorOptions o;
        o.poll_interval = std::chrono::milliseconds(50);
        vfs::VolumeMonitor mon([&](const std::vector<vfs::VolumeEvent>& e) { ev.add(e); }, o);
        CHECK(!mon.volumes().empty());
        mon.refresh();
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    std::lock_guard<std::mutex> lk(ev.mu);
    for (auto& e : ev.all) note("unexpected event at " + u8(e.volume.mount_point)); // a real mount may race
}

} // namespace

int main() {
    Scratch s("volumes");
#ifdef __linux__
    test_monitor(s); // forks: before this process has any threads
#endif
    test_list_and_lookup(s);
    test_monitor_lifecycle();
#ifndef __linux__
    test_monitor(s);
#endif
    return finish("test_volumes");
}
