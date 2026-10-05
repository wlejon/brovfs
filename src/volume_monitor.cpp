// VolumeMonitor: a thread that re-enumerates the volume set when the platform notifier says it
// may have changed (and on a backstop poll) and reports the difference. The Linux notifier is
// here; Windows and macOS have their own files.
#include "brovfs/volumes.h"

#include "src/volumes_internal.h"

#include <algorithm>
#include <condition_variable>
#include <map>
#include <mutex>
#include <thread>

#if defined(__linux__)
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#endif

namespace bro::vfs {

namespace {

using Clock = std::chrono::steady_clock;

bool same_volume_state(const VolumeInfo& a, const VolumeInfo& b) {
    return a.volume_label == b.volume_label && a.fs_type == b.fs_type && a.total_bytes == b.total_bytes &&
           a.is_read_only == b.is_read_only && a.is_removable == b.is_removable && a.is_network == b.is_network;
}

std::vector<VolumeEvent> diff_volumes(const std::vector<VolumeInfo>& before, const std::vector<VolumeInfo>& after) {
    std::map<std::filesystem::path, const VolumeInfo*> old_by_mount, new_by_mount;
    for (auto& v : before) old_by_mount.emplace(v.mount_point, &v);
    for (auto& v : after) new_by_mount.emplace(v.mount_point, &v);
    std::vector<VolumeEvent> events;
    for (auto& [mount, v] : old_by_mount) {
        if (!new_by_mount.count(mount)) events.push_back({VolumeEventKind::Removed, *v});
    }
    for (auto& [mount, v] : new_by_mount) {
        auto it = old_by_mount.find(mount);
        if (it == old_by_mount.end()) {
            events.push_back({VolumeEventKind::Added, *v});
        } else if (!same_volume_state(*it->second, *v)) {
            events.push_back({VolumeEventKind::Changed, *v});
        }
    }
    return events;
}

} // namespace

struct VolumeMonitor::Impl {
    Callback callback;
    VolumeMonitorOptions options;
    mutable std::mutex mu;
    std::condition_variable cv;
    std::vector<VolumeInfo> current;
    std::vector<Clock::time_point> due; // pending re-enumerations, soonest first
    bool stop = false;
    std::unique_ptr<detail::VolumeNotifier> notifier;
    std::string notifier_error;
    std::thread thread;

    void trigger() {
        // Now, and again after the OS has had time to finish what it announced.
        auto now = Clock::now();
        {
            std::lock_guard<std::mutex> lk(mu);
            for (auto d : {std::chrono::milliseconds(0), std::chrono::milliseconds(300), std::chrono::milliseconds(1500)}) {
                due.push_back(now + d);
            }
            std::sort(due.begin(), due.end());
        }
        cv.notify_all();
    }

    void run() {
        auto next_poll = Clock::now() + options.poll_interval;
        std::unique_lock<std::mutex> lk(mu);
        while (!stop) {
            auto now = Clock::now();
            auto wake = due.empty() ? next_poll : std::min(next_poll, due.front());
            if (now < wake) {
                cv.wait_until(lk, wake); // any notify re-evaluates the earliest deadline
                continue;
            }
            // Every request due by now is served by this one enumeration.
            due.erase(due.begin(), std::upper_bound(due.begin(), due.end(), now));
            next_poll = now + options.poll_interval;
            lk.unlock();
            auto fresh = detail::list_volumes_platform();
            lk.lock();
            auto events = diff_volumes(current, fresh);
            current = std::move(fresh);
            if (events.empty()) continue;
            lk.unlock();
            callback(events);
            lk.lock();
        }
    }
};

VolumeMonitor::VolumeMonitor(Callback callback, VolumeMonitorOptions options) : impl_(std::make_unique<Impl>()) {
    impl_->callback = std::move(callback);
    if (options.poll_interval < std::chrono::milliseconds(50)) options.poll_interval = std::chrono::milliseconds(50);
    impl_->options = options;
    impl_->current = detail::list_volumes_platform();
    Impl* impl = impl_.get();
    impl_->thread = std::thread([impl] { impl->run(); });
    impl_->notifier = detail::start_volume_notifier([impl] { impl->trigger(); }, impl_->notifier_error);
}

VolumeMonitor::~VolumeMonitor() {
    impl_->notifier.reset(); // no trigger() after this
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        impl_->stop = true;
    }
    impl_->cv.notify_all();
    if (impl_->thread.joinable()) impl_->thread.join();
}

std::vector<VolumeInfo> VolumeMonitor::volumes() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->current;
}

void VolumeMonitor::refresh() {
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        impl_->due.insert(impl_->due.begin(), std::chrono::steady_clock::now());
    }
    impl_->cv.notify_all();
}

bool VolumeMonitor::notifications_active() const noexcept { return impl_->notifier != nullptr; }

std::string VolumeMonitor::notification_error() const { return impl_->notifier_error; }

// ---------------------------------------------------------------- Linux notifier

#if defined(__linux__)
namespace detail {

namespace {

// poll() on /proc/self/mountinfo reports POLLERR | POLLPRI whenever the mount table of this
// mount namespace changes (the event count is re-armed by the poll itself).
class MountinfoNotifier final : public VolumeNotifier {
public:
    MountinfoNotifier(int fd, int wake, std::function<void()> trigger)
        : fd_(fd), wake_(wake), trigger_(std::move(trigger)), thread_([this] { run(); }) {}
    ~MountinfoNotifier() override {
        uint64_t one = 1;
        ssize_t n = ::write(wake_, &one, sizeof(one));
        (void)n;
        thread_.join();
        ::close(fd_);
        ::close(wake_);
    }

private:
    void run() {
        for (;;) {
            pollfd p[2] = {{fd_, POLLPRI, 0}, {wake_, POLLIN, 0}};
            int r = ::poll(p, 2, -1);
            if (r < 0) {
                if (errno == EINTR) continue;
                return; // the backstop poll carries on
            }
            if (p[1].revents) return;
            if (p[0].revents & (POLLPRI | POLLERR)) trigger_();
        }
    }
    int fd_;
    int wake_;
    std::function<void()> trigger_;
    std::thread thread_;
};

} // namespace

std::unique_ptr<VolumeNotifier> start_volume_notifier(std::function<void()> trigger, std::string& error) {
    int fd = ::open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        error = std::string("open /proc/self/mountinfo: ") + std::strerror(errno);
        return nullptr;
    }
    int wake = ::eventfd(0, EFD_CLOEXEC);
    if (wake < 0) {
        error = std::string("eventfd: ") + std::strerror(errno);
        ::close(fd);
        return nullptr;
    }
    return std::make_unique<MountinfoNotifier>(fd, wake, std::move(trigger));
}

} // namespace detail
#elif !defined(_WIN32) && !defined(__APPLE__)
namespace detail {
std::unique_ptr<VolumeNotifier> start_volume_notifier(std::function<void()>, std::string& error) {
    error = "no volume notification on this platform; polling only";
    return nullptr;
}
} // namespace detail
#endif

} // namespace bro::vfs
