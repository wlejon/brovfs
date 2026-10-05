#include "src/watch_core.h"

#include "brovfs/path.h"
#include "src/sys.h"

#include <atomic>
#include <set>

namespace bro::vfs {

std::string_view to_string(WatchEventKind kind) noexcept {
    switch (kind) {
        case WatchEventKind::Created: return "created";
        case WatchEventKind::Removed: return "removed";
        case WatchEventKind::Modified: return "modified";
        case WatchEventKind::Renamed: return "renamed";
        case WatchEventKind::Rescan: return "rescan";
        case WatchEventKind::RootRemoved: return "root-removed";
        case WatchEventKind::Error: return "error";
    }
    return "?";
}

namespace detail {

std::atomic<int> g_watch_stall_ms{0};

void stall_for_test() {
    int ms = g_watch_stall_ms.load();
    if (ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

bool path_within(const fs::path& p, const fs::path& dir) {
    const auto& a = p.native();
    const auto& d = dir.native();
    if (a.size() < d.size() || a.compare(0, d.size(), d) != 0) return false;
    if (a.size() == d.size()) return true;
    if (!d.empty() && (d.back() == '/' || d.back() == fs::path::preferred_separator)) return true;
    auto c = a[d.size()];
    return c == '/' || c == fs::path::preferred_separator;
}

EventSink::EventSink(std::shared_ptr<WatchEventQueue> out) : out_(std::move(out)) {
    thread_ = std::thread([this] { run(); });
}

EventSink::~EventSink() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_ = true;
    }
    cv_.notify_all();
    thread_.join();
}

void EventSink::open(WatchId id, std::chrono::milliseconds latency) {
    std::lock_guard<std::mutex> lock(mutex_);
    Batch& b = batches_[id];
    b.latency = latency;
}

void EventSink::close(WatchId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    batches_.erase(id);
}

void EventSink::take_locked(Batch& b, std::vector<WatchEvent>& out) {
    for (auto& e : b.events) {
        if (e) out.push_back(std::move(*e));
    }
    b.events.clear();
    b.last.clear();
    b.pending = false;
}

void EventSink::add_locked(Batch& b, WatchEvent&& ev, std::vector<WatchEvent>& now) {
    using K = WatchEventKind;
    if (b.latency.count() <= 0) {
        now.push_back(std::move(ev));
        return;
    }
    const auto key = ev.path.native();
    switch (ev.kind) {
        case K::Modified:
        case K::Created:
        case K::Removed: {
            auto it = b.last.find(key);
            if (it != b.last.end() && b.events[it->second]) {
                WatchEvent& prev = *b.events[it->second];
                if (ev.kind == K::Modified && (prev.kind == K::Modified || prev.kind == K::Created)) {
                    if (prev.file_kind == FileKind::Unknown) prev.file_kind = ev.file_kind;
                    return; // already announced
                }
                if (ev.kind == K::Removed && prev.kind == K::Created) {
                    b.events[it->second].reset(); // appeared and vanished inside the window
                    b.last.erase(it);
                    return;
                }
                if (ev.kind == K::Removed && prev.kind == K::Modified) {
                    b.events[it->second].reset(); // the removal supersedes it, at a later position
                }
            }
            b.last[key] = b.events.size();
            b.events.emplace_back(std::move(ev));
            break;
        }
        default:
            // Renames, rescans and errors are barriers: nothing merges across them.
            b.last.clear();
            b.events.emplace_back(std::move(ev));
            break;
    }
    if (!b.pending) {
        b.pending = true;
        b.deadline = std::chrono::steady_clock::now() + b.latency;
        cv_.notify_all();
    }
}

void EventSink::add(WatchEvent ev) {
    std::vector<WatchEvent> now;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = batches_.find(ev.watch);
        if (it == batches_.end()) return;
        Batch& b = it->second;
        bool terminal = ev.kind == WatchEventKind::RootRemoved;
        add_locked(b, std::move(ev), now);
        if (terminal) take_locked(b, now);
        // Pushed under the lock so deliveries of one watch never overtake each other.
        if (!now.empty()) out_->push_all(std::move(now));
    }
}

void EventSink::rescan(WatchId id, const fs::path& dir, std::error_code why) {
    std::vector<WatchEvent> now;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = batches_.find(id);
    if (it == batches_.end()) return;
    Batch& b = it->second;
    for (auto& e : b.events) {
        if (!e) continue;
        if (path_within(e->path, dir) && (e->kind != WatchEventKind::Renamed || path_within(e->old_path, dir)) &&
            e->kind != WatchEventKind::Error && e->kind != WatchEventKind::RootRemoved) {
            e.reset();
        }
    }
    WatchEvent ev;
    ev.kind = WatchEventKind::Rescan;
    ev.watch = id;
    ev.path = dir;
    ev.file_kind = FileKind::Directory;
    ev.error = why;
    add_locked(b, std::move(ev), now);
    if (!now.empty()) out_->push_all(std::move(now));
}

void EventSink::flush(WatchId id) {
    std::vector<WatchEvent> now;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = batches_.find(id);
    if (it == batches_.end()) return;
    take_locked(it->second, now);
    if (!now.empty()) out_->push_all(std::move(now));
}

void EventSink::run() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!stop_) {
        auto now = std::chrono::steady_clock::now();
        auto next = std::chrono::steady_clock::time_point::max();
        std::vector<WatchEvent> due;
        for (auto& [id, b] : batches_) {
            if (!b.pending) continue;
            if (b.deadline <= now) {
                take_locked(b, due);
            } else if (b.deadline < next) {
                next = b.deadline;
            }
        }
        if (!due.empty()) out_->push_all(std::move(due));
        if (next == std::chrono::steady_clock::time_point::max()) {
            cv_.wait(lock);
        } else {
            cv_.wait_until(lock, next);
        }
    }
}

} // namespace detail

struct DirectoryWatcher::Impl {
    explicit Impl(std::shared_ptr<WatchEventQueue> q) : sink(std::move(q)) {
        backend = detail::make_watch_backend(sink);
    }
    detail::EventSink sink;
    std::unique_ptr<detail::WatchBackend> backend;
    std::mutex mutex;
    std::set<WatchId> ids;
    std::atomic<WatchId> next{1};
};

DirectoryWatcher::DirectoryWatcher(std::shared_ptr<WatchEventQueue> queue)
    : queue_(queue ? std::move(queue) : std::make_shared<WatchEventQueue>()),
      impl_(std::make_unique<Impl>(queue_)) {}

DirectoryWatcher::~DirectoryWatcher() {
    std::set<WatchId> ids;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        ids.swap(impl_->ids);
    }
    for (WatchId id : ids) {
        impl_->backend->remove(id);
        impl_->sink.close(id);
    }
    impl_->backend.reset();
}

WatchId DirectoryWatcher::add(const fs::path& root_in, const WatchOptions& options, std::error_code& ec) {
    ec.clear();
    fs::path root = strip_trailing_separators(root_in);
    if (root.empty()) {
        ec = make_error_code(Errc::invalid_argument);
        return 0;
    }
    sys::Stat st;
    if (!sys::stat_follow(root, st, ec)) return 0;
    if (st.kind != FileKind::Directory) {
        ec = std::make_error_code(std::errc::not_a_directory);
        return 0;
    }
    fs::path real = fs::canonical(root, ec);
    if (ec) return 0;
    WatchId id = impl_->next.fetch_add(1);
    impl_->sink.open(id, options.latency);
    if (!impl_->backend || !impl_->backend->add(id, root, real, options, ec)) {
        if (!ec) ec = std::make_error_code(std::errc::not_supported);
        impl_->sink.close(id);
        return 0;
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->ids.insert(id);
    return id;
}

bool DirectoryWatcher::remove(WatchId id) {
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->ids.erase(id) == 0) return false;
    }
    impl_->backend->remove(id);
    impl_->sink.close(id);
    return true;
}

std::string_view DirectoryWatcher::backend_name() noexcept { return detail::watch_backend_name(); }

} // namespace bro::vfs
