#pragma once
// Internal pieces shared by the watch backends: the coalescing sink that sits between a
// backend thread and the host's queue, and the backend interface.

#include "brovfs/watcher.h"

#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace bro::vfs::detail {

// True if `p` is `dir` or lies below it (lexical, native spelling).
bool path_within(const fs::path& p, const fs::path& dir);

class EventSink {
public:
    explicit EventSink(std::shared_ptr<WatchEventQueue> out);
    ~EventSink();
    EventSink(const EventSink&) = delete;
    EventSink& operator=(const EventSink&) = delete;

    void open(WatchId id, std::chrono::milliseconds latency);
    // Pending events of `id` are discarded; later add() calls for it are ignored.
    void close(WatchId id);

    void add(WatchEvent ev);
    // Pending events under `dir` are subsumed by a Rescan of `dir`.
    void rescan(WatchId id, const fs::path& dir, std::error_code why = {});
    // Delivers whatever is pending for `id` now.
    void flush(WatchId id);

private:
    struct Batch {
        std::chrono::milliseconds latency{0};
        std::vector<std::optional<WatchEvent>> events;
        std::unordered_map<fs::path::string_type, size_t> last; // path -> index of its last mergeable event
        std::chrono::steady_clock::time_point deadline{};
        bool pending = false;
    };

    void add_locked(Batch& b, WatchEvent&& ev, std::vector<WatchEvent>& now);
    void take_locked(Batch& b, std::vector<WatchEvent>& out);
    void run();

    std::shared_ptr<WatchEventQueue> out_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::map<WatchId, Batch> batches_;
    bool stop_ = false;
    std::thread thread_;
};

class WatchBackend {
public:
    virtual ~WatchBackend() = default;
    // `root` is the caller's spelling with trailing separators removed; `real` is the same
    // directory with every link resolved (absolute). Events are reported as root / relative.
    virtual bool add(WatchId id, const fs::path& root, const fs::path& real, const WatchOptions& options,
                     std::error_code& ec) = 0;
    // Synchronous: once it returns the backend pushes nothing more for `id`.
    virtual void remove(WatchId id) = 0;
};

// Test hook: when non-zero, the backend thread sleeps this long before it reads each batch
// of kernel notifications, so tests can drive the kernel queue into overflow.
extern std::atomic<int> g_watch_stall_ms;
void stall_for_test();

std::unique_ptr<WatchBackend> make_watch_backend(EventSink& sink);
std::string_view watch_backend_name() noexcept;

} // namespace bro::vfs::detail
