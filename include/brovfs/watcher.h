#pragma once
// Directory watching: value events pushed into a queue the host drains on its own thread.
//
// Backends: ReadDirectoryChangesExW (Windows), inotify (Linux; recursive by adding a watch per
// directory as directories appear), FSEvents (macOS).
//
// Contract (what a consumer can rely on to keep a live view consistent):
//  * Events are hints that name what changed, never a replay of state. A consumer stats the
//    named path when it applies an event and trusts the file system over the event.
//  * Every change under a watched root is followed, in order, by an event naming the changed
//    path, or by a Rescan naming one of its ancestors (or the root). Nothing is dropped
//    silently: kernel queue overflow, a lost buffer, a watch that could not be added
//    (inotify watch limit) or coalescing beyond what the backend can attribute becomes a
//    Rescan (or an Error naming the unwatched directory).
//  * Created for a directory means "this subtree is new": its contents may not be reported
//    one by one (a tree moved in from outside, a burst of mkdir -p). List it recursively.
//  * Removed for a directory covers its whole subtree.
//  * Renamed is reported when both names are inside the same watch; a rename out of the watch
//    is Removed, into it is Created.
//  * Created may repeat for a path that already exists, and Removed may name a path that was
//    never reported; both are harmless to a consumer that stats.
//  * RootRemoved: the root was deleted, renamed or unmounted. The watch is dead (no further
//    events) and should be removed and re-added by the host if it wants to continue.
//  * After add() returns, every later change is reported. After remove() returns, no further
//    event for that watch is pushed.
//
// Coalescing: events are held for up to `latency` and merged per path (Modified repeats
// collapse; Created then Modified is Created; Created then Removed of the same path cancels).
// Merging never crosses a Rename and never reorders events of one watch.

#include "brovfs/event_queue.h"
#include "brovfs/types.h"

#include <chrono>
#include <memory>
#include <string_view>

namespace bro::vfs {

using WatchId = uint64_t;

enum class WatchEventKind : uint8_t {
    Created = 0,
    Removed,
    Modified,     // content, size, times, attributes, permissions
    Renamed,      // old_path -> path, both inside the watched tree
    Rescan,       // events under `path` (a directory) were lost: rescan it recursively
    RootRemoved,  // the watched root is gone (deleted, moved, unmounted); the watch is dead
    Error,        // `path` could not be watched (e.g. inotify watch limit): `error` says why
};

[[nodiscard]] std::string_view to_string(WatchEventKind kind) noexcept;

struct WatchEvent {
    WatchEventKind kind = WatchEventKind::Modified;
    WatchId watch = 0;
    fs::path path;       // root / relative, in the spelling the root was added with
    fs::path old_path;   // Renamed only
    FileKind file_kind = FileKind::Unknown; // best effort; Unknown when the backend cannot tell
    std::error_code error;                  // Error (and the reason for some Rescans)
};

using WatchEventQueue = MessageQueue<WatchEvent>;

struct WatchOptions {
    bool recursive = true;
    // Coalescing window: an event is delivered at most this long after it was observed.
    // Zero delivers each event as soon as the backend has paired it (renames).
    std::chrono::milliseconds latency{50};
};

class DirectoryWatcher {
public:
    // Events go to `queue`, or to a queue the watcher owns when null.
    explicit DirectoryWatcher(std::shared_ptr<WatchEventQueue> queue = nullptr);
    ~DirectoryWatcher(); // removes every watch, stops the backend thread
    DirectoryWatcher(const DirectoryWatcher&) = delete;
    DirectoryWatcher& operator=(const DirectoryWatcher&) = delete;

    // Watches an existing directory (a link to a directory is resolved once, here). Returns 0
    // with `ec` set on failure. Watches are independent: overlapping roots each get events.
    WatchId add(const fs::path& root, const WatchOptions& options, std::error_code& ec);
    bool remove(WatchId id);

    [[nodiscard]] const std::shared_ptr<WatchEventQueue>& queue() const noexcept { return queue_; }

    // "ReadDirectoryChangesW", "inotify", "FSEvents".
    [[nodiscard]] static std::string_view backend_name() noexcept;

    struct Impl;

private:
    std::shared_ptr<WatchEventQueue> queue_;
    std::unique_ptr<Impl> impl_;
};

} // namespace bro::vfs
