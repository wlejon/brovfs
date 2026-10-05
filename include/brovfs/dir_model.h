#pragma once
// DirectoryModel: what a file view binds to. One directory's entries, kept live (scan +
// non-recursive watch), filtered and sorted, with stable item keys and incremental diffs.
//
// Threading: the model runs on its own thread. The host reads `snapshot()` once and then
// applies the ModelUpdates it drains from `queue()` on its own thread, in order; each update
// carries the generation it produces, so a host that took a snapshot skips updates up to the
// snapshot's generation. Setters (sort, filter, refresh) are asynchronous: their effect
// arrives as an update.
//
// Consistency: the model applies watcher events by stat'ing the named entries and rescans
// the directory on Rescan, so once the file system is quiet the model equals a fresh scan.
//
// Identity: an item's key stays the same while its name exists (metadata changes, and an
// atomic save that replaces the file under the same name) and across renames within the
// directory (matched by file identity: device + inode / file id), so selection and scroll
// anchors survive. A name that disappears and an unrelated object that appears under another
// name get different keys.

#include "brovfs/event_queue.h"
#include "brovfs/scanner.h"

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace bro::vfs {

using ItemKey = uint64_t;

struct ModelItem {
    ItemKey key = 0;
    FileEntry entry; // entry.depth is 0; entry.path = directory / name
};

enum class SortField : uint8_t {
    Name = 0, // natural order (collate.h)
    Size,     // a directory sorts as size 0 (its own size means nothing), so by name among dirs
    Modified,
    Type,     // extension (natural order, case-insensitive), then name
    Kind,     // FileKind, then name
};

struct SortSpec {
    SortField field = SortField::Name;
    bool descending = false;
    bool directories_first = true; // directories (and links to directories) before the rest,
                                   // regardless of `descending`
};

// Return true to show an entry.
using EntryFilter = std::function<bool(const FileEntry&)>;

struct ModelOptions {
    SortSpec sort;
    bool show_hidden = false;
    EntryFilter filter;            // applied after the hidden rule; called on the model thread
    bool watch = true;             // false: a one-shot listing (refresh() re-reads)
    std::chrono::milliseconds latency{100}; // watcher coalescing window
    size_t batch_size = 512;       // entries per update while loading
};

enum class ModelState : uint8_t {
    Loading = 0, // the initial (or a refresh) scan is streaming in
    Ready,       // live
    Gone,        // the directory was removed / moved / unmounted: no items, no further changes
    Failed,      // the directory could not be opened: `error` says why
};

[[nodiscard]] std::string_view to_string(ModelState s) noexcept;

// One change to the visible list. Apply the ops of an update in order:
//   Remove   `index` is in the list as it is at that moment (removals come first, highest
//            index first, so each index is still valid)
//   Insert   `index` is the position in the list after the insertion (ascending order)
//   Update   the item at `index` (final list) changed in place; its key is unchanged
// A key removed and inserted in one update has moved (re-sorted or renamed).
struct ModelOp {
    enum Kind : uint8_t { Remove = 0, Insert, Update } kind = Remove;
    size_t index = 0;
    ModelItem item; // Remove: key and the entry as it was
};

struct ModelUpdate {
    uint64_t generation = 0;   // the generation this update produces (previous + 1)
    ModelState state = ModelState::Loading;
    bool reset = false;        // replace the whole list with `items` (sort change, refresh, Gone)
    std::vector<ModelItem> items; // reset only
    std::vector<ModelOp> ops;
    std::vector<ScanError> errors; // entries / directories that could not be read
    std::error_code error;         // Failed / Gone reason, or a watch that could not be set
};

struct ModelSnapshot {
    uint64_t generation = 0;
    ModelState state = ModelState::Loading;
    std::vector<ModelItem> items; // visible, in order
    std::error_code error;
};

using ModelQueue = MessageQueue<ModelUpdate>;

class DirectoryModel {
public:
    // Starts loading `directory` (a link to a directory is followed: the user navigated into
    // it). Updates go to `queue`, or a queue the model owns when null.
    explicit DirectoryModel(fs::path directory, ModelOptions options = ModelOptions(),
                            std::shared_ptr<ModelQueue> queue = nullptr);
    ~DirectoryModel();
    DirectoryModel(const DirectoryModel&) = delete;
    DirectoryModel& operator=(const DirectoryModel&) = delete;

    [[nodiscard]] const fs::path& directory() const noexcept;
    [[nodiscard]] const std::shared_ptr<ModelQueue>& queue() const noexcept { return queue_; }

    [[nodiscard]] ModelSnapshot snapshot() const;
    // Any entry the model holds, visible or not (filtered / hidden), by key.
    [[nodiscard]] std::optional<ModelItem> find(ItemKey key) const;

    void set_sort(SortSpec sort);                     // a reset update in the new order
    void set_filter(EntryFilter filter, bool show_hidden); // removals / insertions only
    void refresh();                                   // rescan; differences arrive as ops

    // Blocks until nothing has changed for a quiet period (the watch latency + 150 ms) that
    // began no earlier than this call, with every reported change applied and its update
    // pushed (for tests and "wait for idle" UIs). False on timeout.
    bool settle(std::chrono::milliseconds timeout);

    struct Impl;

private:
    std::shared_ptr<ModelQueue> queue_;
    std::unique_ptr<Impl> impl_;
};

// Applies one update to a host-side list (what a view does), for hosts and tests.
void apply_update(std::vector<ModelItem>& list, const ModelUpdate& update);

} // namespace bro::vfs
