#pragma once
// Size / count of a selection, computed in the background ("Properties" of 3 folders, the
// status bar's "12 items, 4.1 GB"), with live totals and cancellation.

#include "brovfs/scanner.h"

#include <chrono>
#include <functional>
#include <memory>
#include <vector>

namespace bro::vfs {

struct SelectionTotals {
    uint64_t files = 0;        // regular files (hard links of one file counted once)
    uint64_t directories = 0;  // including selected directories themselves
    uint64_t links = 0;        // symlinks / junctions (never followed)
    uint64_t others = 0;       // fifos, sockets, devices
    uint64_t bytes = 0;        // logical size of the regular files counted
    uint64_t errors = 0;       // entries or directories that could not be read
    bool finished = false;     // every path fully walked (errors still possible)
    bool cancelled = false;
    [[nodiscard]] uint64_t items() const noexcept { return files + directories + links + others; }
};

struct AggregateOptions {
    // A file reachable by several names counts once. Needs the link count from the listing:
    // POSIX has it; Windows directory listings do not report it, so there each name counts.
    bool count_hard_links_once = true;
    bool include_hidden = true;
    std::chrono::milliseconds progress_interval{100}; // how often on_progress may be called
};

// Called on the aggregation's thread with the totals so far; the last call has finished or
// cancelled set.
using AggregateProgress = std::function<void(const SelectionTotals&)>;

class SelectionAggregate {
public:
    virtual ~SelectionAggregate() = default; // cancels and joins
    virtual void cancel() = 0;
    [[nodiscard]] virtual SelectionTotals totals() const = 0; // live, any thread
    virtual SelectionTotals wait() = 0;                       // blocks until finished / cancelled
    [[nodiscard]] virtual std::vector<ScanError> errors() const = 0; // first 100
};

[[nodiscard]] std::unique_ptr<SelectionAggregate> aggregate_selection(std::vector<fs::path> paths,
                                                                     AggregateProgress on_progress = nullptr,
                                                                     AggregateOptions options = AggregateOptions());

} // namespace bro::vfs
