#pragma once
// Disk usage of a whole tree ("what is filling this drive"), measured in the background by a
// few threads while the caller reads partial results: the tree fills in as it is listed, and
// every directory's totals grow as its descendants are counted, so a viewer can show the
// biggest folders of C:\ seconds into a scan that takes minutes.
//
// The tree is kept compactly (a node per directory, a small record per file), so a drive of a
// few million files costs on the order of 50 bytes per file. Links are counted, never
// followed; sizes are logical (the bytes a file holds, not the clusters it occupies).

#include "brovfs/scanner.h"

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace bro::vfs {

struct UsageOptions {
    bool include_hidden = true;
    unsigned threads = 0; // listing threads; 0 = min(4, hardware threads)
};

struct UsageProgress {
    uint64_t files = 0;       // non-directories counted so far (links included)
    uint64_t directories = 0; // directories listed or queued, the root excluded
    uint64_t bytes = 0;       // logical size of the files counted
    uint64_t errors = 0;      // directories or entries that could not be read
    uint64_t version = 0;     // bumps whenever the tree changes; equal = nothing to redraw
    bool finished = false;    // every directory listed (errors still possible)
    bool cancelled = false;
    double elapsed_ms = 0;
};

// One child of a directory as the scan knows it so far. A directory's bytes / files /
// directories cover its whole subtree; `complete` says whether all of it has been listed.
struct UsageItem {
    std::string name;
    fs::path path;
    FileKind kind = FileKind::Unknown;
    uint64_t bytes = 0;
    uint64_t files = 0;       // directory: files in the subtree; file: 1
    uint64_t directories = 0; // directory: directories in the subtree (itself excluded)
    uint64_t children = 0;    // directory: direct children known so far
    int64_t mtime_ms = 0;
    bool hidden = false;
    bool complete = true;
    [[nodiscard]] bool is_directory() const noexcept { return kind == FileKind::Directory; }
};

enum class UsageSort : uint8_t { Bytes, Name };

class UsageScan {
public:
    virtual ~UsageScan() = default; // cancels and joins
    virtual void cancel() = 0;
    [[nodiscard]] virtual UsageProgress progress() const = 0; // any thread
    virtual UsageProgress wait() = 0;                         // until finished or cancelled
    [[nodiscard]] virtual fs::path root() const = 0;

    // The children of `dir` (the root, or a directory inside it), biggest first by default,
    // at most `limit` of them (0 = all). False when `dir` is not a directory the scan has
    // reached (yet).
    virtual bool children(const fs::path& dir, std::vector<UsageItem>& out, UsageSort sort = UsageSort::Bytes,
                          size_t limit = 0) const = 0;
    // The scan's record of `p` (the root included). False when the scan has not reached it.
    virtual bool entry(const fs::path& p, UsageItem& out) const = 0;
    // Forgets `p` (after it was deleted or trashed): its bytes and counts come off every
    // ancestor, and listing of anything beneath it stops. False when the scan has no `p`.
    virtual bool remove(const fs::path& p) = 0;
    [[nodiscard]] virtual std::vector<ScanError> errors() const = 0; // first 100
};

[[nodiscard]] std::unique_ptr<UsageScan> start_usage_scan(fs::path root, UsageOptions options = UsageOptions());

} // namespace bro::vfs
