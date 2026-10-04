#pragma once

#include "brovfs/types.h"

#include <functional>
#include <memory>
#include <vector>

namespace bro::vfs {

// ---------------------------------------------------------------- conflicts

enum class ConflictKind : uint8_t {
    Exists = 0,    // destination exists, same kind of object (file over file, link over file, ...)
    TypeMismatch,  // directory vs non-directory
    SameFile,      // destination is the source itself (same path, other case, hard link)
};

struct Conflict {
    ConflictKind kind = ConflictKind::Exists;
    fs::path source;
    fs::path destination;
    FileKind source_kind = FileKind::Unknown;
    FileKind destination_kind = FileKind::Unknown;
    uint64_t source_size = 0;
    uint64_t destination_size = 0;
    int64_t source_mtime_ms = 0;
    int64_t destination_mtime_ms = 0;
};

enum class ConflictAction : uint8_t {
    Overwrite = 0, // replace atomically; refused (error) for SameFile and TypeMismatch
    Skip,
    KeepBoth,      // write under a free "name (2).ext" next to the destination
    Abort,         // stop the whole operation (outcome Cancelled)
};

// Called on the thread running the operation, before any data is written for that item.
using ConflictResolver = std::function<ConflictAction(const Conflict&)>;

enum class ConflictPolicy : uint8_t {
    Ask = 0,    // call FileOpOptions::on_conflict; with no resolver the item fails with conflict_unresolved
    Overwrite,
    Skip,
    KeepBoth,
    KeepNewer,  // overwrite only if the source is strictly newer, otherwise skip
};

struct FileOpOptions {
    ConflictPolicy conflict = ConflictPolicy::Ask;
    ConflictResolver on_conflict;
    bool preserve_metadata = true;  // mode / timestamps / xattrs (POSIX), attributes / times / streams (Windows)
    bool sync = false;              // flush every file before commit (always done before a move deletes its source)
    bool allow_reflink = true;      // try FICLONE first on Linux
    bool allow_kernel_copy = true;  // copy_file_range on Linux; CopyFile2 on Windows is always used
    size_t buffer_size = 1u << 20;
};

// Return false to cancel.
using ProgressCallback = std::function<bool(const ProgressInfo&)>;

// ---------------------------------------------------------------- operations
//
// Semantics shared by every operation:
//  * Links are links: symlinks and junctions are copied/moved as links and never followed;
//    remove() deletes the link, never the target. FIFOs are recreated; sockets and device
//    nodes are reported as unsupported_file_type and left in place.
//  * Files are written to a temporary name in the destination directory and committed with a
//    rename (no-replace unless the conflict decision was Overwrite). An existing destination
//    is never truncated: a cancelled or failed overwrite leaves it untouched.
//  * Same-object detection uses file identity (device+inode / volume+file id).
//  * A move renames when it can; only a cross-device error falls back to copy + delete, and
//    each source item is deleted only after its copy is committed, flushed and the source is
//    verified unchanged since planning. Any other rename error is reported, nothing deleted.
//  * A partial result is an error: OpResult::errors lists each failed item.

// Copy each source into dest_dir (dest_dir / source.filename()).
OpResult copy_into(const std::vector<fs::path>& sources, const fs::path& dest_dir,
                   const FileOpOptions& options = FileOpOptions(), ProgressCallback on_progress = nullptr,
                   std::shared_ptr<CancellationToken> token = nullptr);
// Copy src to exactly dst.
OpResult copy_to(const fs::path& src, const fs::path& dst,
                 const FileOpOptions& options = FileOpOptions(), ProgressCallback on_progress = nullptr,
                 std::shared_ptr<CancellationToken> token = nullptr);

OpResult move_into(const std::vector<fs::path>& sources, const fs::path& dest_dir,
                   const FileOpOptions& options = FileOpOptions(), ProgressCallback on_progress = nullptr,
                   std::shared_ptr<CancellationToken> token = nullptr);
OpResult move_to(const fs::path& src, const fs::path& dst,
                 const FileOpOptions& options = FileOpOptions(), ProgressCallback on_progress = nullptr,
                 std::shared_ptr<CancellationToken> token = nullptr);

// Permanently delete. Plans first (no-follow scan), then deletes bottom-up, re-checking each
// object's identity against the plan so a directory swapped for a link is not descended.
OpResult remove(const std::vector<fs::path>& paths, ProgressCallback on_progress = nullptr,
                std::shared_ptr<CancellationToken> token = nullptr);

// A free "name (N).ext" next to `path` (returns `path` itself if it does not exist).
[[nodiscard]] fs::path unique_sibling_name(const fs::path& path);

// ---------------------------------------------------------------- single-file clone

enum class CopyMethod : uint8_t {
    None = 0,
    Reflink,     // copy-on-write clone (FICLONE): no data was copied
    KernelCopy,  // copy_file_range (Linux) or CopyFile2 (Windows; may block-clone on ReFS, not observable)
    Stream,      // read/write loop
};
[[nodiscard]] std::string_view to_string(CopyMethod m) noexcept;

struct CloneResult {
    std::error_code error;
    CopyMethod method = CopyMethod::None;
    [[nodiscard]] bool ok() const noexcept { return !error; }
};

// Copy one regular file to a destination that must not exist, via temp + no-replace rename.
// With allow_fallback=false only a real CoW clone counts; anything else fails with
// std::errc::operation_not_supported and leaves no destination.
CloneResult clone_file(const fs::path& src, const fs::path& dst, bool allow_fallback = true);

// Whether `path`'s file system can CoW-clone (Linux: probes FICLONE in a temp file next to
// `path`, which must be a writable directory; Windows: FILE_SUPPORTS_BLOCK_REFCOUNTING).
[[nodiscard]] bool reflink_supported(const fs::path& directory);

} // namespace bro::vfs
