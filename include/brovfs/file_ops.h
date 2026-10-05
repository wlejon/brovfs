#pragma once

#include "brovfs/types.h"

#include <chrono>
#include <functional>
#include <memory>
#include <string_view>
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
    // Timestamps (access, modification; birth time where the OS lets it be set: Windows,
    // macOS — Linux has no API for it), POSIX mode, Windows attributes. When false, nothing
    // below applies either and copies get fresh times and umask permissions.
    bool preserve_metadata = true;
    // Extended attributes of files and directories: Linux user.* (trusted.* / security.* are
    // the source's policy and never copied), macOS all (via copyfile, so resource forks and
    // compressed files are handled). Windows: alternate data streams of directories; a file's
    // streams and EAs always travel with it (CopyFile2).
    bool preserve_xattrs = true;
    // Access policy travels only when asked: POSIX ACLs (system.posix_acl_access / _default),
    // macOS extended ACLs, the Windows DACL (protected DACLs as-is; otherwise the explicit
    // ACEs, and inheritance from the destination's parent).
    bool preserve_acls = false;
    // Ownership where the process may set it: as root, uid and gid; otherwise the group if the
    // caller belongs to it. Windows (with preserve_acls): owner and group if permitted.
    // Anything not permitted is skipped silently.
    bool preserve_owner = true;
    // Files that are hard links of each other within one operation's sources are linked to
    // each other in the copy too, instead of becoming independent copies.
    bool preserve_hard_links = true;
    bool sync = false;              // flush every file before commit (always done before a move deletes its source)
    bool allow_reflink = true;      // try a CoW clone first: FICLONE on Linux, clonefile on macOS
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

// ---------------------------------------------------------------- crash leftovers
//
// Every write is staged as ".brovfs-<16 hex digits>.tmp" in the destination directory and
// renamed into place. A crash or power loss between the two leaves the staging file behind
// (never a half-written destination). These recognise and remove such leftovers.

// True for a name brovfs stages under (exactly ".brovfs-" + 16 lowercase hex + ".tmp").
[[nodiscard]] bool is_staging_name(std::string_view leaf) noexcept;

struct StagingLeftover {
    fs::path path;
    FileKind kind = FileKind::Unknown; // a regular file; a link / FIFO staged by a copy; see below
    uint64_t size = 0;
    int64_t changed_ms = 0;            // last status change (ctime / NTFS ChangeTime), Unix ms
    FileId id;
};

// Leftovers in `dir` (and below it when `recursive`; links are never followed). A directory is
// a leftover only when empty (a junction interrupted between its mkdir and its reparse data);
// brovfs never stages directory contents. Anything whose status changed less than
// `min_age` ago may belong to an operation still running (a copy in progress keeps touching
// it) and is not listed.
[[nodiscard]] std::vector<StagingLeftover> find_staging_leftovers(
    const fs::path& dir, bool recursive, std::chrono::seconds min_age, std::vector<ItemError>* errors = nullptr);

// Deletes every leftover find_staging_leftovers lists, each re-checked by identity first.
OpResult clean_staging_leftovers(const fs::path& dir, bool recursive = false,
                                 std::chrono::seconds min_age = std::chrono::seconds(600));

// ---------------------------------------------------------------- single-file clone

enum class CopyMethod : uint8_t {
    None = 0,
    Reflink,     // copy-on-write clone (FICLONE / clonefile): no data was copied
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

// Whether `path`'s file system can CoW-clone (Linux / macOS: probes FICLONE / fclonefileat in a
// temp file next to `path`, which must be a writable directory; Windows:
// FILE_SUPPORTS_BLOCK_REFCOUNTING).
[[nodiscard]] bool reflink_supported(const fs::path& directory);

} // namespace bro::vfs
