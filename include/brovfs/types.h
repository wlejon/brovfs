#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace bro::vfs {

namespace fs = std::filesystem;

// What a directory entry *is*, observed without following links.
enum class FileKind : uint8_t {
    Unknown = 0,
    Regular,
    Directory,
    Symlink,     // POSIX symlink, or a Windows IO_REPARSE_TAG_SYMLINK (file or directory)
    Junction,    // Windows mount point (IO_REPARSE_TAG_MOUNT_POINT): a link, never traversed
    Fifo,
    Socket,
    CharDevice,
    BlockDevice,
};

[[nodiscard]] std::string_view to_string(FileKind kind) noexcept;
[[nodiscard]] constexpr bool is_link(FileKind k) noexcept { return k == FileKind::Symlink || k == FileKind::Junction; }

// Identity of a file system object: (device or volume serial, inode or 128-bit file id).
// Two paths name the same object iff their ids are equal and valid. This is what same-file
// detection uses, never path text (case, hard links, junction aliases all defeat text).
struct FileId {
    uint64_t device = 0;
    uint64_t hi = 0;
    uint64_t lo = 0;
    bool valid = false;
    friend bool operator==(const FileId& a, const FileId& b) noexcept {
        return a.valid && b.valid && a.device == b.device && a.hi == b.hi && a.lo == b.lo;
    }
};

struct FileEntry {
    fs::path path;            // parent / name, in the caller's spelling
    std::string name;         // UTF-8 (WTF-8 for unpaired surrogates) on Windows, raw bytes on POSIX
    FileKind kind = FileKind::Unknown;
    bool is_hidden = false;
    bool link_is_directory = false; // Windows directory symlink / junction
    uint64_t size = 0;
    int64_t mtime_ms = 0;     // Unix epoch milliseconds
    int64_t birthtime_ms = 0; // 0 when unknown
    uint32_t mode = 0;        // POSIX st_mode (permission + type bits); 0 on Windows
    uint32_t attributes = 0;  // Windows FILE_ATTRIBUTE_*; 0 on POSIX
    uint64_t nlink = 0;
    uint32_t depth = 0;       // 0 = direct child of the scanned root
    FileId id;
    std::string link_target;  // symlink / junction target (UTF-8 on Windows, raw bytes on POSIX)

    [[nodiscard]] bool is_directory() const noexcept { return kind == FileKind::Directory; }
    [[nodiscard]] bool is_regular() const noexcept { return kind == FileKind::Regular; }
    [[nodiscard]] bool is_link() const noexcept { return vfs::is_link(kind); }
};

// ---------------------------------------------------------------- errors

// Logical errors that are not OS errors. OS errors are reported in std::system_category().
enum class Errc {
    ok = 0,
    same_file = 1,                // source and destination are the same object
    destination_inside_source,    // copying / moving a directory into itself
    conflict_unresolved,          // destination exists and no decision was available
    type_mismatch,                // e.g. overwrite a directory with a file
    source_changed,               // source changed between planning and deletion; source kept
    unsupported_file_type,        // sockets, device nodes
    incomplete_copy,              // byte count mismatch
    not_found,
    no_trash_available,           // the volume has no trash / recycle bin; nothing was deleted
    invalid_trash_id,
    trash_info_invalid,
    restore_target_exists,
    aborted,                      // a conflict resolver chose Abort
    cancelled,
    invalid_argument,
    directory_not_empty_after_move, // entries appeared in the source while it was being moved
};

[[nodiscard]] const std::error_category& vfs_category() noexcept;
[[nodiscard]] std::error_code make_error_code(Errc e) noexcept;

// One failed item. `source`/`destination` are empty when not applicable.
struct ItemError {
    fs::path source;
    fs::path destination;
    std::error_code code;
    std::string operation; // short verb: "open", "read", "rename", "rmdir", "scan", ...
    [[nodiscard]] std::string message() const;
};

enum class Outcome : uint8_t {
    Success = 0, // every item done (user-chosen skips do not count as failures)
    Partial,     // some items done, at least one error
    Failed,      // errors and nothing done
    Cancelled,   // cancelled or aborted; `errors` lists anything that failed before
};

[[nodiscard]] std::string_view to_string(Outcome o) noexcept;

struct OpResult {
    Outcome outcome = Outcome::Success;
    std::vector<ItemError> errors;     // per-item failures: the operation is NOT complete if non-empty
    std::vector<ItemError> warnings;   // metadata that could not be preserved; data is intact
    std::vector<fs::path> created;     // top-level destinations created (for undo)
    std::vector<std::string> trash_ids; // trash jobs: id per input, "" on failure
    uint64_t files_done = 0;   // regular files written / moved / deleted
    uint64_t dirs_done = 0;
    uint64_t links_done = 0;   // symlinks, junctions, fifos recreated
    uint64_t bytes_done = 0;
    uint64_t skipped = 0;      // skipped by a conflict decision
    uint64_t reflinked = 0;    // files cloned copy-on-write (FICLONE)
    uint64_t kernel_copied = 0; // files copied in-kernel / by the OS copy engine (copy_file_range, CopyFile2)
    uint64_t hard_linked = 0;  // files recreated as a hard link to an earlier file of the same set

    [[nodiscard]] bool ok() const noexcept { return outcome == Outcome::Success; }
};

// ---------------------------------------------------------------- progress / cancel

enum class Phase : uint8_t { Planning = 0, Copying, Moving, Deleting, Trashing, Finishing };

struct ProgressInfo {
    Phase phase = Phase::Planning;
    uint64_t bytes_processed = 0;
    uint64_t total_bytes = 0;
    uint64_t items_processed = 0;
    uint64_t total_items = 0;
    double speed_bytes_per_sec = 0.0;
    double eta_seconds = 0.0;
    fs::path current_path;

    [[nodiscard]] double fraction() const noexcept {
        if (total_bytes > 0) return static_cast<double>(bytes_processed) / static_cast<double>(total_bytes);
        if (total_items > 0) return static_cast<double>(items_processed) / static_cast<double>(total_items);
        return 0.0;
    }
};

class CancellationToken {
public:
    void cancel() noexcept { cancelled_.store(true, std::memory_order_release); }
    [[nodiscard]] bool is_cancelled() const noexcept { return cancelled_.load(std::memory_order_acquire); }
    void reset() noexcept { cancelled_.store(false, std::memory_order_release); }

private:
    std::atomic<bool> cancelled_{false};
};

enum class OpStatus : uint8_t { Pending = 0, Running, Paused, Completed, Cancelled, Failed };
[[nodiscard]] std::string_view to_string(OpStatus status) noexcept;

} // namespace bro::vfs

template <>
struct std::is_error_code_enum<bro::vfs::Errc> : std::true_type {};
