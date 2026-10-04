#pragma once
// Private platform layer. Every function here observes and acts on the named object itself and
// never follows a link in the final path component. Errors are OS error codes in
// std::system_category() (POSIX errno / Win32 GetLastError) unless noted.

#include "brovfs/file_ops.h"
#include "brovfs/types.h"

#include <functional>
#include <string>
#include <vector>

namespace bro::vfs::sys {

struct Stat {
    FileKind kind = FileKind::Unknown;
    uint64_t size = 0;
    int64_t mtime_ns = 0;
    int64_t atime_ns = 0;
    int64_t btime_ns = 0;   // 0 when unknown
    uint32_t mode = 0;      // POSIX st_mode
    uint32_t uid = 0, gid = 0;
    uint32_t attributes = 0; // Windows FILE_ATTRIBUTE_*
    uint32_t reparse_tag = 0;
    uint64_t nlink = 0;
    FileId id;
    bool link_is_dir = false; // Windows: the link object is a directory (dir symlink / junction)
};

bool lstat(const fs::path& p, Stat& out, std::error_code& ec);
// Follows links: used only to identify the directory a path finally reaches (e.g. "is the
// destination inside the source?").
bool stat_follow(const fs::path& p, Stat& out, std::error_code& ec);
bool exists_nofollow(const fs::path& p); // lstat succeeds

struct RawEntry {
    fs::path name;          // single component, native encoding
    std::string name_utf8;  // UTF-8/WTF-8 (Windows) or raw bytes (POSIX)
    Stat st;
    std::error_code stat_error; // entry listed but could not be stat'ed
};

// Enumerate the children of `dir` ("." and ".." excluded). Opening `dir` does not follow a
// link: a symlink/junction at `dir` fails (ELOOP / ENOTDIR / ERROR_DIRECTORY-ish). Return false
// from the callback to stop. Returns false with ec set if the directory could not be read
// (entries already delivered stay valid).
bool list_dir(const fs::path& dir, const std::function<bool(RawEntry&&)>& cb, std::error_code& ec);

bool read_link_target(const fs::path& link, std::string& target_utf8, std::error_code& ec);

// Fails with EEXIST / ERROR_ALREADY_EXISTS (mapped to std::errc::file_exists) if `to` exists.
bool rename_noreplace(const fs::path& from, const fs::path& to, std::error_code& ec);
// Atomically replaces a non-directory `to`.
bool rename_replace(const fs::path& from, const fs::path& to, std::error_code& ec);
bool is_cross_device(const std::error_code& ec);
// Windows: the two paths differ only by letter case (callers check they are the same object).
bool is_case_variant(const fs::path& a, const fs::path& b);
bool is_exists_error(const std::error_code& ec);
bool is_not_found(const std::error_code& ec);

// mkdir; the new directory is private (0700) on POSIX until apply_metadata.
bool make_dir(const fs::path& p, std::error_code& ec);
bool make_dir_default(const fs::path& p, std::error_code& ec); // 0777 & ~umask
bool make_dirs(const fs::path& p, std::error_code& ec); // like mkdir -p, follows existing links
// Remove an empty real directory (fails on non-empty). Never follows.
// With `expect`, fails with Errc::source_changed if the object's identity differs (checked on
// the open handle on Windows, by lstat just before on POSIX).
bool remove_dir(const fs::path& p, std::error_code& ec, const FileId* expect = nullptr);
// Remove a file, symlink, junction, fifo... the object itself, never a link target.
// Clears the Windows read-only attribute if needed.
bool remove_nondir(const fs::path& p, std::error_code& ec, const FileId* expect = nullptr);

// Recreate the link `src` (symlink or junction) at `dst`, which must not exist.
bool copy_link(const fs::path& src, const Stat& src_st, const fs::path& dst, std::error_code& ec);
// Recreate a FIFO; other special files fail with unsupported_file_type.
bool copy_special(const Stat& src_st, const fs::path& dst, std::error_code& ec);

struct DataCopyHooks {
    // Bytes copied since last call; return false to cancel (copy fails with Errc::cancelled).
    std::function<bool(uint64_t delta)> on_chunk;
    bool allow_reflink = true;
    bool require_reflink = false; // fail with operation_not_supported unless a CoW clone happened
    bool allow_kernel_copy = true;
    bool sync = false;
    bool preserve_metadata = true;
    size_t buffer_size = 1u << 20;
    std::vector<ItemError>* warnings = nullptr; // metadata failures
};

// Copy a regular file's content (and, if requested, metadata) into `dst`, which must not
// exist and is created exclusively. On failure `dst` is removed. Verifies the byte count
// against what was read; a read error is an error, never a short success.
CopyMethod copy_file_data(const fs::path& src, const Stat& src_st, const fs::path& dst,
                          const DataCopyHooks& hooks, uint64_t& bytes_copied, std::error_code& ec);

// Times / mode / attributes of a directory or link after its contents are in place.
void apply_metadata(const fs::path& dst, const Stat& src_st, std::vector<ItemError>* warnings);

// Make a completed rename durable (POSIX: fsync the directory; Windows: no-op, handled by
// MOVEFILE_WRITE_THROUGH / FlushFileBuffers).
void sync_dir(const fs::path& dir);

bool reflink_supported(const fs::path& dir);

// A unique temp name for staging `final_name` inside `dir`.
fs::path temp_sibling(const fs::path& dir);

int64_t now_unix_ms();

// Test hook: when set, a *move's* rename attempt fails with the platform's cross-device error
// so the copy + verified-delete path can be exercised on a single file system. (Staging
// commits, trash and restore renames are unaffected.)
extern std::atomic<bool> g_force_cross_device;
std::error_code cross_device_error();

} // namespace bro::vfs::sys
