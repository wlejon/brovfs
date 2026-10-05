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
    int64_t ctime_ns = 0;   // status change time (POSIX ctime / NTFS ChangeTime); 0 when unknown
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

// An open directory, for traversal and removal relative to a handle instead of a path: once a
// directory is open, swapping one of its ancestors (for a link, or a different tree) cannot
// redirect what is listed, opened or deleted beneath it.
//   POSIX: an O_DIRECTORY fd; children via openat / fstatat / unlinkat with AT_SYMLINK_NOFOLLOW.
//   Windows: a directory HANDLE; children via NtCreateFile relative to it with
//   FILE_OPEN_REPARSE_POINT, and identity checked on the child's own handle before deleting.
class Dir {
public:
    Dir() = default;
    ~Dir();
    Dir(Dir&& o) noexcept;
    Dir& operator=(Dir&& o) noexcept;
    Dir(const Dir&) = delete;
    Dir& operator=(const Dir&) = delete;

    [[nodiscard]] bool ok() const noexcept;
    void close() noexcept;

    // Opens the directory `p`. With follow_leaf=false a link at `p` itself is refused (ELOOP /
    // not_a_directory); links in earlier components are followed as the caller spelled them.
    static bool open(const fs::path& p, bool follow_leaf, Dir& out, std::error_code& ec);
    // Opens child directory `name` (one component) without following a link. With `expect`,
    // fails with Errc::source_changed unless the opened directory has that identity.
    bool open_child(const fs::path& name, const FileId* expect, Dir& out, std::error_code& ec) const;
    bool stat(Stat& out, std::error_code& ec) const;
    bool stat_child(const fs::path& name, Stat& out, std::error_code& ec) const;
    // Lists from the start; see list_dir.
    bool list(const std::function<bool(RawEntry&&)>& cb, std::error_code& ec) const;
    // Deletes child `name`: an empty directory when `is_dir`, else a non-directory (a link is
    // deleted as a link). With `expect` the object must have that identity (Windows: checked on
    // the handle that deletes it; POSIX: fstatat immediately before unlinkat in this directory).
    bool remove_child(const fs::path& name, bool is_dir, const FileId* expect, std::error_code& ec) const;

private:
#ifdef _WIN32
    void* h_ = nullptr;
#else
    int fd_ = -1;
#endif
};

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

// Which metadata travels with a copy (see FileOpOptions).
struct MetaOptions {
    bool enabled = true; // times, mode, attributes; false = none of this struct
    bool xattrs = true;
    bool acls = false;
    bool owner = true;
};

struct DataCopyHooks {
    // Bytes copied since last call; return false to cancel (copy fails with Errc::cancelled).
    std::function<bool(uint64_t delta)> on_chunk;
    bool allow_reflink = true;
    bool require_reflink = false; // fail with operation_not_supported unless a CoW clone happened
    bool allow_kernel_copy = true;
    bool sync = false;
    MetaOptions meta;
    size_t buffer_size = 1u << 20;
    std::vector<ItemError>* warnings = nullptr; // metadata failures
};

// Copy a regular file's content (and, if requested, metadata) into `dst`, which must not
// exist and is created exclusively. On failure `dst` is removed. Verifies the byte count
// against what was read; a read error is an error, never a short success.
CopyMethod copy_file_data(const fs::path& src, const Stat& src_st, const fs::path& dst,
                          const DataCopyHooks& hooks, uint64_t& bytes_copied, std::error_code& ec);

// Metadata of a directory, link or special file after its contents are in place: times,
// mode/attributes, and per `meta` xattrs (Windows: alternate data streams of a directory),
// ACLs / security descriptor and ownership. `src` is read for xattrs / ACLs.
void apply_metadata(const fs::path& src, const fs::path& dst, const Stat& src_st, const MetaOptions& meta,
                    std::vector<ItemError>* warnings);

// macOS ACL entries can deny `delete`, which also forbids renaming the object, so the ACL of
// a staged non-directory is applied after its commit rename: stage with staged_meta(), then
// call apply_acl_committed on the final name. Elsewhere the ACL is part of staging.
#ifdef __APPLE__
inline MetaOptions staged_meta(MetaOptions m) {
    m.acls = false;
    return m;
}
void apply_acl_committed(const fs::path& src, const fs::path& dst, const Stat& src_st, const MetaOptions& meta,
                         std::vector<ItemError>* warnings);
#else
inline MetaOptions staged_meta(MetaOptions m) { return m; }
inline void apply_acl_committed(const fs::path&, const fs::path&, const Stat&, const MetaOptions&,
                                std::vector<ItemError>*) {}
#endif

// A new hard link `link` to the existing non-directory `target` (no-follow on both).
bool make_hard_link(const fs::path& target, const fs::path& link, std::error_code& ec);

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
