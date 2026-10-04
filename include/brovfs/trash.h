#pragma once

#include "brovfs/types.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace bro::vfs {

struct TrashItem {
    std::string id;          // opaque, pass back to restore()/erase()
    fs::path original_path;
    fs::path stored_path;    // where the item lives inside the trash
    std::string name;        // display name (leaf of original_path), UTF-8 / raw bytes
    int64_t deletion_time_ms = 0;
    uint64_t size = 0;       // directories: total size when the backend records it, else 0
    bool is_directory = false;
};

enum class RestoreConflict : uint8_t {
    Fail = 0,   // restore_target_exists if something now occupies the original path
    KeepBoth,   // restore under a free "name (N).ext" next to the original path
};

// A trash never deletes permanently on your behalf: if a path cannot be moved to the trash
// (no trash on that volume, network path, ...) trash() fails with no_trash_available and the
// file is untouched, so the caller can offer a permanent delete explicitly.
class Trash {
public:
    virtual ~Trash() = default;

    virtual bool trash(const fs::path& path, std::string* out_id, std::error_code& ec) = 0;
    // Items that could not be read are reported in `errors` (optional).
    [[nodiscard]] virtual std::vector<TrashItem> list(std::vector<ItemError>* errors = nullptr) = 0;
    virtual bool restore(const std::string& id, RestoreConflict on_conflict, fs::path* restored_to,
                         std::error_code& ec) = 0;
    virtual bool erase(const std::string& id, std::error_code& ec) = 0;
    // Erases every item this backend lists. Never called by the test suite on a real trash.
    virtual OpResult empty() = 0;
};

// The platform trash: Windows Recycle Bin, or the freedesktop.org trash elsewhere.
[[nodiscard]] std::shared_ptr<Trash> system_trash();

// Trash several paths; result.trash_ids is parallel to `paths`.
OpResult trash_paths(Trash& trash, const std::vector<fs::path>& paths,
                     const std::function<bool(const ProgressInfo&)>& on_progress = nullptr,
                     std::shared_ptr<CancellationToken> token = nullptr);

#ifndef _WIN32
// freedesktop.org Trash specification 1.0: home trash plus per-mount $topdir/.Trash/$uid and
// $topdir/.Trash-$uid, exclusive .trashinfo creation, local-time DeletionDate, directorysizes.
struct FreedesktopTrashConfig {
    fs::path home_trash;               // empty = $XDG_DATA_HOME/Trash or ~/.local/share/Trash
    // Maps a path to the top directory of its mount; empty = derived from st_dev / mount table.
    std::function<fs::path(const fs::path&)> topdir_of;
    // Extra top directories to search in list() (the mount table is always searched).
    std::vector<fs::path> extra_topdirs;
    bool search_mounts = true;
    // If no trash exists on the file's device, move (copy + verified delete) into the home trash.
    bool allow_home_trash_across_devices = false;
};

std::shared_ptr<Trash> make_freedesktop_trash(FreedesktopTrashConfig config = FreedesktopTrashConfig());
#endif

#ifdef _WIN32
// The shell Recycle Bin. trash() goes through IFileOperation (on a private STA thread) and
// refuses any item the shell would delete permanently. list/restore/erase work directly on
// <volume>\$Recycle.Bin\<user SID>\$I / $R records of local volumes.
std::shared_ptr<Trash> make_recycle_bin();
#endif

} // namespace bro::vfs
