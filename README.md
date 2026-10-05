# brovfs

[![CI](https://github.com/wlejon/brovfs/actions/workflows/ci.yml/badge.svg)](https://github.com/wlejon/brovfs/actions/workflows/ci.yml)

File-operations substrate for a desktop file manager: scanning, copy/move/remove, trash,
volumes and MIME sniffing. A standalone C++20 library with no dependencies beyond the OS
(no bro, no bronze, no Qt/GLib), Windows, Linux and macOS.

The first duty is never to lose data:

- Every operation is planned against a scanned, no-follow model of the source and checked
  by file identity (device + inode / volume serial + 128-bit file ID) before it acts.
- Files are written to a temp sibling (`.brovfs-<hex>.tmp`), synced, and committed with a
  no-replace rename (or replace, only when the caller chose Overwrite).
- A move renames when it can. Only a cross-device error falls back to copy, and a source is
  deleted only after its destination is committed and the source still matches the plan.
  Source directories are removed with `rmdir` only.
- Removal and traversal go through directory handles (`openat`/`fstatat`/`unlinkat` with
  no-follow on POSIX; `NtCreateFile` relative to the parent handle and delete-by-handle on
  Windows), each opened relative to its parent and identity-checked, so a parent swapped
  for a link mid-operation cannot redirect a delete.
- Metadata travels with a copy: times (and birth time where settable), mode, ownership
  where permitted, xattrs, POSIX / extended ACLs or security descriptors when asked
  (`preserve_acls`), Windows alternate data streams and attributes, and hard-link sets
  within one operation. Crash leftovers (`.brovfs-<16 hex>.tmp`) can be found and cleaned
  with `find_staging_leftovers` / `clean_staging_leftovers`.
- Links are copied, moved and removed as links; deleting a junction or symlink never
  touches its target.
- Conflicts are surfaced (`ConflictPolicy`, or a `ConflictResolver` callback with
  `Ask`); same-file and type-mismatch overwrites are refused.
- Results are per item: `OpResult` reports Success / Partial / Failed / Cancelled with
  every error and warning.

## Headers

- `brovfs/path.h`: UTF-8 (WTF-8 on Windows) path conversion, `\\?\` long paths.
- `brovfs/scanner.h`: sync, streamed and async directory scans with per-entry errors
  (getdents64 + statx on Linux; FileIdExtdDirectoryInfo on Windows).
- `brovfs/file_ops.h`: `copy_into/to`, `move_into/to`, `remove`, `clone_file`
  (FICLONE / APFS clonefile reflink, then copy_file_range, then streaming; the method used
  is reported), staging-leftover cleanup. On btrfs / XFS, copy_file_range shares extents
  just as FICLONE does, so `allow_reflink = false` probes for clone support and then
  streams: false guarantees a physical copy on Linux (verified with FIEMAP). Windows
  CopyFile2 may still block-clone on ReFS. Traversal keeps at most
  `detail::g_dir_handle_budget` (32) directory handles open however deep the tree; a
  dropped level is reopened by path and accepted only if its identity still matches.
  `OpResult::done` lists what each operation did, for `undo.h`.
- `brovfs/watcher.h`: `DirectoryWatcher`, recursive or not, value events (Created /
  Removed / Modified / Renamed / Rescan / RootRemoved / Error) coalesced into a
  `WatchEventQueue` the host drains on its own thread. ReadDirectoryChangesExW on Windows,
  inotify with dynamic subdirectory watches and cookie rename pairing on Linux, FSEvents on
  macOS. A lost kernel queue is a `Rescan` of the affected directory, never silence, so a
  consumer applying the events to its model (rescanning on `Rescan`) always reconciles.
  Windows 8.3 short names in events are reported as long names (a name that no longer
  resolves becomes a `Rescan`); on Linux a directory over the inotify watch limit is an
  `Error` event (ENOSPC) naming it, and the rest stays watched.
- `brovfs/dir_model.h`: `DirectoryModel`, one directory as a sorted, filtered list kept
  current by a scan plus a watcher: stable item keys (kept across renames), incremental
  Remove / Insert / Update ops by index, generations, snapshots, `settle()`.
- `brovfs/collate.h`: `natural_compare` / `NaturalLess` ("file2" before "file10",
  case-folded, total order).
- `brovfs/aggregate.h`: `aggregate_selection`, background size / count totals for a
  selection, with progress and cancellation.
- `brovfs/undo.h`: `UndoJournal` of copy / move / trash records made from
  `OpResult::done`; undo and redo check every step against identity (id, birth time,
  inode generation) and state first and refuse (`target_changed`, `not_reversible`,
  `restore_target_exists`) with nothing changed; save / load as text.
- `brovfs/event_queue.h`: the `MessageQueue<T>` the watcher delivers through.
- `brovfs/worker.h`: `FileOpsWorker` background job queue with progress, pause, resume
  and cancel.
- `brovfs/trash.h`: freedesktop.org trash per spec (home trash, `$topdir/.Trash/$uid`,
  `$topdir/.Trash-$uid`, directorysizes) and the Windows Recycle Bin (shell recycle that
  refuses rather than permanently deleting; listing, restore and erase from `$I` records),
  and the macOS Trash. On macOS, Finder's "Put Back" works only for items Finder itself
  trashed (its records live in the trash's `.DS_Store`). `MacTrashConfig::finder` trashes
  through Finder by Apple Event when the user has granted Automation consent, so Put Back
  works for those items. Otherwise NSFileManager is used and restore data goes in xattrs on
  the item. Items Finder trashed are listed and restored from its `.DS_Store` records,
  which needs Full Disk Access for `~/.Trash`. See the header.
- `brovfs/volumes.h`: mounted volumes, capacity, read-only state; `VolumeMonitor` for
  added / removed / changed volumes (WM_DEVICECHANGE, `/proc/self/mountinfo` POLLPRI,
  DiskArbitration, plus a backstop poll).
- `brovfs/mime.h`: the one place sibling libraries ask "what type is this file". Magic-byte
  sniffing (images, audio, video, documents, archives, fonts, glTF/glb, Netpbm, ...) and
  `MimeDatabase`: `system()` is the platform's own type database (shared-mime-info from
  the XDG data dirs on Linux, UTType on macOS, the registry via `AssocQueryString` on
  Windows) with the built-in table behind it for anything it does not know; `built_in()` is
  the deterministic table alone, which is also the test oracle. Name lookups (`globs2`
  weights, literal and wildcard globs, case-sensitive globs), aliases and `is_a`
  (subclasses, plus `text/*` is `text/plain`, `+xml`/`+json`/`+zip` suffixes, everything
  but `inode/*` is `application/octet-stream`). `type_for_file` / `type_for_data`
  reconcile content and name: a weak sniff lets the name decide, a name that agrees with
  (or refines) the content wins, otherwise the content does, and `FileType::basis` says
  which.
- `brovfs/vfs.h`: umbrella header.

## Building

There is nothing to fetch: brovfs needs CMake 3.24+, a C++20 compiler (MSVC, GCC or
Clang) and the OS. [broapps](https://github.com/wlejon/broapps) and
[brothumb](https://github.com/wlejon/brothumb) build on it, resolving it as a checkout
beside them (`../brovfs`) or as their `third_party/brovfs` submodule.

```bash
# Windows (Visual Studio generator)
cmake -B build -DBROVFS_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure

# Linux
cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DBROVFS_BUILD_TESTS=ON
cmake --build build-release && ctest --test-dir build-release --output-on-failure

# macOS (Foundation + CoreServices + DiskArbitration; one Objective-C++ file for the trash)
cmake -B build-release -DCMAKE_BUILD_TYPE=Release -DBROVFS_BUILD_TESTS=ON
cmake --build build-release && ctest --test-dir build-release --output-on-failure
```

The tests use the real file system, only inside scratch directories they create
(`BROVFS_TEST_SCRATCH`, default `./brovfs-scratch`). Cross-device cases use
`BROVFS_TEST_SCRATCH2` (default: `%TEMP%` on Windows, `/dev/shm` on Linux, when it is a
different device). The Windows and macOS trash tests use the real Recycle Bin / Trash but
touch only items they created themselves. On macOS a persistent journal in the scratch
base records each item before it is trashed, so a crashed run's leftovers are erased by
the next run (enumerating `~/.Trash` itself needs Full Disk Access). The volume tests
create a `subst` drive (Windows), a bind mount in a private user + mount namespace (Linux)
or an attached disk image (macOS), and remove it again.
