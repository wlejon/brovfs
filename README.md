# brovfs

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
  is reported), staging-leftover cleanup.
- `brovfs/watcher.h`: `DirectoryWatcher`, recursive or not, value events (Created /
  Removed / Modified / Renamed / Rescan / RootRemoved / Error) coalesced into a
  `WatchEventQueue` the host drains on its own thread. ReadDirectoryChangesExW on Windows,
  inotify with dynamic subdirectory watches and cookie rename pairing on Linux, FSEvents on
  macOS. A lost kernel queue is a `Rescan` of the affected directory, never silence, so a
  consumer applying the events to its model (rescanning on `Rescan`) always reconciles.
- `brovfs/event_queue.h`: the `MessageQueue<T>` the watcher delivers through.
- `brovfs/worker.h`: `FileOpsWorker` background job queue with progress, pause, resume
  and cancel.
- `brovfs/trash.h`: freedesktop.org trash per spec (home trash, `$topdir/.Trash/$uid`,
  `$topdir/.Trash-$uid`, directorysizes) and the Windows Recycle Bin (shell recycle that
  refuses rather than permanently deleting; listing, restore and erase from `$I` records),
  and the macOS Trash through NSFileManager (restore data in xattrs on the item; Finder's
  "Put Back" does not apply to these items, see the header).
- `brovfs/volumes.h`: mounted volumes, capacity, read-only state.
- `brovfs/mime.h`: magic-byte MIME sniffing (images, audio, video, documents,
  archives, fonts, glTF/glb, ...).
- `brovfs/vfs.h`: umbrella header.

## Building

```bash
# Windows (Visual Studio generator)
cmake -B build -DBROVFS_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure

# Linux
cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DBROVFS_BUILD_TESTS=ON
cmake --build build-release && ctest --test-dir build-release --output-on-failure

# macOS (Foundation + CoreServices; one Objective-C++ file for the trash)
cmake -B build-release -DCMAKE_BUILD_TYPE=Release -DBROVFS_BUILD_TESTS=ON
cmake --build build-release && ctest --test-dir build-release --output-on-failure
```

The tests use the real file system, only inside scratch directories they create
(`BROVFS_TEST_SCRATCH`, default `./brovfs-scratch`). Cross-device cases use
`BROVFS_TEST_SCRATCH2` (default: `%TEMP%` on Windows, `/dev/shm` on Linux, when it is a
different device). The Windows and macOS trash tests use the real Recycle Bin / Trash but
touch only items they created themselves.
