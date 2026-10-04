# brovfs

File-operations substrate for a desktop file manager: scanning, copy/move/remove, trash,
volumes and MIME sniffing. A standalone C++20 library with no dependencies beyond the OS
(no bro, no bronze, no Qt/GLib), Windows and Linux.

The first duty is never to lose data:

- Every operation is planned against a scanned, no-follow model of the source and checked
  by file identity (device + inode / volume serial + 128-bit file ID) before it acts.
- Files are written to a temp sibling (`.brovfs-<hex>.tmp`), synced, and committed with a
  no-replace rename (or replace, only when the caller chose Overwrite).
- A move renames when it can. Only a cross-device error falls back to copy, and a source is
  deleted only after its destination is committed and the source still matches the plan.
  Source directories are removed with `rmdir` only.
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
  (FICLONE reflink, then copy_file_range, then streaming; the method used is reported).
- `brovfs/worker.h`: `FileOpsWorker` background job queue with progress, pause, resume
  and cancel.
- `brovfs/trash.h`: freedesktop.org trash per spec (home trash, `$topdir/.Trash/$uid`,
  `$topdir/.Trash-$uid`, directorysizes) and the Windows Recycle Bin (shell recycle that
  refuses rather than permanently deleting; listing, restore and erase from `$I` records).
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
```

The tests use the real file system, only inside scratch directories they create
(`BROVFS_TEST_SCRATCH`, default `./brovfs-scratch`). Cross-device cases use
`BROVFS_TEST_SCRATCH2` (default: `%TEMP%` on Windows, `/dev/shm` on Linux, when it is a
different device). The Windows trash test uses the real Recycle Bin but touches only
items it created itself.
