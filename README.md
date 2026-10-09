# brovfs

[![CI](https://github.com/wlejon/brovfs/actions/workflows/ci.yml/badge.svg)](https://github.com/wlejon/brovfs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

File-operations substrate for a desktop file manager: directory scanning, copy/move/remove,
trash lifecycle, volume monitoring, file watching, and MIME sniffing. A standalone C++20
library with no dependencies beyond the operating system (no bro, no bronze, no Qt or GLib),
shipping native backends for Windows, Linux, and macOS.

brovfs sits in the desktop-environment layer of the
[bro ecosystem](https://github.com/wlejon/bro/blob/main/docs/ecosystem.md). It is consumed
directly by sibling desktop libraries such as [broapps](https://github.com/wlejon/broapps)
(which relies on its MIME database and directory watcher) and
[brothumb](https://github.com/wlejon/brothumb) (for file sniffing and cache locations).
The [bro runtime](https://github.com/wlejon/bro) mounts its JavaScript binding
(`brovfs_api` in `src/api/`) under the `BRO_WITH_VFS` build gate, exposing `bro.vfs` to
apps running on the bronze JavaScript engine.

## Safety Guarantees

The first duty is never to lose data:

- **Pre-flight planning & file identity:** Every operation is planned against a scanned,
  no-follow model of the source and verified by file identity (device + inode on POSIX;
  volume serial + 128-bit file ID on Windows) before acting.
- **Atomic staging:** Files are copied to a temp sibling (`.brovfs-<hex>.tmp`), flushed to
  disk, and committed with an atomic no-replace rename (or replacement rename only when the
  caller specifies `Overwrite`).
- **Safe moves:** Same-device moves rename in place. Cross-device transfers fall back to
  copy-then-delete; the source is unlinked only after the destination is fully committed and
  the source still matches the pre-flight identity. Source directories are removed with
  `rmdir` only.
- **Race-resistant traversal:** Directory traversal and removal go through directory handles
  (`openat`/`fstatat`/`unlinkat` with `O_NOFOLLOW` on POSIX; `NtCreateFile` relative to the
  parent handle and delete-by-handle on Windows). A parent swapped for a symlink mid-operation
  cannot redirect a deletion.
- **Metadata preservation:** File timestamps (including birth time where supported),
  permissions/mode, ownership where permitted, POSIX/extended ACLs or Windows security
  descriptors (`preserve_acls`), Windows alternate data streams (ADS), and hard-link sets
  within an operation are preserved. Staging leftovers can be swept with
  `clean_staging_leftovers()`.
- **Link safety:** Symlinks and junctions are manipulated as links; deleting a link never
  touches its target.
- **Structured results:** Operations report per-item status via `OpResult` (`Success`,
  `Partial`, `Failed`, `Cancelled`), recording an audit trail in `OpResult::done` for undo.

## Platforms

All backends use native OS system calls directly without abstraction wrappers:

| Platform | Verified Toolchain | File Operations & Scanning | File Watching | Trash System | Volumes & Types |
|---|---|---|---|---|---|
| **Windows** | MSVC 2022+ (x64) | `FileIdExtdDirectoryInfo` fast enumerations; `CopyFile2` / streaming; delete-by-handle via `NtCreateFile` | `ReadDirectoryChangesExW` with 8.3 short-name expansion | Windows Recycle Bin via Shell interfaces; listing, restore, and erase from `$I` records | `WM_DEVICECHANGE`, `GetVolumeInformationW`; Registry `AssocQueryString` MIME lookup |
| **Linux** | GCC 12+, Clang 15+ (x86-64, aarch64) | `getdents64` + `statx`; `FICLONE` reflink, `copy_file_range` extent sharing, streaming fallback; `openat`/`unlinkat` | `inotify` with dynamic recursive sub-watches and cookie rename pairing | Freedesktop Trash specification (`~/.local/share/Trash`, `$topdir/.Trash-$uid`) | `/proc/self/mountinfo` polling (`POLLPRI`); XDG shared-mime-info database |
| **macOS** | Apple Clang (Xcode 15+, arm64, x86-64) | APFS `clonefile` reflink; `openat`/`unlinkat` directory-relative operations | `FSEvents` API with event coalescing and path translation | `NSFileManager` trash; Finder Apple Events when Automation consent is granted; `.DS_Store` restore | `DiskArbitration` framework; Uniform Type Identifiers (`UTType`) |

## Architecture & API Overview

```
include/brovfs/
  vfs.h           Umbrella header
  path.h          UTF-8 (WTF-8 on Windows) normalization and \\?\ long-path handling
  types.h         FileIdentity, FileMetadata, DirEntry, OpResult, ConflictPolicy
  scanner.h       Synchronous, streamed, and async directory scanners with per-entry errors
  file_ops.h      copy_into/to, move_into/to, remove, clone_file, staging cleanup
  watcher.h       DirectoryWatcher (recursive/flat) delivering to WatchEventQueue
  dir_model.h     DirectoryModel: reactive sorted/filtered file lists with stable keys
  collate.h       natural_compare / NaturalLess human-friendly collation
  aggregate.h     aggregate_selection: background recursive size and entry counts
  undo.h          UndoJournal: identity-validated undo/redo for copy, move, and trash
  trash.h         Native trash operations: trash_items, list_trash, restore, erase
  volumes.h       Mounted volumes, disk capacity, and VolumeMonitor hotplug listener
  mime.h          Magic-byte sniffing, MimeDatabase (system + deterministic built-in), globs
  worker.h        FileOpsWorker background queue with progress, pause, resume, and cancel
  event_queue.h   Thread-safe MessageQueue<T>
  api.h           Bronze JavaScript binding entry point (brovfs_api)
```

### Key Components

- **Directory Scanning (`scanner.h`):** `scan_directory` delivers batches of `DirEntry` items
  streamed or accumulated. Linux uses `getdents64` followed by `statx` only when extra
  metadata is needed; Windows queries `FileIdExtdDirectoryInfo` to retrieve 128-bit file
  identifiers in bulk.
- **File Operations (`file_ops.h`):** High-level verbs handle recursive trees, preserve
  attributes, and report progress. `clone_file` attempts hardware/filesystem clone
  first (`FICLONE` on Linux btrfs/XFS, `clonefile` on macOS APFS) before falling back to
  `copy_file_range` or buffered streaming.
- **Directory Watching (`watcher.h`):** `DirectoryWatcher` emits `WatchEvent` notifications
  (`Created`, `Removed`, `Modified`, `Renamed`, `Rescan`, `RootRemoved`, `Error`). A kernel
  queue overflow produces a `Rescan` event rather than dropped events, guaranteeing the
  consumer model reconciles.
- **Reactive Model (`dir_model.h`):** `DirectoryModel` maintains an in-memory view of a
  directory, applying watcher events incrementally (`Insert`, `Remove`, `Update`) with
  deterministic sorting and filtering.
- **MIME System (`mime.h`):** `MimeDatabase::system()` inspects magic signatures, XDG
  `shared-mime-info` or OS registries, glob rules, and sub-class hierarchies (`is_a`), while
  `MimeDatabase::built_in()` provides an offline deterministic oracle.
- **Undo Journal (`undo.h`):** Records completed actions from `OpResult::done`. Reversals
  verify file identity, timestamps, and destination availability before mutating the
  filesystem.

## Building

brovfs requires CMake 3.24+ and a C++20 compiler. It has no mandatory external dependencies.

### Standalone Build

```bash
# Windows (Visual Studio 2022 or Ninja)
cmake -B build -DBROVFS_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure

# Linux (GCC / Clang + Ninja)
cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DBROVFS_BUILD_TESTS=ON
cmake --build build-release
ctest --test-dir build-release --output-on-failure

# macOS (Apple Clang + Ninja)
cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DBROVFS_BUILD_TESTS=ON
cmake --build build-release
ctest --test-dir build-release --output-on-failure
```

### Consuming brovfs as a Dependency

Downstream consumers (such as [broapps](https://github.com/wlejon/broapps) and
[brothumb](https://github.com/wlejon/brothumb)) resolve brovfs via CMake `add_subdirectory()`
and link against `brovfs::brovfs`:

```cmake
add_subdirectory(path/to/brovfs)
target_link_libraries(your_target PRIVATE brovfs::brovfs)
```

Ecosystem consumers pin brovfs with `bro_dependency(brovfs ...)` (`cmake/bro_deps.cmake`):
a target the outer project already added wins, else a `../brovfs` working tree beside the
top-level project, else the pinned commit, fetched at configure. Point at another tree with
`-DFETCHCONTENT_SOURCE_DIR_BROVFS=<path>`.

### Optional Bronze JavaScript API

The standalone JavaScript binding (`BROVFS_ENABLE_API`, on when brovfs is the top-level
project) compiles `brovfs_api` for the [bronze](https://github.com/wlejon/bronze) engine.
bronze (with brass) resolves the same way: `../bronze` beside the top-level project, else the
pinned commit, fetched at configure, so a plain clone builds. Set `-DBROVFS_ENABLE_API=OFF`
for pure C++ builds without JavaScript support.

## Tests

The test suite runs real system operations against the OS filesystem (no mocks, no plain
`assert()`). Failures count in all build configurations. When an optional OS capability is
absent, tests exit with status `77` (ctest skip) and report the exact reason:

- **Scoped Scratch Directories:** All file operations run within an isolated scratch root
  configured via `BROVFS_TEST_SCRATCH` (defaults to `./brovfs-scratch`). Cross-device move
  tests use `BROVFS_TEST_SCRATCH2` (`%TEMP%` on Windows, `/dev/shm` on Linux) to safely test
  fallback copy-then-unlink logic across filesystem boundaries.
- **Linux User & Mount Namespaces:** Volume monitoring tests (`test_volumes`) verify bind
  mounts and read-only remounts by creating an isolated unprivileged user and mount namespace
  (`unshare(CLONE_NEWUSER | CLONE_NEWNS)`). If the kernel restricts unprivileged user
  namespaces (such as Ubuntu 24.04 AppArmor confinement via
  `kernel.apparmor_restrict_unprivileged_userns`), the namespace test skips gracefully.
- **macOS Full Disk Access (FDA):** Native trash testing uses `NSFileManager` and temporary
  journals. Trashing via Finder automation or inspecting raw `~/.Trash` contents / `.DS_Store`
  records requires Full Disk Access under macOS privacy controls. If FDA is not granted to
  the test runner, tests that inspect `~/.Trash` directly skip while scoped scratch trash tests
  continue to run.
- **Windows Recycle Bin Isolation:** Shell Recycle Bin tests operate strictly on uniquely
  named temporary items created by the test harness and clean them up during teardown.
- **Coverage:** Linux GCC/Clang builds support `-DBROVFS_COVERAGE=ON` for branch coverage
  reporting with `gcovr`.
