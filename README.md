# brovfs

High-performance, non-blocking Desktop Virtual Filesystem and File Operations Engine for Bro (`bro.vfs`).

`brovfs` powers Bro's desktop file explorer, system file pickers, and desktop shell. Unlike general-purpose libraries, `brovfs` is built specifically for desktop file managers and shell applications:
- **Asynchronous batch directory streaming off-thread** without stalling the UI loop.
- **Background recursive file copy/move/delete jobs** with real-time byte progress, speed estimation, ETA, pause, resume, and cancellation tokens.
- **Conflict resolution policies** (Overwrite, Skip, AutoRename, KeepNewer).
- **FreeDesktop Trash specification & Windows Shell Recycle Bin** undo support.
- **Linux CoW (reflink) file cloning** (`copy_file_range(2)` and `ioctl(FICLONE)`) with streaming fallback.
- **Volume and drive enumeration** (`statvfs` on Linux, `GetDiskFreeSpaceExW` / `GetLogicalDriveStringsW` on Windows).
- **Instant magic-byte MIME sniffing** from the first 512 bytes for all desktop file types.

---

## Architecture & Subsystems

- `include/brovfs/scanner.h` (`async_scanner`):
  Non-blocking directory enumeration off-thread with batched callbacks. Leverages `FindFirstFileExW` with `FIND_FIRST_EX_LARGE_FETCH` on Windows and `opendir`/`readdir` on POSIX without per-item `stat()` calls.
- `include/brovfs/file_ops.h` (`file_ops_worker`):
  Standalone copy, move, and delete routines, plus `FileOpsWorker` - a managed background job queue with pause, resume, cancel, and ETA computation.
- `include/brovfs/reflink.h` (`reflink_cow`):
  Zero-cost CoW file cloning via Btrfs/XFS/ZFS `FICLONE` with transparent fast streaming fallback.
- `include/brovfs/trash.h` & `trash_freedesktop.h` (`trash`):
  Full FreeDesktop.org Trash specification implementation (`$XDG_DATA_HOME/Trash/{files,info}`) with collision resolution and `.trashinfo` metadata, plus Windows Recycle Bin integration.
- `include/brovfs/volumes.h` (`volumes`):
  Mount point discovery, filesystem types, capacity, and usage metrics across Windows drives and Linux mounts.
- `include/brovfs/mime.h` (`mime_sniffer`):
  Magic-byte identification from first 512 bytes for desktop images, audio, video, documents, archives, and binaries.
- `include/brovfs/vfs.h`:
  Convenient unified entry point.

---

## Building

Modern C++20 compiler required. No external dependencies (no Qt, no GLib).

```bash
# Configure
cmake -B build -G "Visual Studio 17 2022" -A x64

# Build
cmake --build build --config Debug

# Run tests
ctest --test-dir build -C Debug --output-on-failure
```

---

## Coding Guidelines

- Every source file is strictly under 1,000 lines.
- Memory safe, RAII wrappers, clean Modern C++20 idioms.
