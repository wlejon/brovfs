#pragma once

#include "brovfs/types.h"
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <vector>

namespace bro::vfs {

struct ScanOptions {
    bool recursive = false;
    bool include_hidden = true;
    bool follow_symlinks = false;
    uint32_t max_depth = 0;       // 0 means no limit if recursive
    size_t batch_size = 128;      // Number of entries per batch callback
    bool sort_directories_first = false;
};

// Batch callback: return true to continue scanning, false to abort scan
using BatchCallback = std::function<bool(std::vector<FileEntry>&& batch)>;

class AsyncScanHandle {
public:
    virtual ~AsyncScanHandle() = default;
    virtual void cancel() = 0;
    [[nodiscard]] virtual bool is_running() const = 0;
    virtual void wait() = 0;
    [[nodiscard]] virtual std::vector<FileEntry> get_results() = 0;
};

// Synchronous full scan
[[nodiscard]] std::vector<FileEntry> scan_directory(
    const std::string& path,
    const ScanOptions& options = {},
    std::shared_ptr<CancellationToken> token = nullptr);

// Synchronous batch streaming scan (returns false if aborted early)
bool scan_directory_stream(
    const std::string& path,
    BatchCallback callback,
    const ScanOptions& options = {},
    std::shared_ptr<CancellationToken> token = nullptr);

// Asynchronous non-blocking directory scan running on a worker thread
[[nodiscard]] std::unique_ptr<AsyncScanHandle> scan_directory_async(
    const std::string& path,
    BatchCallback callback = nullptr,
    const ScanOptions& options = {},
    std::shared_ptr<CancellationToken> token = nullptr);

} // namespace bro::vfs
