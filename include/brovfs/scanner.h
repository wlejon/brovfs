#pragma once

#include "brovfs/types.h"

#include <functional>
#include <memory>
#include <vector>

namespace bro::vfs {

// Directory enumeration. Never follows links: a symlink or junction is reported as an entry
// and never descended into. Errors are per entry: an unreadable subdirectory is reported in
// `errors` and the scan continues with its siblings.
struct ScanOptions {
    bool recursive = false;
    bool include_hidden = true;
    uint32_t max_depth = 0;   // 0 = unlimited (when recursive); 1 = root's children only
    size_t batch_size = 256;
    bool read_link_targets = true;
};

struct ScanError {
    fs::path path;
    std::error_code code;
};

struct ScanBatch {
    std::vector<FileEntry> entries;
    std::vector<ScanError> errors;
};

struct ScanResult {
    std::vector<FileEntry> entries;
    std::vector<ScanError> errors;
    bool cancelled = false;
    // True iff the root was opened and every directory was enumerated without error.
    [[nodiscard]] bool complete() const noexcept { return errors.empty() && !cancelled; }
};

// Return false to stop the scan.
using ScanCallback = std::function<bool(ScanBatch&& batch)>;

[[nodiscard]] ScanResult scan_directory(const fs::path& root,
                                        const ScanOptions& options = ScanOptions(),
                                        std::shared_ptr<CancellationToken> token = nullptr);

// Streams batches; returns the same summary as scan_directory but with entries left empty.
ScanResult scan_directory_stream(const fs::path& root, const ScanCallback& callback,
                                 const ScanOptions& options = ScanOptions(),
                                 std::shared_ptr<CancellationToken> token = nullptr);

class AsyncScan {
public:
    virtual ~AsyncScan() = default;
    virtual void cancel() = 0;
    [[nodiscard]] virtual bool is_running() const = 0;
    virtual void wait() = 0;
    // Waits, then returns everything scanned (also delivered through the callback, if any).
    [[nodiscard]] virtual ScanResult result() = 0;
};

// Runs on its own thread; the callback (optional) is invoked on that thread.
[[nodiscard]] std::unique_ptr<AsyncScan> scan_directory_async(const fs::path& root,
                                                              ScanCallback callback = nullptr,
                                                              const ScanOptions& options = ScanOptions(),
                                                              std::shared_ptr<CancellationToken> token = nullptr);

// Single-object metadata without following links.
[[nodiscard]] bool stat_entry(const fs::path& path, FileEntry& out, std::error_code& ec);
// True iff both paths exist and name the same object (by file id, following neither).
[[nodiscard]] bool same_file(const fs::path& a, const fs::path& b, std::error_code& ec);

} // namespace bro::vfs
