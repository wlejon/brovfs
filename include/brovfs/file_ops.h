#pragma once

#include "brovfs/types.h"
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bro::vfs {

struct FileOpOptions {
    ConflictResolution conflict_resolution = ConflictResolution::Overwrite;
    bool preserve_timestamps = true;
    bool preserve_permissions = true;
    bool follow_symlinks = false;
    size_t buffer_size = 256 * 1024; // 256 KB chunk
};

using ProgressCallback = std::function<bool(const ProgressInfo& info)>;
using CompletionCallback = std::function<void(bool success, const std::string& error)>;

// Conflict path resolver (e.g. returns "file (1).ext" for AutoRename)
[[nodiscard]] std::string resolve_conflict_path(
    const std::string& destination_path,
    ConflictResolution resolution,
    const std::string& source_path = "");

// Standalone synchronous operations
bool copy_file(
    const std::string& src,
    const std::string& dst,
    const FileOpOptions& options = {},
    ProgressCallback on_progress = nullptr,
    std::shared_ptr<CancellationToken> token = nullptr);

bool copy_directory(
    const std::string& src,
    const std::string& dst,
    const FileOpOptions& options = {},
    ProgressCallback on_progress = nullptr,
    std::shared_ptr<CancellationToken> token = nullptr);

bool copy_path(
    const std::string& src,
    const std::string& dst,
    const FileOpOptions& options = {},
    ProgressCallback on_progress = nullptr,
    std::shared_ptr<CancellationToken> token = nullptr);

bool move_path(
    const std::string& src,
    const std::string& dst,
    const FileOpOptions& options = {},
    ProgressCallback on_progress = nullptr,
    std::shared_ptr<CancellationToken> token = nullptr);

bool delete_path(
    const std::string& path,
    ProgressCallback on_progress = nullptr,
    std::shared_ptr<CancellationToken> token = nullptr);

// Background File Operations Worker Job Queue
class FileOpsWorker {
public:
    FileOpsWorker();
    ~FileOpsWorker();

    FileOpsWorker(const FileOpsWorker&) = delete;
    FileOpsWorker& operator=(const FileOpsWorker&) = delete;

    uint64_t submit_copy(
        const std::string& src,
        const std::string& dst,
        const FileOpOptions& options = {},
        ProgressCallback on_progress = nullptr,
        CompletionCallback on_complete = nullptr);

    uint64_t submit_move(
        const std::string& src,
        const std::string& dst,
        const FileOpOptions& options = {},
        ProgressCallback on_progress = nullptr,
        CompletionCallback on_complete = nullptr);

    uint64_t submit_delete(
        const std::string& path,
        ProgressCallback on_progress = nullptr,
        CompletionCallback on_complete = nullptr);

    bool pause(uint64_t job_id);
    bool resume(uint64_t job_id);
    bool cancel(uint64_t job_id);

    [[nodiscard]] OpStatus get_status(uint64_t job_id) const;
    [[nodiscard]] ProgressInfo get_progress(uint64_t job_id) const;
    [[nodiscard]] std::string get_error(uint64_t job_id) const;

    void wait_job(uint64_t job_id);
    void wait_all();
    void cancel_all();

private:
    struct Job;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace bro::vfs
