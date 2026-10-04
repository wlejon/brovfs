#pragma once

#include "brovfs/file_ops.h"
#include "brovfs/trash.h"

#include <functional>
#include <memory>
#include <vector>

namespace bro::vfs {

using JobId = uint64_t;
using CompletionCallback = std::function<void(JobId, const OpResult&)>;

// Background job queue: one worker thread runs jobs in submission order. Progress and conflict
// callbacks run on the worker thread; a conflict resolver may block (e.g. waiting on the UI).
class FileOpsWorker {
public:
    FileOpsWorker();
    ~FileOpsWorker(); // cancels everything, then joins
    FileOpsWorker(const FileOpsWorker&) = delete;
    FileOpsWorker& operator=(const FileOpsWorker&) = delete;

    JobId submit_copy(std::vector<fs::path> sources, fs::path dest_dir,
                      FileOpOptions options = FileOpOptions(), ProgressCallback on_progress = nullptr,
                      CompletionCallback on_complete = nullptr);
    JobId submit_move(std::vector<fs::path> sources, fs::path dest_dir,
                      FileOpOptions options = FileOpOptions(), ProgressCallback on_progress = nullptr,
                      CompletionCallback on_complete = nullptr);
    JobId submit_remove(std::vector<fs::path> paths, ProgressCallback on_progress = nullptr,
                        CompletionCallback on_complete = nullptr);
    JobId submit_trash(std::vector<fs::path> paths, std::shared_ptr<Trash> trash,
                       ProgressCallback on_progress = nullptr, CompletionCallback on_complete = nullptr);

    bool pause(JobId id);   // running or pending job; takes effect at the next chunk boundary
    bool resume(JobId id);
    bool cancel(JobId id);  // a pending job is finished as Cancelled immediately and never runs
    void cancel_all();

    [[nodiscard]] OpStatus status(JobId id) const;
    [[nodiscard]] ProgressInfo progress(JobId id) const;
    [[nodiscard]] OpResult result(JobId id) const; // meaningful once the job is finished

    void wait(JobId id);
    void wait_all();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace bro::vfs
