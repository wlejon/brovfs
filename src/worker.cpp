#include "brovfs/worker.h"

#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace bro::vfs {

namespace {

enum class JobType : uint8_t { Copy, Move, Remove, Trash };

bool finished(OpStatus s) { return s == OpStatus::Completed || s == OpStatus::Cancelled || s == OpStatus::Failed; }

} // namespace

struct FileOpsWorker::Impl {
    struct Job {
        JobId id = 0;
        JobType type = JobType::Copy;
        std::vector<fs::path> sources;
        fs::path dest;
        FileOpOptions options;
        ProgressCallback on_progress;
        CompletionCallback on_complete;
        std::shared_ptr<Trash> trash;
        std::shared_ptr<CancellationToken> token = std::make_shared<CancellationToken>();
        OpStatus status = OpStatus::Pending;
        bool paused = false;
        ProgressInfo progress;
        OpResult result;
    };

    mutable std::mutex m;
    std::condition_variable work_cv;  // queue / stop
    std::condition_variable state_cv; // job state changes (pause, finish)
    std::deque<std::shared_ptr<Job>> queue;
    std::unordered_map<JobId, std::shared_ptr<Job>> jobs;
    std::shared_ptr<Job> active;
    JobId next_id = 1;
    bool stopping = false;
    std::thread thread;

    Impl() { thread = std::thread([this] { loop(); }); }

    ~Impl() {
        std::vector<std::shared_ptr<Job>> dropped;
        {
            std::lock_guard<std::mutex> lock(m);
            stopping = true;
            for (auto& [id, j] : jobs) {
                j->token->cancel();
                j->paused = false;
            }
            for (auto& j : queue) {
                j->status = OpStatus::Cancelled;
                j->result.outcome = Outcome::Cancelled;
                dropped.push_back(j);
            }
            queue.clear();
        }
        work_cv.notify_all();
        state_cv.notify_all();
        if (thread.joinable()) thread.join();
        for (auto& j : dropped) {
            if (j->on_complete) j->on_complete(j->id, j->result);
        }
    }

    JobId submit(std::shared_ptr<Job> job) {
        std::lock_guard<std::mutex> lock(m);
        job->id = next_id++;
        jobs[job->id] = job;
        queue.push_back(job);
        work_cv.notify_one();
        return job->id;
    }

    std::shared_ptr<Job> find(JobId id) const {
        auto it = jobs.find(id);
        return it == jobs.end() ? nullptr : it->second;
    }

    void loop() {
        for (;;) {
            std::shared_ptr<Job> job;
            {
                std::unique_lock<std::mutex> lock(m);
                work_cv.wait(lock, [this] { return stopping || !queue.empty(); });
                if (stopping && queue.empty()) return;
                job = queue.front();
                queue.pop_front();
                active = job;
                job->status = job->paused ? OpStatus::Paused : OpStatus::Running;
            }
            OpResult r = execute(*job);
            {
                std::lock_guard<std::mutex> lock(m);
                job->result = r;
                job->status = r.outcome == Outcome::Cancelled ? OpStatus::Cancelled
                              : r.outcome == Outcome::Success ? OpStatus::Completed
                                                              : OpStatus::Failed;
                active.reset();
            }
            state_cv.notify_all();
            if (job->on_complete) job->on_complete(job->id, r);
        }
    }

    // Pause gate + progress snapshot; runs on the worker thread between chunks and items.
    bool gate(Job& job, const ProgressInfo& info) {
        {
            std::unique_lock<std::mutex> lock(m);
            job.progress = info;
            state_cv.wait(lock, [&] { return !job.paused || job.token->is_cancelled(); });
            if (job.token->is_cancelled()) return false;
        }
        return !job.on_progress || job.on_progress(info);
    }

    OpResult execute(Job& job) {
        // A job paused before it started waits here before touching anything.
        if (!gate(job, ProgressInfo{})) {
            OpResult r;
            r.outcome = Outcome::Cancelled;
            return r;
        }
        ProgressCallback cb = [this, &job](const ProgressInfo& info) { return gate(job, info); };
        switch (job.type) {
            case JobType::Copy: return copy_into(job.sources, job.dest, job.options, cb, job.token);
            case JobType::Move: return move_into(job.sources, job.dest, job.options, cb, job.token);
            case JobType::Remove: return remove(job.sources, cb, job.token);
            case JobType::Trash: {
                if (!job.trash) {
                    OpResult r;
                    r.errors.push_back({{}, {}, make_error_code(Errc::no_trash_available), "trash"});
                    r.outcome = Outcome::Failed;
                    return r;
                }
                return trash_paths(*job.trash, job.sources, cb, job.token);
            }
        }
        return {};
    }
};

FileOpsWorker::FileOpsWorker() : impl_(std::make_unique<Impl>()) {}
FileOpsWorker::~FileOpsWorker() = default;

JobId FileOpsWorker::submit_copy(std::vector<fs::path> sources, fs::path dest_dir, FileOpOptions options,
                                 ProgressCallback on_progress, CompletionCallback on_complete) {
    auto j = std::make_shared<Impl::Job>();
    j->type = JobType::Copy;
    j->sources = std::move(sources);
    j->dest = std::move(dest_dir);
    j->options = std::move(options);
    j->on_progress = std::move(on_progress);
    j->on_complete = std::move(on_complete);
    return impl_->submit(std::move(j));
}

JobId FileOpsWorker::submit_move(std::vector<fs::path> sources, fs::path dest_dir, FileOpOptions options,
                                 ProgressCallback on_progress, CompletionCallback on_complete) {
    auto j = std::make_shared<Impl::Job>();
    j->type = JobType::Move;
    j->sources = std::move(sources);
    j->dest = std::move(dest_dir);
    j->options = std::move(options);
    j->on_progress = std::move(on_progress);
    j->on_complete = std::move(on_complete);
    return impl_->submit(std::move(j));
}

JobId FileOpsWorker::submit_remove(std::vector<fs::path> paths, ProgressCallback on_progress,
                                   CompletionCallback on_complete) {
    auto j = std::make_shared<Impl::Job>();
    j->type = JobType::Remove;
    j->sources = std::move(paths);
    j->on_progress = std::move(on_progress);
    j->on_complete = std::move(on_complete);
    return impl_->submit(std::move(j));
}

JobId FileOpsWorker::submit_trash(std::vector<fs::path> paths, std::shared_ptr<Trash> trash,
                                  ProgressCallback on_progress, CompletionCallback on_complete) {
    auto j = std::make_shared<Impl::Job>();
    j->type = JobType::Trash;
    j->sources = std::move(paths);
    j->trash = std::move(trash);
    j->on_progress = std::move(on_progress);
    j->on_complete = std::move(on_complete);
    return impl_->submit(std::move(j));
}

bool FileOpsWorker::pause(JobId id) {
    std::lock_guard<std::mutex> lock(impl_->m);
    auto j = impl_->find(id);
    if (!j || finished(j->status)) return false;
    j->paused = true;
    if (j->status == OpStatus::Running) j->status = OpStatus::Paused;
    return true;
}

bool FileOpsWorker::resume(JobId id) {
    {
        std::lock_guard<std::mutex> lock(impl_->m);
        auto j = impl_->find(id);
        if (!j || !j->paused) return false;
        j->paused = false;
        if (j->status == OpStatus::Paused) j->status = OpStatus::Running;
    }
    impl_->state_cv.notify_all();
    return true;
}

bool FileOpsWorker::cancel(JobId id) {
    std::shared_ptr<Impl::Job> dropped;
    {
        std::lock_guard<std::mutex> lock(impl_->m);
        auto j = impl_->find(id);
        if (!j || finished(j->status)) return false;
        j->token->cancel();
        j->paused = false;
        for (auto it = impl_->queue.begin(); it != impl_->queue.end(); ++it) {
            if ((*it)->id == id) {
                impl_->queue.erase(it);
                j->status = OpStatus::Cancelled;
                j->result.outcome = Outcome::Cancelled;
                dropped = j;
                break;
            }
        }
    }
    impl_->state_cv.notify_all();
    if (dropped && dropped->on_complete) dropped->on_complete(dropped->id, dropped->result);
    return true;
}

void FileOpsWorker::cancel_all() {
    std::vector<JobId> ids;
    {
        std::lock_guard<std::mutex> lock(impl_->m);
        for (auto& [id, j] : impl_->jobs) {
            if (!finished(j->status)) ids.push_back(id);
        }
    }
    for (JobId id : ids) cancel(id);
}

OpStatus FileOpsWorker::status(JobId id) const {
    std::lock_guard<std::mutex> lock(impl_->m);
    auto j = impl_->find(id);
    return j ? j->status : OpStatus::Failed;
}

ProgressInfo FileOpsWorker::progress(JobId id) const {
    std::lock_guard<std::mutex> lock(impl_->m);
    auto j = impl_->find(id);
    return j ? j->progress : ProgressInfo{};
}

OpResult FileOpsWorker::result(JobId id) const {
    std::lock_guard<std::mutex> lock(impl_->m);
    auto j = impl_->find(id);
    return j ? j->result : OpResult{};
}

void FileOpsWorker::wait(JobId id) {
    std::unique_lock<std::mutex> lock(impl_->m);
    auto j = impl_->find(id);
    if (!j) return;
    impl_->state_cv.wait(lock, [&] { return finished(j->status); });
}

void FileOpsWorker::wait_all() {
    std::unique_lock<std::mutex> lock(impl_->m);
    impl_->state_cv.wait(lock, [&] { return impl_->queue.empty() && !impl_->active; });
}

} // namespace bro::vfs
