#include "brovfs/file_ops.h"
#include "brovfs/scanner.h"

#include <chrono>
#include <deque>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#include <utime.h>
#endif

namespace bro::vfs {

namespace fs = std::filesystem;

namespace {

int64_t get_path_mtime_ms(const fs::path& p) {
    std::error_code ec;
    auto ftime = fs::last_write_time(p, ec);
    if (ec) return 0;
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
    );
    return std::chrono::duration_cast<std::chrono::milliseconds>(sctp.time_since_epoch()).count();
}

} // namespace

std::string resolve_conflict_path(
    const std::string& destination_path,
    ConflictResolution resolution,
    const std::string& source_path)
{
    fs::path dst_p(destination_path);
    std::error_code ec;
    if (!fs::exists(dst_p, ec)) {
        return destination_path;
    }

    switch (resolution) {
        case ConflictResolution::Overwrite:
            return destination_path;

        case ConflictResolution::Skip:
            return "";

        case ConflictResolution::KeepNewer: {
            if (source_path.empty()) {
                return destination_path;
            }
            fs::path src_p(source_path);
            int64_t src_mtime = get_path_mtime_ms(src_p);
            int64_t dst_mtime = get_path_mtime_ms(dst_p);
            if (src_mtime > dst_mtime) {
                return destination_path;
            }
            return "";
        }

        case ConflictResolution::AutoRename: {
            std::string parent = dst_p.parent_path().generic_string();
            std::string stem = dst_p.stem().generic_string();
            std::string ext = dst_p.extension().generic_string();

            for (uint32_t i = 1; i < 100000; ++i) {
                std::string candidate_name = stem + " (" + std::to_string(i) + ")" + ext;
                fs::path candidate = parent.empty() ? fs::path(candidate_name) : fs::path(parent) / candidate_name;
                if (!fs::exists(candidate, ec)) {
                    return candidate.generic_string();
                }
            }
            return "";
        }
    }

    return destination_path;
}

namespace {

void preserve_metadata(const fs::path& src, const fs::path& dst, const FileOpOptions& options) {
    std::error_code ec;
    if (options.preserve_timestamps) {
        auto mtime = fs::last_write_time(src, ec);
        if (!ec) {
            fs::last_write_time(dst, mtime, ec);
        }
    }
    if (options.preserve_permissions) {
        auto perms = fs::status(src, ec).permissions();
        if (!ec) {
            fs::permissions(dst, perms, fs::perm_options::replace, ec);
        }
    }
}

} // namespace

bool copy_file(
    const std::string& src,
    const std::string& dst,
    const FileOpOptions& options,
    ProgressCallback on_progress,
    std::shared_ptr<CancellationToken> token)
{
    if (token && token->is_cancelled()) {
        return false;
    }

    fs::path src_p(src);
    std::error_code ec;
    if (!fs::exists(src_p, ec) || fs::is_directory(src_p, ec)) {
        return false;
    }

    std::string actual_dst = resolve_conflict_path(dst, options.conflict_resolution, src);
    if (actual_dst.empty()) {
        // Skipped per conflict resolution
        return true;
    }

    fs::path dst_p(actual_dst);
    if (dst_p.has_parent_path()) {
        fs::create_directories(dst_p.parent_path(), ec);
    }

    uint64_t file_size = fs::file_size(src_p, ec);
    if (ec) {
        file_size = 0;
    }

    std::ifstream in(src_p, std::ios::binary);
    if (!in.is_open()) {
        return false;
    }

    std::ofstream out(dst_p, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }

    size_t buf_size = options.buffer_size > 0 ? options.buffer_size : 64 * 1024;
    std::vector<char> buffer(buf_size);

    ProgressInfo info;
    info.total_bytes = file_size;
    info.total_files = 1;
    info.current_file = src;

    auto start_time = std::chrono::steady_clock::now();
    uint64_t bytes_copied = 0;

    while (in && !in.eof()) {
        if (token && token->is_cancelled()) {
            out.close();
            in.close();
            fs::remove(dst_p, ec);
            return false;
        }

        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        std::streamsize bytes_read = in.gcount();
        if (bytes_read > 0) {
            out.write(buffer.data(), bytes_read);
            if (!out) {
                out.close();
                in.close();
                fs::remove(dst_p, ec);
                return false;
            }
            bytes_copied += static_cast<uint64_t>(bytes_read);
        }

        if (on_progress) {
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - start_time).count();
            info.bytes_processed = bytes_copied;
            if (elapsed > 0.0001) {
                info.speed_bytes_per_sec = static_cast<double>(bytes_copied) / elapsed;
                if (info.speed_bytes_per_sec > 0.0 && file_size > bytes_copied) {
                    info.eta_seconds = static_cast<double>(file_size - bytes_copied) / info.speed_bytes_per_sec;
                } else {
                    info.eta_seconds = 0.0;
                }
            }
            if (!on_progress(info)) {
                out.close();
                in.close();
                fs::remove(dst_p, ec);
                return false;
            }
        }
    }

    out.close();
    in.close();

    preserve_metadata(src_p, dst_p, options);

    if (on_progress) {
        info.bytes_processed = bytes_copied;
        info.files_processed = 1;
        info.eta_seconds = 0.0;
        on_progress(info);
    }

    return true;
}

namespace {

struct TreeScanResult {
    uint64_t total_bytes = 0;
    uint64_t total_files = 0;
    std::vector<FileEntry> entries;
};

TreeScanResult scan_tree(const std::string& root) {
    TreeScanResult result;
    ScanOptions opt;
    opt.recursive = true;
    opt.include_hidden = true;
    opt.follow_symlinks = false;

    result.entries = scan_directory(root, opt);
    for (const auto& e : result.entries) {
        result.total_files++;
        if (e.is_regular_file) {
            result.total_bytes += e.size;
        }
    }
    return result;
}

} // namespace

bool copy_directory(
    const std::string& src,
    const std::string& dst,
    const FileOpOptions& options,
    ProgressCallback on_progress,
    std::shared_ptr<CancellationToken> token)
{
    if (token && token->is_cancelled()) {
        return false;
    }

    fs::path src_p(src);
    std::error_code ec;
    if (!fs::exists(src_p, ec) || !fs::is_directory(src_p, ec)) {
        return false;
    }

    std::string actual_dst = resolve_conflict_path(dst, options.conflict_resolution, src);
    if (actual_dst.empty()) {
        return true;
    }

    fs::path dst_p(actual_dst);
    fs::create_directories(dst_p, ec);

    auto tree = scan_tree(src);

    ProgressInfo global_info;
    global_info.total_bytes = tree.total_bytes;
    global_info.total_files = tree.total_files;

    auto start_time = std::chrono::steady_clock::now();

    fs::path src_base = fs::canonical(src_p, ec);
    if (ec) src_base = src_p;

    for (const auto& entry : tree.entries) {
        if (token && token->is_cancelled()) {
            return false;
        }

        fs::path entry_p(entry.path);
        fs::path rel = fs::relative(entry_p, src_p, ec);
        if (ec) {
            rel = entry.name;
        }
        fs::path target_p = dst_p / rel;

        global_info.current_file = entry.path;

        if (entry.is_directory) {
            fs::create_directories(target_p, ec);
            preserve_metadata(entry_p, target_p, options);
            global_info.files_processed++;
            if (on_progress) {
                if (!on_progress(global_info)) return false;
            }
        } else if (entry.is_regular_file) {
            uint64_t file_bytes_copied = 0;
            auto file_progress = [&](const ProgressInfo& file_info) -> bool {
                uint64_t delta = file_info.bytes_processed - file_bytes_copied;
                file_bytes_copied = file_info.bytes_processed;
                global_info.bytes_processed += delta;

                auto now = std::chrono::steady_clock::now();
                double elapsed = std::chrono::duration<double>(now - start_time).count();
                if (elapsed > 0.0001) {
                    global_info.speed_bytes_per_sec = static_cast<double>(global_info.bytes_processed) / elapsed;
                    if (global_info.speed_bytes_per_sec > 0.0 && global_info.total_bytes > global_info.bytes_processed) {
                        global_info.eta_seconds = static_cast<double>(global_info.total_bytes - global_info.bytes_processed) / global_info.speed_bytes_per_sec;
                    }
                }

                if (on_progress) {
                    return on_progress(global_info);
                }
                return true;
            };

            if (!copy_file(entry.path, target_p.generic_string(), options, file_progress, token)) {
                return false;
            }
            global_info.files_processed++;
        }
    }

    preserve_metadata(src_p, dst_p, options);
    return true;
}

bool copy_path(
    const std::string& src,
    const std::string& dst,
    const FileOpOptions& options,
    ProgressCallback on_progress,
    std::shared_ptr<CancellationToken> token)
{
    fs::path src_p(src);
    std::error_code ec;
    if (fs::is_directory(src_p, ec)) {
        return copy_directory(src, dst, options, on_progress, token);
    }
    return copy_file(src, dst, options, on_progress, token);
}

bool move_path(
    const std::string& src,
    const std::string& dst,
    const FileOpOptions& options,
    ProgressCallback on_progress,
    std::shared_ptr<CancellationToken> token)
{
    if (token && token->is_cancelled()) {
        return false;
    }

    std::string actual_dst = resolve_conflict_path(dst, options.conflict_resolution, src);
    if (actual_dst.empty()) {
        return true;
    }

    std::error_code ec;
    fs::rename(src, actual_dst, ec);
    if (!ec) {
        if (on_progress) {
            ProgressInfo info;
            info.files_processed = 1;
            info.total_files = 1;
            info.current_file = src;
            on_progress(info);
        }
        return true;
    }

    // Fallback: cross-volume copy + delete
    if (!copy_path(src, actual_dst, options, on_progress, token)) {
        return false;
    }
    return delete_path(src, nullptr, token);
}

bool delete_path(
    const std::string& path,
    ProgressCallback on_progress,
    std::shared_ptr<CancellationToken> token)
{
    if (token && token->is_cancelled()) {
        return false;
    }

    fs::path p(path);
    std::error_code ec;
    if (!fs::exists(p, ec)) {
        return true;
    }

    if (fs::is_directory(p, ec)) {
        auto tree = scan_tree(path);
        ProgressInfo info;
        info.total_files = tree.total_files + 1;
        info.total_bytes = tree.total_bytes;

        // Delete files first, then directories bottom-up
        for (auto it = tree.entries.rbegin(); it != tree.entries.rend(); ++it) {
            if (token && token->is_cancelled()) return false;
            info.current_file = it->path;
            fs::remove(it->path, ec);
            info.files_processed++;
            info.bytes_processed += it->size;
            if (on_progress) {
                if (!on_progress(info)) return false;
            }
        }
        fs::remove(p, ec);
        info.files_processed++;
        if (on_progress) {
            on_progress(info);
        }
        return !ec;
    }

    uint64_t sz = fs::file_size(p, ec);
    fs::remove(p, ec);
    if (on_progress) {
        ProgressInfo info;
        info.total_files = 1;
        info.files_processed = 1;
        info.total_bytes = sz;
        info.bytes_processed = sz;
        info.current_file = path;
        on_progress(info);
    }
    return !ec;
}

// Background Worker Implementation
struct FileOpsWorker::Job {
    uint64_t id = 0;
    OpType type = OpType::Copy;
    std::string src;
    std::string dst;
    FileOpOptions options;
    ProgressCallback on_progress;
    CompletionCallback on_complete;

    std::shared_ptr<CancellationToken> token;
    OpStatus status = OpStatus::Pending;
    ProgressInfo progress;
    std::string error_message;
    std::atomic<bool> is_paused{false};
};

struct FileOpsWorker::Impl {
    std::mutex mutex;
    std::condition_variable cv;
    std::condition_variable pause_cv;
    std::deque<std::shared_ptr<Job>> pending_jobs;
    std::unordered_map<uint64_t, std::shared_ptr<Job>> all_jobs;
    uint64_t next_id = 1;
    bool stop_requested = false;
    std::thread worker_thread;
    std::shared_ptr<Job> current_job;

    Impl() {
        worker_thread = std::thread([this]() { worker_loop(); });
    }

    ~Impl() {
        {
            std::lock_guard<std::mutex> lock(mutex);
            stop_requested = true;
            for (auto& [_, j] : all_jobs) {
                if (j->token) j->token->cancel();
                j->is_paused.store(false);
            }
        }
        cv.notify_all();
        pause_cv.notify_all();
        if (worker_thread.joinable()) {
            worker_thread.join();
        }
    }

    void worker_loop() {
        while (true) {
            std::shared_ptr<Job> job;
            {
                std::unique_lock<std::mutex> lock(mutex);
                cv.wait(lock, [this]() {
                    return stop_requested || !pending_jobs.empty();
                });

                if (stop_requested && pending_jobs.empty()) {
                    break;
                }

                if (!pending_jobs.empty()) {
                    job = pending_jobs.front();
                    pending_jobs.pop_front();
                    current_job = job;
                    job->status = OpStatus::Running;
                }
            }

            if (!job) continue;

            if (job->token && job->token->is_cancelled()) {
                job->status = OpStatus::Cancelled;
                if (job->on_complete) job->on_complete(false, "Cancelled before start");
                continue;
            }

            auto wrapped_progress = [this, job](const ProgressInfo& info) -> bool {
                while (job->is_paused.load(std::memory_order_acquire)) {
                    std::unique_lock<std::mutex> pause_lock(mutex);
                    pause_cv.wait(pause_lock, [this, job]() {
                        return stop_requested || !job->is_paused.load(std::memory_order_acquire) ||
                               (job->token && job->token->is_cancelled());
                    });
                }

                if (job->token && job->token->is_cancelled()) {
                    return false;
                }

                {
                    std::lock_guard<std::mutex> lock(mutex);
                    job->progress = info;
                }

                if (job->on_progress) {
                    return job->on_progress(info);
                }
                return true;
            };

            bool success = false;
            std::string err;

            try {
                switch (job->type) {
                    case OpType::Copy:
                        success = copy_path(job->src, job->dst, job->options, wrapped_progress, job->token);
                        break;
                    case OpType::Move:
                        success = move_path(job->src, job->dst, job->options, wrapped_progress, job->token);
                        break;
                    case OpType::Delete:
                        success = delete_path(job->src, wrapped_progress, job->token);
                        break;
                }
            } catch (const std::exception& e) {
                err = e.what();
                success = false;
            }

            {
                std::lock_guard<std::mutex> lock(mutex);
                if (job->token && job->token->is_cancelled()) {
                    job->status = OpStatus::Cancelled;
                    err = "Operation cancelled";
                } else if (success) {
                    job->status = OpStatus::Completed;
                } else {
                    job->status = OpStatus::Failed;
                    job->error_message = err.empty() ? "Operation failed" : err;
                }
                current_job.reset();
            }

            if (job->on_complete) {
                job->on_complete(success, job->error_message);
            }
        }
    }
};

FileOpsWorker::FileOpsWorker() : impl_(std::make_unique<Impl>()) {}
FileOpsWorker::~FileOpsWorker() = default;

uint64_t FileOpsWorker::submit_copy(
    const std::string& src,
    const std::string& dst,
    const FileOpOptions& options,
    ProgressCallback on_progress,
    CompletionCallback on_complete)
{
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto job = std::make_shared<Job>();
    job->id = impl_->next_id++;
    job->type = OpType::Copy;
    job->src = src;
    job->dst = dst;
    job->options = options;
    job->on_progress = std::move(on_progress);
    job->on_complete = std::move(on_complete);
    job->token = std::make_shared<CancellationToken>();

    impl_->pending_jobs.push_back(job);
    impl_->all_jobs[job->id] = job;
    impl_->cv.notify_one();
    return job->id;
}

uint64_t FileOpsWorker::submit_move(
    const std::string& src,
    const std::string& dst,
    const FileOpOptions& options,
    ProgressCallback on_progress,
    CompletionCallback on_complete)
{
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto job = std::make_shared<Job>();
    job->id = impl_->next_id++;
    job->type = OpType::Move;
    job->src = src;
    job->dst = dst;
    job->options = options;
    job->on_progress = std::move(on_progress);
    job->on_complete = std::move(on_complete);
    job->token = std::make_shared<CancellationToken>();

    impl_->pending_jobs.push_back(job);
    impl_->all_jobs[job->id] = job;
    impl_->cv.notify_one();
    return job->id;
}

uint64_t FileOpsWorker::submit_delete(
    const std::string& path,
    ProgressCallback on_progress,
    CompletionCallback on_complete)
{
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto job = std::make_shared<Job>();
    job->id = impl_->next_id++;
    job->type = OpType::Delete;
    job->src = path;
    job->on_progress = std::move(on_progress);
    job->on_complete = std::move(on_complete);
    job->token = std::make_shared<CancellationToken>();

    impl_->pending_jobs.push_back(job);
    impl_->all_jobs[job->id] = job;
    impl_->cv.notify_one();
    return job->id;
}

bool FileOpsWorker::pause(uint64_t job_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto it = impl_->all_jobs.find(job_id);
    if (it != impl_->all_jobs.end() && it->second->status == OpStatus::Running) {
        it->second->is_paused.store(true, std::memory_order_release);
        it->second->status = OpStatus::Paused;
        return true;
    }
    return false;
}

bool FileOpsWorker::resume(uint64_t job_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto it = impl_->all_jobs.find(job_id);
    if (it != impl_->all_jobs.end() && it->second->status == OpStatus::Paused) {
        it->second->is_paused.store(false, std::memory_order_release);
        it->second->status = OpStatus::Running;
        impl_->pause_cv.notify_all();
        return true;
    }
    return false;
}

bool FileOpsWorker::cancel(uint64_t job_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto it = impl_->all_jobs.find(job_id);
    if (it != impl_->all_jobs.end()) {
        if (it->second->token) {
            it->second->token->cancel();
        }
        if (it->second->is_paused.load()) {
            it->second->is_paused.store(false);
            impl_->pause_cv.notify_all();
        }
        return true;
    }
    return false;
}

OpStatus FileOpsWorker::get_status(uint64_t job_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto it = impl_->all_jobs.find(job_id);
    if (it != impl_->all_jobs.end()) {
        return it->second->status;
    }
    return OpStatus::Failed;
}

ProgressInfo FileOpsWorker::get_progress(uint64_t job_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto it = impl_->all_jobs.find(job_id);
    if (it != impl_->all_jobs.end()) {
        return it->second->progress;
    }
    return {};
}

std::string FileOpsWorker::get_error(uint64_t job_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto it = impl_->all_jobs.find(job_id);
    if (it != impl_->all_jobs.end()) {
        return it->second->error_message;
    }
    return "";
}

void FileOpsWorker::wait_job(uint64_t job_id) {
    while (true) {
        {
            std::lock_guard<std::mutex> lock(impl_->mutex);
            auto it = impl_->all_jobs.find(job_id);
            if (it == impl_->all_jobs.end()) return;
            auto st = it->second->status;
            if (st == OpStatus::Completed || st == OpStatus::Cancelled || st == OpStatus::Failed) {
                return;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

void FileOpsWorker::wait_all() {
    while (true) {
        {
            std::lock_guard<std::mutex> lock(impl_->mutex);
            if (impl_->pending_jobs.empty() && !impl_->current_job) {
                return;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

void FileOpsWorker::cancel_all() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    for (auto& [_, job] : impl_->all_jobs) {
        if (job->token) {
            job->token->cancel();
        }
        if (job->is_paused.load()) {
            job->is_paused.store(false);
        }
    }
    impl_->pause_cv.notify_all();
}

} // namespace bro::vfs
