#include "brovfs/scanner.h"
#include "src/scanner_internal.h"
#include <algorithm>
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

namespace bro::vfs {

namespace {

class AsyncScanHandleImpl : public AsyncScanHandle {
public:
    AsyncScanHandleImpl(
        std::string path,
        BatchCallback user_callback,
        ScanOptions options,
        std::shared_ptr<CancellationToken> token)
        : path_(std::move(path)),
          user_callback_(std::move(user_callback)),
          options_(options),
          token_(token ? token : std::make_shared<CancellationToken>()),
          is_running_(true)
    {
        worker_ = std::thread([this]() {
            run();
        });
    }

    ~AsyncScanHandleImpl() override {
        cancel();
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    void cancel() override {
        if (token_) {
            token_->cancel();
        }
    }

    bool is_running() const override {
        return is_running_.load(std::memory_order_acquire);
    }

    void wait() override {
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    std::vector<FileEntry> get_results() override {
        wait();
        std::lock_guard<std::mutex> lock(mutex_);
        return accumulated_results_;
    }

private:
    void run() {
        BatchCallback internal_cb = [this](std::vector<FileEntry>&& batch) -> bool {
            bool user_continue = true;
            if (user_callback_) {
                user_continue = user_callback_(std::vector<FileEntry>(batch));
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                for (auto& item : batch) {
                    accumulated_results_.push_back(std::move(item));
                }
            }
            return user_continue;
        };

        detail::scan_directory_platform(path_, internal_cb, options_, token_, 0);

        if (options_.sort_directories_first) {
            std::lock_guard<std::mutex> lock(mutex_);
            std::sort(accumulated_results_.begin(), accumulated_results_.end(), [](const FileEntry& a, const FileEntry& b) {
                if (a.is_directory != b.is_directory) {
                    return a.is_directory > b.is_directory;
                }
                return a.name < b.name;
            });
        }

        is_running_.store(false, std::memory_order_release);
    }

    std::string path_;
    BatchCallback user_callback_;
    ScanOptions options_;
    std::shared_ptr<CancellationToken> token_;
    std::atomic<bool> is_running_;
    std::thread worker_;
    std::mutex mutex_;
    std::vector<FileEntry> accumulated_results_;
};

void sort_entries(std::vector<FileEntry>& entries, bool directories_first) {
    std::sort(entries.begin(), entries.end(), [directories_first](const FileEntry& a, const FileEntry& b) {
        if (directories_first && a.is_directory != b.is_directory) {
            return a.is_directory > b.is_directory;
        }
        return a.name < b.name;
    });
}

} // namespace

std::vector<FileEntry> scan_directory(
    const std::string& path,
    const ScanOptions& options,
    std::shared_ptr<CancellationToken> token)
{
    std::vector<FileEntry> all_entries;
    BatchCallback cb = [&all_entries](std::vector<FileEntry>&& batch) -> bool {
        for (auto& e : batch) {
            all_entries.push_back(std::move(e));
        }
        return true;
    };

    scan_directory_stream(path, cb, options, token);

    if (options.sort_directories_first) {
        sort_entries(all_entries, true);
    }

    return all_entries;
}

bool scan_directory_stream(
    const std::string& path,
    BatchCallback callback,
    const ScanOptions& options,
    std::shared_ptr<CancellationToken> token)
{
    if (!callback) {
        return false;
    }
    return detail::scan_directory_platform(path, callback, options, token, 0);
}

std::unique_ptr<AsyncScanHandle> scan_directory_async(
    const std::string& path,
    BatchCallback callback,
    const ScanOptions& options,
    std::shared_ptr<CancellationToken> token)
{
    return std::make_unique<AsyncScanHandleImpl>(path, std::move(callback), options, token);
}

} // namespace bro::vfs
