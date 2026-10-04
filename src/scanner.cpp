#include "brovfs/scanner.h"

#include "brovfs/path.h"
#include "src/walk.h"

#include <atomic>
#include <mutex>
#include <thread>

namespace bro::vfs {

namespace {

ScanResult run_scan(const fs::path& root, const ScanOptions& options, const CancellationToken* token,
                    const ScanCallback& callback, bool keep_entries) {
    ScanResult result;
    ScanBatch batch;
    size_t batch_size = options.batch_size ? options.batch_size : 256;
    bool stopped = false;

    auto flush = [&]() -> bool {
        if (batch.entries.empty() && batch.errors.empty()) return true;
        if (keep_entries) {
            for (auto& e : batch.entries) result.entries.push_back(e);
        }
        for (auto& e : batch.errors) result.errors.push_back(e);
        bool go = true;
        if (callback) go = callback(std::move(batch));
        batch = ScanBatch{};
        return go;
    };

    detail::WalkOptions wo;
    wo.include_hidden = options.include_hidden;
    wo.max_depth = options.recursive ? options.max_depth : 1;
    wo.follow_root_link = true;

    bool finished = detail::walk(
        root, wo, token,
        [&](const detail::WalkNode& n) {
            FileEntry e = detail::make_entry(n.path, n.name, n.st, n.depth);
            if (n.stat_error) batch.errors.push_back({n.path, n.stat_error});
            if (options.read_link_targets && is_link(n.st.kind)) {
                std::error_code ec;
                sys::read_link_target(n.path, e.link_target, ec);
            }
            batch.entries.push_back(std::move(e));
            if (batch.entries.size() >= batch_size && !flush()) {
                stopped = true;
                return false;
            }
            return true;
        },
        [&](const fs::path& p, const std::error_code& ec) { batch.errors.push_back({p, ec}); });
    if (!stopped && !flush()) stopped = true;
    result.cancelled = !finished || stopped;
    return result;
}

class AsyncScanImpl final : public AsyncScan {
public:
    AsyncScanImpl(fs::path root, ScanCallback cb, ScanOptions options, std::shared_ptr<CancellationToken> token)
        : root_(std::move(root)), cb_(std::move(cb)), options_(options),
          token_(token ? std::move(token) : std::make_shared<CancellationToken>()) {
        thread_ = std::thread([this] {
            ScanResult r = run_scan(root_, options_, token_.get(), cb_, true);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                result_ = std::move(r);
            }
            running_.store(false, std::memory_order_release);
        });
    }
    ~AsyncScanImpl() override {
        cancel();
        wait();
    }
    void cancel() override { token_->cancel(); }
    bool is_running() const override { return running_.load(std::memory_order_acquire); }
    void wait() override {
        std::lock_guard<std::mutex> lock(join_mutex_);
        if (thread_.joinable()) thread_.join();
    }
    ScanResult result() override {
        wait();
        std::lock_guard<std::mutex> lock(mutex_);
        return result_;
    }

private:
    fs::path root_;
    ScanCallback cb_;
    ScanOptions options_;
    std::shared_ptr<CancellationToken> token_;
    std::atomic<bool> running_{true};
    std::mutex mutex_, join_mutex_;
    ScanResult result_;
    std::thread thread_;
};

} // namespace

ScanResult scan_directory(const fs::path& root, const ScanOptions& options, std::shared_ptr<CancellationToken> token) {
    return run_scan(root, options, token.get(), nullptr, true);
}

ScanResult scan_directory_stream(const fs::path& root, const ScanCallback& callback, const ScanOptions& options,
                                 std::shared_ptr<CancellationToken> token) {
    return run_scan(root, options, token.get(), callback, false);
}

std::unique_ptr<AsyncScan> scan_directory_async(const fs::path& root, ScanCallback callback,
                                                const ScanOptions& options, std::shared_ptr<CancellationToken> token) {
    return std::make_unique<AsyncScanImpl>(root, std::move(callback), options, std::move(token));
}

bool stat_entry(const fs::path& path, FileEntry& out, std::error_code& ec) {
    sys::Stat st;
    if (!sys::lstat(path, st, ec)) return false;
    out = detail::make_entry(path, path_to_utf8(leaf_name(path)), st, 0);
    if (is_link(st.kind)) {
        std::error_code lec;
        sys::read_link_target(path, out.link_target, lec);
    }
    return true;
}

bool same_file(const fs::path& a, const fs::path& b, std::error_code& ec) {
    sys::Stat sa, sb;
    if (!sys::lstat(a, sa, ec) || !sys::lstat(b, sb, ec)) return false;
    return sa.id == sb.id;
}

} // namespace bro::vfs
