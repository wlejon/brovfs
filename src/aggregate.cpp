#include "brovfs/aggregate.h"

#include "brovfs/path.h"
#include "src/walk.h"

#include <condition_variable>
#include <mutex>
#include <set>
#include <thread>
#include <tuple>

namespace bro::vfs {

namespace {

class Aggregate final : public SelectionAggregate {
public:
    Aggregate(std::vector<fs::path> paths, AggregateProgress cb, AggregateOptions opt)
        : paths_(std::move(paths)), cb_(std::move(cb)), opt_(opt) {
        thread_ = std::thread([this] { run(); });
    }
    ~Aggregate() override {
        cancel();
        if (thread_.joinable()) thread_.join();
    }

    void cancel() override { token_.cancel(); }

    SelectionTotals totals() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return totals_;
    }

    SelectionTotals wait() override {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [&] { return totals_.finished || totals_.cancelled; });
        return totals_;
    }

    std::vector<ScanError> errors() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return errors_;
    }

private:
    void count(const sys::Stat& st, SelectionTotals& t) {
        switch (st.kind) {
            case FileKind::Regular:
                if (opt_.count_hard_links_once && st.nlink > 1 && st.id.valid) {
                    if (!seen_.insert(std::make_tuple(st.id.device, st.id.hi, st.id.lo)).second) return;
                }
                ++t.files;
                t.bytes += st.size;
                break;
            case FileKind::Directory: ++t.directories; break;
            case FileKind::Symlink:
            case FileKind::Junction: ++t.links; break;
            default: ++t.others; break;
        }
    }

    void error(const fs::path& p, const std::error_code& ec, SelectionTotals& t) {
        ++t.errors;
        std::lock_guard<std::mutex> lock(mutex_);
        if (errors_.size() < 100) errors_.push_back({p, ec});
    }

    // Publishes the local totals at most every progress_interval (always when `final`).
    void publish(const SelectionTotals& t, bool final) {
        auto now = std::chrono::steady_clock::now();
        if (!final && now - last_ < opt_.progress_interval) return;
        last_ = now;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            totals_ = t;
        }
        if (final) cv_.notify_all();
        if (cb_) cb_(t);
    }

    void run() {
        SelectionTotals t;
        detail::WalkOptions wo;
        wo.include_hidden = opt_.include_hidden;
        for (const auto& raw : paths_) {
            if (token_.is_cancelled()) break;
            fs::path p = strip_trailing_separators(raw);
            sys::Stat st;
            std::error_code ec;
            if (!sys::lstat(p, st, ec)) {
                error(p, ec, t);
                continue;
            }
            count(st, t);
            if (st.kind != FileKind::Directory) continue;
            detail::walk(
                p, wo, &token_,
                [&](const detail::WalkNode& n) {
                    if (n.stat_error) {
                        error(n.path, n.stat_error, t);
                    } else {
                        count(n.st, t);
                    }
                    publish(t, false);
                    return true;
                },
                [&](const fs::path& ep, const std::error_code& e) { error(ep, e, t); });
        }
        t.cancelled = token_.is_cancelled();
        t.finished = !t.cancelled;
        publish(t, true);
    }

    std::vector<fs::path> paths_;
    AggregateProgress cb_;
    AggregateOptions opt_;
    CancellationToken token_;
    std::set<std::tuple<uint64_t, uint64_t, uint64_t>> seen_;
    std::chrono::steady_clock::time_point last_{};
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    SelectionTotals totals_;
    std::vector<ScanError> errors_;
    std::thread thread_;
};

} // namespace

std::unique_ptr<SelectionAggregate> aggregate_selection(std::vector<fs::path> paths, AggregateProgress on_progress,
                                                        AggregateOptions options) {
    return std::make_unique<Aggregate>(std::move(paths), std::move(on_progress), options);
}

} // namespace bro::vfs
