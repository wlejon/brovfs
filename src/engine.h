#pragma once
// Internal operation engine shared by the public functions, the worker and the trash backends.

#include "brovfs/file_ops.h"
#include "src/sys.h"

#include <chrono>

namespace bro::vfs::detail {

class Progress {
public:
    Progress(const ProgressCallback* cb, const CancellationToken* token) : cb_(cb), token_(token) {
        start_ = std::chrono::steady_clock::now();
    }

    void phase(Phase p) {
        info_.phase = p;
        emit();
    }
    void add_totals(uint64_t bytes, uint64_t items) {
        info_.total_bytes += bytes;
        info_.total_items += items;
    }
    // Each returns false once the operation should stop (token cancelled or callback said no).
    bool begin_item(const fs::path& p) {
        info_.current_path = p;
        return emit();
    }
    bool bytes(uint64_t delta) {
        info_.bytes_processed += delta;
        return emit();
    }
    bool end_item() {
        ++info_.items_processed;
        return emit();
    }
    [[nodiscard]] bool stopped() const {
        return stopped_ || (token_ && token_->is_cancelled());
    }
    [[nodiscard]] const ProgressInfo& info() const { return info_; }

private:
    bool emit() {
        if (stopped()) return false;
        double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start_).count();
        if (elapsed > 0.0) {
            info_.speed_bytes_per_sec = static_cast<double>(info_.bytes_processed) / elapsed;
            info_.eta_seconds = info_.speed_bytes_per_sec > 0.0 && info_.total_bytes > info_.bytes_processed
                                    ? static_cast<double>(info_.total_bytes - info_.bytes_processed) /
                                          info_.speed_bytes_per_sec
                                    : 0.0;
        }
        if (cb_ && *cb_ && !(*cb_)(info_)) stopped_ = true;
        return !stopped();
    }

    const ProgressCallback* cb_;
    const CancellationToken* token_;
    ProgressInfo info_;
    std::chrono::steady_clock::time_point start_;
    bool stopped_ = false;
};

enum class TransferMode : uint8_t { Copy, Move };

struct TransferPair {
    fs::path src;
    fs::path dst; // exact destination path
};

OpResult run_transfer(TransferMode mode, const std::vector<TransferPair>& pairs, const FileOpOptions& options,
                      Progress& progress);

OpResult run_remove(const std::vector<fs::path>& paths, Progress& progress);

// Sets result.outcome from errors / work done / cancellation.
void finish_result(OpResult& r, bool cancelled);

fs::path unique_sibling(const fs::path& path, bool is_dir);

} // namespace bro::vfs::detail
