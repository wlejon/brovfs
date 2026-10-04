#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace bro::vfs {

enum class FileType : uint8_t {
    Unknown = 0,
    Regular,
    Directory,
    Symlink,
    BlockDevice,
    CharacterDevice,
    FIFO,
    Socket
};

[[nodiscard]] std::string_view file_type_to_string(FileType type) noexcept;

struct FileEntry {
    std::string name;
    std::string path;
    FileType type = FileType::Unknown;
    bool is_directory = false;
    bool is_regular_file = false;
    bool is_symlink = false;
    bool is_hidden = false;
    uint64_t size = 0;
    int64_t mtime_ms = 0;      // Milliseconds since Unix epoch
    int64_t birthtime_ms = 0;  // Milliseconds since Unix epoch (creation time)
    uint32_t permissions = 0;  // POSIX mode bits or Windows attribute flags
    std::string symlink_target;
};

enum class ConflictResolution : uint8_t {
    Overwrite = 0,
    Skip,
    AutoRename,
    KeepNewer
};

enum class OpType : uint8_t {
    Copy = 0,
    Move,
    Delete
};

enum class OpStatus : uint8_t {
    Pending = 0,
    Running,
    Paused,
    Completed,
    Cancelled,
    Failed
};

[[nodiscard]] std::string_view op_status_to_string(OpStatus status) noexcept;

struct ProgressInfo {
    uint64_t bytes_processed = 0;
    uint64_t total_bytes = 0;
    uint64_t files_processed = 0;
    uint64_t total_files = 0;
    double speed_bytes_per_sec = 0.0;
    double eta_seconds = 0.0;
    std::string current_file;

    [[nodiscard]] double fraction() const noexcept {
        return total_bytes > 0 ? static_cast<double>(bytes_processed) / static_cast<double>(total_bytes) : 1.0;
    }

    [[nodiscard]] double speed_mb_s() const noexcept {
        return speed_bytes_per_sec / (1024.0 * 1024.0);
    }
};

class CancellationToken {
public:
    CancellationToken() : cancelled_(false) {}
    explicit CancellationToken(bool initial) : cancelled_(initial) {}

    void cancel() noexcept {
        cancelled_.store(true, std::memory_order_release);
    }

    [[nodiscard]] bool is_cancelled() const noexcept {
        return cancelled_.load(std::memory_order_acquire);
    }

    void reset() noexcept {
        cancelled_.store(false, std::memory_order_release);
    }

private:
    std::atomic<bool> cancelled_;
};

// Path helpers
[[nodiscard]] std::string normalize_path(std::string_view path);
[[nodiscard]] std::string join_path(std::string_view parent, std::string_view child);
[[nodiscard]] std::string get_file_name(std::string_view path);
[[nodiscard]] std::string get_parent_path(std::string_view path);
[[nodiscard]] std::string get_file_extension(std::string_view path);
[[nodiscard]] std::string get_stem(std::string_view path);

} // namespace bro::vfs
