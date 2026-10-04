#ifndef _WIN32

#include "src/scanner_internal.h"
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <string>

namespace bro::vfs::detail {

namespace {

int64_t timespec_to_epoch_ms(const struct timespec& ts) {
    return (static_cast<int64_t>(ts.tv_sec) * 1000) + (ts.tv_nsec / 1000000);
}

} // namespace

bool scan_directory_platform(
    const std::string& path,
    BatchCallback& callback,
    const ScanOptions& options,
    std::shared_ptr<CancellationToken> token,
    uint32_t current_depth)
{
    if (token && token->is_cancelled()) {
        return false;
    }

    std::string norm_path = normalize_path(path);
    if (norm_path.empty()) {
        return false;
    }

    DIR* dir = opendir(norm_path.c_str());
    if (!dir) {
        return false;
    }

    std::vector<FileEntry> batch;
    batch.reserve(options.batch_size);

    std::vector<std::string> subdirectories;
    bool continue_scanning = true;

    struct dirent* entry_ptr = nullptr;
    while ((entry_ptr = readdir(dir)) != nullptr) {
        if (token && token->is_cancelled()) {
            continue_scanning = false;
            break;
        }

        const char* name = entry_ptr->d_name;
        if (std::strcmp(name, ".") == 0 || std::strcmp(name, "..") == 0) {
            continue;
        }

        bool is_hidden = (name[0] == '.');
        if (!options.include_hidden && is_hidden) {
            continue;
        }

        FileEntry entry;
        entry.name = name;
        entry.path = join_path(norm_path, name);
        entry.is_hidden = is_hidden;

        // Try using d_type if available
        bool need_stat = false;
#ifdef DT_DIR
        switch (entry_ptr->d_type) {
            case DT_DIR:
                entry.type = FileType::Directory;
                entry.is_directory = true;
                break;
            case DT_REG:
                entry.type = FileType::Regular;
                entry.is_regular_file = true;
                break;
            case DT_LNK:
                entry.type = FileType::Symlink;
                entry.is_symlink = true;
                break;
            case DT_FIFO:
                entry.type = FileType::FIFO;
                break;
            case DT_SOCK:
                entry.type = FileType::Socket;
                break;
            case DT_CHR:
                entry.type = FileType::CharacterDevice;
                break;
            case DT_BLK:
                entry.type = FileType::BlockDevice;
                break;
            default:
                need_stat = true;
                break;
        }
#else
        need_stat = true;
#endif

        struct stat st;
        if (need_stat || lstat(entry.path.c_str(), &st) == 0) {
            if (need_stat && lstat(entry.path.c_str(), &st) != 0) {
                // If lstat fails, skip or mark unknown
                continue;
            }
            entry.size = static_cast<uint64_t>(st.st_size);
            entry.permissions = static_cast<uint32_t>(st.st_mode);

#if defined(__APPLE__)
            entry.mtime_ms = timespec_to_epoch_ms(st.st_mtimespec);
            entry.birthtime_ms = timespec_to_epoch_ms(st.st_birthtimespec);
#else
            entry.mtime_ms = timespec_to_epoch_ms(st.st_mtim);
            entry.birthtime_ms = timespec_to_epoch_ms(st.st_ctim);
#endif

            if (need_stat) {
                if (S_ISDIR(st.st_mode)) {
                    entry.type = FileType::Directory;
                    entry.is_directory = true;
                } else if (S_ISREG(st.st_mode)) {
                    entry.type = FileType::Regular;
                    entry.is_regular_file = true;
                } else if (S_ISLNK(st.st_mode)) {
                    entry.type = FileType::Symlink;
                    entry.is_symlink = true;
                } else if (S_ISFIFO(st.st_mode)) {
                    entry.type = FileType::FIFO;
                } else if (S_ISSOCK(st.st_mode)) {
                    entry.type = FileType::Socket;
                } else if (S_ISCHR(st.st_mode)) {
                    entry.type = FileType::CharacterDevice;
                } else if (S_ISBLK(st.st_mode)) {
                    entry.type = FileType::BlockDevice;
                }
            }
        }

        if (options.recursive && entry.is_directory) {
            if (!entry.is_symlink || options.follow_symlinks) {
                if (options.max_depth == 0 || current_depth + 1 <= options.max_depth) {
                    subdirectories.push_back(entry.path);
                }
            }
        }

        batch.push_back(std::move(entry));

        if (batch.size() >= options.batch_size) {
            if (!callback(std::move(batch))) {
                continue_scanning = false;
                break;
            }
            batch.clear();
            batch.reserve(options.batch_size);
        }
    }

    closedir(dir);

    if (continue_scanning && !batch.empty()) {
        if (!callback(std::move(batch))) {
            continue_scanning = false;
        }
    }

    if (continue_scanning && options.recursive) {
        for (const auto& subdir : subdirectories) {
            if (token && token->is_cancelled()) {
                return false;
            }
            if (!scan_directory_platform(subdir, callback, options, token, current_depth + 1)) {
                return false;
            }
        }
    }

    return continue_scanning;
}

} // namespace bro::vfs::detail

#endif // !_WIN32
