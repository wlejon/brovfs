#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "src/scanner_internal.h"
#include <vector>
#include <string>
#include <memory>

namespace bro::vfs::detail {

namespace {

std::wstring utf8_to_wide(std::string_view str) {
    if (str.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
    if (len <= 0) return L"";
    std::wstring result(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), result.data(), len);
    return result;
}

std::string wide_to_utf8(const wchar_t* wstr) {
    if (!wstr || !*wstr) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, result.data(), len - 1, nullptr, nullptr);
    return result;
}

int64_t filetime_to_epoch_ms(const FILETIME& ft) {
    constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL; // 100ns intervals between 1601 and 1970
    uint64_t val = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    if (val < EPOCH_DIFF) return 0;
    return static_cast<int64_t>((val - EPOCH_DIFF) / 10000ULL);
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

    std::string search_pattern = norm_path;
    if (search_pattern.back() != '/' && search_pattern.back() != '\\') {
        search_pattern += "/*";
    } else {
        search_pattern += "*";
    }

    std::wstring wide_pattern = utf8_to_wide(search_pattern);
    if (wide_pattern.size() >= 240 && wide_pattern.rfind(L"\\\\?\\", 0) != 0) {
        wide_pattern = L"\\\\?\\" + wide_pattern;
    }

    WIN32_FIND_DATAW find_data;
    HANDLE h_find = FindFirstFileExW(
        wide_pattern.c_str(),
        FindExInfoBasic,
        &find_data,
        FindExSearchNameMatch,
        nullptr,
        FIND_FIRST_EX_LARGE_FETCH
    );

    if (h_find == INVALID_HANDLE_VALUE) {
        return false;
    }

    std::vector<FileEntry> batch;
    batch.reserve(options.batch_size);

    std::vector<std::string> subdirectories;

    bool continue_scanning = true;

    do {
        if (token && token->is_cancelled()) {
            continue_scanning = false;
            break;
        }

        const wchar_t* filename_w = find_data.cFileName;
        if (wcscmp(filename_w, L".") == 0 || wcscmp(filename_w, L"..") == 0) {
            continue;
        }

        std::string filename = wide_to_utf8(filename_w);
        bool is_hidden = (find_data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0 ||
                         (!filename.empty() && filename[0] == '.');

        if (!options.include_hidden && is_hidden) {
            continue;
        }

        FileEntry entry;
        entry.name = filename;
        entry.path = join_path(norm_path, filename);
        entry.is_hidden = is_hidden;
        entry.permissions = find_data.dwFileAttributes;

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            entry.type = FileType::Symlink;
            entry.is_symlink = true;
            // On Windows reparse point can also be directory
            entry.is_directory = (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            entry.is_regular_file = !entry.is_directory;
        } else if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            entry.type = FileType::Directory;
            entry.is_directory = true;
        } else {
            entry.type = FileType::Regular;
            entry.is_regular_file = true;
        }

        entry.size = (static_cast<uint64_t>(find_data.nFileSizeHigh) << 32) | find_data.nFileSizeLow;
        entry.mtime_ms = filetime_to_epoch_ms(find_data.ftLastWriteTime);
        entry.birthtime_ms = filetime_to_epoch_ms(find_data.ftCreationTime);

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
    } while (FindNextFileW(h_find, &find_data));

    FindClose(h_find);

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

#endif // _WIN32
