#include "brovfs/types.h"
#include <filesystem>
#include <algorithm>

namespace bro::vfs {

std::string_view file_type_to_string(FileType type) noexcept {
    switch (type) {
        case FileType::Regular:         return "regular";
        case FileType::Directory:       return "directory";
        case FileType::Symlink:         return "symlink";
        case FileType::BlockDevice:     return "block_device";
        case FileType::CharacterDevice: return "character_device";
        case FileType::FIFO:            return "fifo";
        case FileType::Socket:          return "socket";
        case FileType::Unknown:
        default:                        return "unknown";
    }
}

std::string_view op_status_to_string(OpStatus status) noexcept {
    switch (status) {
        case OpStatus::Pending:   return "pending";
        case OpStatus::Running:   return "running";
        case OpStatus::Paused:    return "paused";
        case OpStatus::Completed: return "completed";
        case OpStatus::Cancelled: return "cancelled";
        case OpStatus::Failed:    return "failed";
        default:                  return "unknown";
    }
}

std::string normalize_path(std::string_view path) {
    if (path.empty()) {
        return "";
    }
    std::filesystem::path p(path);
    std::string s = p.lexically_normal().generic_string();
    // Strip trailing slash unless it's the root directory (e.g. "/" or "C:/")
    if (s.size() > 1 && s.back() == '/' && (s.size() != 3 || s[1] != ':')) {
        s.pop_back();
    }
    return s;
}

std::string join_path(std::string_view parent, std::string_view child) {
    if (parent.empty()) return std::string(child);
    if (child.empty()) return std::string(parent);

    std::filesystem::path p(parent);
    p /= child;
    return p.lexically_normal().generic_string();
}

std::string get_file_name(std::string_view path) {
    std::filesystem::path p(path);
    return p.filename().generic_string();
}

std::string get_parent_path(std::string_view path) {
    std::filesystem::path p(path);
    return p.parent_path().generic_string();
}

std::string get_file_extension(std::string_view path) {
    std::filesystem::path p(path);
    return p.extension().generic_string();
}

std::string get_stem(std::string_view path) {
    std::filesystem::path p(path);
    return p.stem().generic_string();
}

} // namespace bro::vfs
