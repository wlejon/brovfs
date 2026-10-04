#include "brovfs/trash_freedesktop.h"
#include "brovfs/types.h"
#include "brovfs/file_ops.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>

namespace bro::vfs {

namespace fs = std::filesystem;

namespace {

// Percent-encoding / decoding for RFC 2396
std::string url_encode(std::string_view str) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : str) {
        // Keep alphanumeric and other accepted characters unescaped
        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    return escaped.str();
}

std::string url_decode(std::string_view str) {
    std::string result;
    result.reserve(str.size());

    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '%' && i + 2 < str.size()) {
            int val = 0;
            std::istringstream hex_stream(std::string(str.substr(i + 1, 2)));
            if (hex_stream >> std::hex >> val) {
                result.push_back(static_cast<char>(val));
                i += 2;
                continue;
            }
        }
        result.push_back(str[i]);
    }
    return result;
}

std::string get_iso8601_now() {
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &tt);
#else
    gmtime_r(&tt, &tm_buf);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    return std::string(buf);
}

int64_t parse_iso8601_to_ms(std::string_view iso_str) {
    std::tm tm_buf{};
    std::string s_iso(iso_str);
    std::istringstream ss(s_iso);
    char dash1, dash2, t_char, col1, col2;
    int year, month, day, hour, min, sec;
    if (ss >> year >> dash1 >> month >> dash2 >> day >> t_char >> hour >> col1 >> min >> col2 >> sec) {
        tm_buf.tm_year = year - 1900;
        tm_buf.tm_mon = month - 1;
        tm_buf.tm_mday = day;
        tm_buf.tm_hour = hour;
        tm_buf.tm_min = min;
        tm_buf.tm_sec = sec;
#ifdef _WIN32
        std::time_t t = _mkgmtime(&tm_buf);
#else
        std::time_t t = timegm(&tm_buf);
#endif
        if (t != static_cast<std::time_t>(-1)) {
            return static_cast<int64_t>(t) * 1000;
        }
    }
    return 0;
}

std::string default_xdg_trash_dir() {
    const char* xdg_data_home = std::getenv("XDG_DATA_HOME");
    if (xdg_data_home && *xdg_data_home) {
        return (fs::path(xdg_data_home) / "Trash").generic_string();
    }
    const char* home = std::getenv("HOME");
    if (home && *home) {
        return (fs::path(home) / ".local" / "share" / "Trash").generic_string();
    }
#ifdef _WIN32
    const char* userprofile = std::getenv("USERPROFILE");
    if (userprofile && *userprofile) {
        return (fs::path(userprofile) / ".local" / "share" / "Trash").generic_string();
    }
#endif
    return "./.Trash";
}

} // namespace

FreeDesktopTrash::FreeDesktopTrash(std::string trash_dir)
    : trash_dir_(trash_dir.empty() ? default_xdg_trash_dir() : normalize_path(trash_dir))
{
    ensure_directories_exist();
}

std::string FreeDesktopTrash::get_files_dir() const {
    return join_path(trash_dir_, "files");
}

std::string FreeDesktopTrash::get_info_dir() const {
    return join_path(trash_dir_, "info");
}

void FreeDesktopTrash::ensure_directories_exist() {
    std::error_code ec;
    fs::create_directories(get_files_dir(), ec);
    fs::create_directories(get_info_dir(), ec);
}

std::string FreeDesktopTrash::allocate_trash_id(const std::string& original_filename) {
    ensure_directories_exist();
    std::string files_dir = get_files_dir();
    std::string info_dir = get_info_dir();

    fs::path base_p(original_filename);
    std::string stem = base_p.stem().generic_string();
    std::string ext = base_p.extension().generic_string();

    std::string candidate = original_filename;
    std::error_code ec;

    if (!fs::exists(fs::path(files_dir) / candidate, ec) &&
        !fs::exists(fs::path(info_dir) / (candidate + ".trashinfo"), ec)) {
        return candidate;
    }

    for (uint32_t i = 2; i < 1000000; ++i) {
        candidate = stem + "." + std::to_string(i) + ext;
        if (!fs::exists(fs::path(files_dir) / candidate, ec) &&
            !fs::exists(fs::path(info_dir) / (candidate + ".trashinfo"), ec)) {
            return candidate;
        }
    }
    return original_filename + "." + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
}

bool FreeDesktopTrash::trash_path(const std::string& path, std::string* out_id) {
    ensure_directories_exist();

    fs::path p(path);
    std::error_code ec;
    if (!fs::exists(p, ec)) {
        return false;
    }

    fs::path abs_path = fs::absolute(p, ec);
    if (ec) abs_path = p;
    std::string abs_path_str = abs_path.generic_string();
    std::string filename = p.filename().generic_string();

    std::string trash_id = allocate_trash_id(filename);
    std::string dest_file_path = join_path(get_files_dir(), trash_id);
    std::string dest_info_path = join_path(get_info_dir(), trash_id + ".trashinfo");

    // Write .trashinfo file
    std::ofstream info_file(dest_info_path, std::ios::trunc);
    if (!info_file.is_open()) {
        return false;
    }

    info_file << "[Trash Info]\n";
    info_file << "Path=" << url_encode(abs_path_str) << "\n";
    info_file << "DeletionDate=" << get_iso8601_now() << "\n";
    info_file.close();

    // Move file/dir into files/
    if (!move_path(abs_path_str, dest_file_path)) {
        fs::remove(dest_info_path, ec);
        return false;
    }

    if (out_id) {
        *out_id = trash_id;
    }
    return true;
}

std::vector<TrashItem> FreeDesktopTrash::list_trash() {
    ensure_directories_exist();
    std::vector<TrashItem> items;
    std::string info_dir = get_info_dir();
    std::string files_dir = get_files_dir();

    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(info_dir, ec)) {
        if (!entry.is_regular_file(ec)) continue;

        std::string filename = entry.path().filename().generic_string();
        constexpr std::string_view suffix = ".trashinfo";
        if (filename.size() <= suffix.size() ||
            filename.compare(filename.size() - suffix.size(), suffix.size(), suffix) != 0) {
            continue;
        }

        std::string id = filename.substr(0, filename.size() - suffix.size());
        std::string actual_file = join_path(files_dir, id);

        std::ifstream f(entry.path());
        if (!f.is_open()) continue;

        std::string line;
        std::string original_path;
        std::string deletion_date;

        while (std::getline(f, line)) {
            if (line.starts_with("Path=")) {
                original_path = url_decode(line.substr(5));
            } else if (line.starts_with("DeletionDate=")) {
                deletion_date = line.substr(13);
            }
        }

        TrashItem item;
        item.id = id;
        item.original_path = original_path;
        item.current_path = actual_file;
        item.deletion_time_ms = parse_iso8601_to_ms(deletion_date);

        fs::path f_path(actual_file);
        if (fs::exists(f_path, ec)) {
            item.is_directory = fs::is_directory(f_path, ec);
            if (item.is_directory) {
                // Approximate directory size
                item.size = 0;
            } else {
                item.size = fs::file_size(f_path, ec);
            }
        }

        items.push_back(std::move(item));
    }

    return items;
}

bool FreeDesktopTrash::restore_item(const std::string& id) {
    ensure_directories_exist();
    std::string info_path = join_path(get_info_dir(), id + ".trashinfo");
    std::string file_path = join_path(get_files_dir(), id);

    std::error_code ec;
    if (!fs::exists(fs::path(info_path), ec) || !fs::exists(fs::path(file_path), ec)) {
        return false;
    }

    std::ifstream f(info_path);
    if (!f.is_open()) return false;

    std::string line;
    std::string original_path;
    while (std::getline(f, line)) {
        if (line.starts_with("Path=")) {
            original_path = url_decode(line.substr(5));
            break;
        }
    }
    f.close();

    if (original_path.empty()) {
        return false;
    }

    fs::path orig_p(original_path);
    if (orig_p.has_parent_path()) {
        fs::create_directories(orig_p.parent_path(), ec);
    }

    if (!move_path(file_path, original_path)) {
        return false;
    }

    fs::remove(info_path, ec);
    return true;
}

bool FreeDesktopTrash::delete_item(const std::string& id) {
    ensure_directories_exist();
    std::string info_path = join_path(get_info_dir(), id + ".trashinfo");
    std::string file_path = join_path(get_files_dir(), id);

    delete_path(file_path);
    std::error_code ec;
    fs::remove(info_path, ec);
    return true;
}

bool FreeDesktopTrash::empty_trash() {
    ensure_directories_exist();
    delete_path(get_files_dir());
    delete_path(get_info_dir());
    ensure_directories_exist();
    return true;
}

} // namespace bro::vfs
