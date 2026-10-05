// shared-mime-info: globs2 (or globs), aliases and subclasses from ".../share/mime" directories.
// Pure text parsing, so it builds and is tested on every OS; MimeDatabase::system() uses it on
// Linux.
#include "src/mime_db.h"

#include <fstream>
#include <string>
#include <unordered_set>

namespace bro::vfs {

namespace {

using detail::TableDatabase;
using detail::TypeTable;

struct TableHolder {
    TypeTable table;
};

class SmiDatabase : private TableHolder, public TableDatabase {
public:
    SmiDatabase() : TableDatabase("shared-mime-info", &table) {}
    TypeTable& mutable_table() { return table; }
};

std::vector<std::string> split(const std::string& line, char sep) {
    std::vector<std::string> out;
    size_t start = 0;
    while (true) {
        size_t at = line.find(sep, start);
        out.push_back(line.substr(start, at == std::string::npos ? std::string::npos : at - start));
        if (at == std::string::npos) break;
        start = at + 1;
    }
    return out;
}

bool read_lines(const std::filesystem::path& file, std::vector<std::string>& lines) {
    std::ifstream in(file, std::ios::binary);
    if (!in.is_open()) return false;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        lines.push_back(std::move(line));
    }
    return true;
}

// Globs of one directory. Types a higher-priority directory marked __NOGLOBS__ are skipped.
bool load_globs(const std::filesystem::path& dir, TypeTable& table,
                const std::unordered_set<std::string>& suppressed, std::unordered_set<std::string>& noglobs) {
    std::vector<std::string> lines;
    bool v2 = read_lines(dir / "globs2", lines);
    if (!v2 && !read_lines(dir / "globs", lines)) return false;
    for (const auto& line : lines) {
        auto f = split(line, ':');
        int weight = 50;
        std::string mime, pattern;
        bool cs = false;
        if (v2) {
            if (f.size() < 3) continue;
            try {
                weight = std::stoi(f[0]);
            } catch (...) {
                continue;
            }
            mime = f[1];
            pattern = f[2];
            if (f.size() > 3) {
                for (const auto& flag : split(f[3], ',')) cs = cs || flag == "cs";
            }
        } else {
            if (f.size() < 2) continue;
            mime = f[0];
            pattern = f[1];
        }
        std::string m = detail::ascii_lower(mime);
        if (pattern == "__NOGLOBS__") {
            noglobs.insert(m);
            continue;
        }
        if (suppressed.contains(m)) continue;
        table.add_glob(pattern, mime, weight, cs);
    }
    return true;
}

} // namespace

std::unique_ptr<MimeDatabase> MimeDatabase::load_shared_mime_info(const std::vector<std::filesystem::path>& mime_dirs,
                                                                  std::error_code& ec) {
    ec.clear();
    auto db = std::make_unique<SmiDatabase>();
    TypeTable& table = db->mutable_table();
    std::unordered_set<std::string> suppressed;
    bool any = false;
    for (const auto& dir : mime_dirs) {
        std::unordered_set<std::string> noglobs;
        any = load_globs(dir, table, suppressed, noglobs) || any;
        suppressed.insert(noglobs.begin(), noglobs.end());

        std::vector<std::string> lines;
        if (read_lines(dir / "aliases", lines)) {
            for (const auto& l : lines) {
                auto f = split(l, ' ');
                if (f.size() >= 2) table.add_alias(f[0], f[1]); // first (highest priority) wins
            }
        }
        lines.clear();
        if (read_lines(dir / "subclasses", lines)) {
            for (const auto& l : lines) {
                auto f = split(l, ' ');
                if (f.size() >= 2) table.add_parent(f[0], f[1]);
            }
        }
    }
    if (!any) {
        ec = std::make_error_code(std::errc::no_such_file_or_directory);
        return nullptr;
    }
    return db;
}

} // namespace bro::vfs
