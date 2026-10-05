#pragma once
// Read-only parser for Finder's .DS_Store (the "Bud1" buddy-allocated B-tree of records), used
// to find Finder's own put-back data for items in a macOS trash folder:
//   ptbL  ustr  put-back location: the original parent, relative to the volume root
//               ("Users/j/Desktop/")
//   ptbN  ustr  put-back name: the original name, when the trash renamed the item
// Records are keyed by the item's name in the trash folder. Pure parsing: compiled on every
// platform so it is tested everywhere against a fixture written by an independent library.

#include <filesystem>
#include <map>
#include <string>
#include <system_error>
#include <vector>

namespace bro::vfs::detail {

struct FinderPutBack {
    std::string location; // ptbL, UTF-8, relative to the volume root
    std::string name;     // ptbN, UTF-8; empty = the item's current name
};

// Every record of the file as (item name, code, type) with string values decoded; values of
// other types are skipped. Fails with errc::illegal_byte_sequence on a malformed file.
struct DsRecord {
    std::string item;  // UTF-8
    std::string code;  // 4 characters
    std::string type;  // 4 characters
    std::string text;  // ustr value as UTF-8, else empty
};

bool read_ds_store(const std::vector<unsigned char>& data, std::vector<DsRecord>& out, std::error_code& ec);

// Put-back records of a trash folder's .DS_Store, keyed by item name.
bool read_finder_putback(const std::filesystem::path& ds_store, std::map<std::string, FinderPutBack>& out,
                         std::error_code& ec);

} // namespace bro::vfs::detail
