#pragma once

#include "src/sys.h"

#include <functional>

namespace bro::vfs::detail {

struct WalkNode {
    fs::path path;        // root / rel
    fs::path rel;         // relative to the walked root
    std::string name;     // UTF-8 / raw bytes
    sys::Stat st;
    std::error_code stat_error;
    uint32_t depth = 0;   // 0 = child of root
    int64_t index = 0;    // pre-order sequence number
    int64_t parent = -1;  // index of the parent node, -1 for children of the root
};

struct WalkOptions {
    bool include_hidden = true;
    uint32_t max_depth = 0; // 0 = unlimited; 1 = root's children only
    // List the root through a link (a folder the user navigated into). Descendant links are
    // never followed regardless. Operations (copy/move/remove) leave this false.
    bool follow_root_link = false;
};

// Pre-order, depth-first, never following links. A directory that cannot be listed is
// reported to on_error and skipped; its siblings continue. Returns false if on_node asked to
// stop or the token was cancelled.
bool walk(const fs::path& root, const WalkOptions& options, const CancellationToken* token,
          const std::function<bool(const WalkNode&)>& on_node,
          const std::function<void(const fs::path&, const std::error_code&)>& on_error);

bool is_hidden(const std::string& name, const sys::Stat& st);
FileEntry make_entry(const fs::path& path, std::string name, const sys::Stat& st, uint32_t depth);

} // namespace bro::vfs::detail
