#pragma once

#include "src/sys.h"

#include <functional>
#include <utility>
#include <vector>

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

// Pre-order, depth-first, never following links. Each directory is opened relative to its
// parent's open handle and checked against the identity it was listed with, so a directory
// swapped for a link (or another tree) mid-walk is refused, not entered. A directory that
// cannot be opened or listed is reported to on_error (right after its own on_node) and
// skipped; its siblings continue. Returns false if on_node asked to stop or the token was
// cancelled.
//
// Handles are bounded: at most g_dir_handle_budget directories stay open however deep the
// tree. An ancestor whose handle was dropped is reopened by path when it is needed again and
// accepted only if it is still the directory planned (same identity), which keeps the
// guarantee above at the cost of a path open.
bool walk(const fs::path& root, const WalkOptions& options, const CancellationToken* token,
          const std::function<bool(const WalkNode&)>& on_node,
          const std::function<void(const fs::path&, const std::error_code&)>& on_error);

// Open directory handles along the current path of a planned tree (nodes in pre-order, each
// with its parent's index, -1 for the root). Each is opened relative to its parent's handle and
// checked against the planned identity, so acting on a child through get(parent) can never be
// redirected by an ancestor swapped after planning. At most g_dir_handle_budget handles stay
// open (the root's and the deepest ones); a dropped level is reopened by its path (`path`) and
// identity-checked when the chain climbs back to it.
class DirChain {
public:
    using ParentOf = std::function<int64_t(int64_t)>;
    using NameOf = std::function<fs::path(int64_t)>;
    using IdOf = std::function<FileId(int64_t)>;
    using PathOf = std::function<fs::path(int64_t)>;

    DirChain(sys::Dir root, ParentOf parent, NameOf name, IdOf id, PathOf path)
        : root_(std::move(root)), parent_(std::move(parent)), name_(std::move(name)), id_(std::move(id)),
          path_(std::move(path)) {}

    // The open directory for node `index` (-1: the root); null with `ec` set on failure, and
    // `failed` (if given) set to the node whose directory could not be opened.
    const sys::Dir* get(int64_t index, std::error_code& ec, int64_t* failed = nullptr);
    // Closes every handle (the root's too); get() fails afterwards.
    void close() {
        stack_.clear();
        root_.close();
    }

private:
    sys::Dir root_;
    ParentOf parent_;
    NameOf name_;
    IdOf id_;
    PathOf path_;
    std::vector<std::pair<int64_t, sys::Dir>> stack_; // handles below the deepest `budget` are closed
};

// The most directory handles one traversal keeps open (default 32; tests lower it).
extern std::atomic<size_t> g_dir_handle_budget;

// Opens directory `p` again and accepts it only if it is `expect` (source_changed otherwise).
bool reopen_dir(const fs::path& p, const FileId& expect, bool follow_leaf, sys::Dir& out, std::error_code& ec);

bool is_hidden(const std::string& name, const sys::Stat& st);
FileEntry make_entry(const fs::path& path, std::string name, const sys::Stat& st, uint32_t depth);

} // namespace bro::vfs::detail
