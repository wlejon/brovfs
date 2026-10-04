#include "src/walk.h"

#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace bro::vfs::detail {

bool is_hidden(const std::string& name, const sys::Stat& st) {
#ifdef _WIN32
    (void)name;
    return (st.attributes & FILE_ATTRIBUTE_HIDDEN) != 0;
#else
    (void)st;
    return !name.empty() && name[0] == '.';
#endif
}

FileEntry make_entry(const fs::path& path, std::string name, const sys::Stat& st, uint32_t depth) {
    FileEntry e;
    e.path = path;
    e.name = std::move(name);
    e.kind = st.kind;
    e.is_hidden = is_hidden(e.name, st);
    e.link_is_directory = st.link_is_dir;
    e.size = st.size;
    e.mtime_ms = st.mtime_ns / 1000000;
    e.birthtime_ms = st.btime_ns / 1000000;
    e.mode = st.mode;
    e.attributes = st.attributes;
    e.nlink = st.nlink;
    e.depth = depth;
    e.id = st.id;
    return e;
}

bool walk(const fs::path& root, const WalkOptions& options, const CancellationToken* token,
          const std::function<bool(const WalkNode&)>& on_node,
          const std::function<void(const fs::path&, const std::error_code&)>& on_error) {
    struct Frame {
        fs::path path;
        fs::path rel;
        uint32_t depth;
        int64_t index;
        std::vector<sys::RawEntry> children;
        size_t next = 0;
    };
    int64_t counter = 0;
    std::vector<Frame> stack;

    auto open_frame = [&](const fs::path& path, const fs::path& rel, uint32_t depth, int64_t index,
                          const fs::path& list_path) {
        Frame f{path, rel, depth, index, {}, 0};
        std::error_code ec;
        bool ok = sys::list_dir(list_path, [&](sys::RawEntry&& e) {
            f.children.push_back(std::move(e));
            return !(token && token->is_cancelled());
        }, ec);
        if (!ok) {
            // Entries delivered before the error are still walked; the directory is reported
            // incomplete either way.
            on_error(path, ec);
        }
        stack.push_back(std::move(f));
    };

    fs::path root_list = root;
    if (options.follow_root_link) {
        sys::Stat rs;
        std::error_code ec;
        if (sys::lstat(root, rs, ec) && is_link(rs.kind)) {
            fs::path resolved = fs::canonical(root, ec);
            if (!ec) root_list = resolved;
        }
    }
    open_frame(root, fs::path(), 0, -1, root_list);
    while (!stack.empty()) {
        if (token && token->is_cancelled()) return false;
        Frame& top = stack.back();
        if (top.next >= top.children.size()) {
            stack.pop_back();
            continue;
        }
        sys::RawEntry& child = top.children[top.next++];
        if (!options.include_hidden && is_hidden(child.name_utf8, child.st)) continue;

        WalkNode node;
        node.path = top.path / child.name;
        node.rel = top.rel.empty() ? child.name : top.rel / child.name;
        node.name = std::move(child.name_utf8);
        node.st = child.st;
        node.stat_error = child.stat_error;
        node.depth = top.depth;
        node.index = counter++;
        node.parent = top.index;
        if (!on_node(node)) return false;

        bool descend = node.st.kind == FileKind::Directory && !node.stat_error &&
                       (options.max_depth == 0 || node.depth + 1 < options.max_depth);
        if (descend) open_frame(node.path, node.rel, node.depth + 1, node.index, node.path); // invalidates `top`
    }
    return !(token && token->is_cancelled());
}

} // namespace bro::vfs::detail
