#include "src/walk.h"

#include <algorithm>
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

std::atomic<size_t> g_dir_handle_budget{32};

namespace {
size_t budget() { return std::max<size_t>(2, g_dir_handle_budget.load(std::memory_order_relaxed)); }
} // namespace

bool reopen_dir(const fs::path& p, const FileId& expect, bool follow_leaf, sys::Dir& out, std::error_code& ec) {
    if (!sys::Dir::open(p, follow_leaf, out, ec)) {
        if (expect.valid && (sys::is_not_found(ec) || ec == std::errc::too_many_symbolic_link_levels ||
                             ec == std::errc::not_a_directory)) {
            ec = make_error_code(Errc::source_changed);
        }
        return false;
    }
    sys::Stat st;
    if (!out.stat(st, ec)) {
        out.close();
        return false;
    }
    if (expect.valid && !(st.id == expect)) {
        out.close();
        ec = make_error_code(Errc::source_changed);
        return false;
    }
    return true;
}

bool walk(const fs::path& root, const WalkOptions& options, const CancellationToken* token,
          const std::function<bool(const WalkNode&)>& on_node,
          const std::function<void(const fs::path&, const std::error_code&)>& on_error) {
    struct Frame {
        fs::path path;
        fs::path rel;
        uint32_t depth;
        int64_t index;
        FileId id;      // the identity this directory was opened with
        sys::Dir dir;   // closed when the frame is out of the handle budget
        std::vector<sys::RawEntry> children;
        size_t next = 0;
    };
    int64_t counter = 0;
    std::vector<Frame> stack;
    size_t open_handles = 0;
    size_t lowest_open = 0; // frames below this index have no handle

    auto open_frame = [&](const fs::path& path, const fs::path& rel, uint32_t depth, int64_t index, sys::Dir&& dir) {
        Frame f{path, rel, depth, index, {}, std::move(dir), {}, 0};
        std::error_code ec;
        sys::Stat st;
        if (f.dir.stat(st, ec)) f.id = st.id;
        bool ok = f.dir.list([&](sys::RawEntry&& e) {
            f.children.push_back(std::move(e));
            return !(token && token->is_cancelled());
        }, ec);
        if (!ok) {
            // Entries delivered before the error are still walked; the directory is reported
            // incomplete either way.
            on_error(path, ec);
        }
        stack.push_back(std::move(f));
        ++open_handles;
        lowest_open = std::min(lowest_open, stack.size() - 1);
        // Over budget: drop the handles nearest the root; they are reopened when needed.
        while (open_handles > budget() && lowest_open + 1 < stack.size()) {
            if (stack[lowest_open].dir.ok()) {
                stack[lowest_open].dir.close();
                --open_handles;
            }
            ++lowest_open;
        }
    };
    auto pop_frame = [&] {
        if (stack.back().dir.ok()) --open_handles;
        stack.pop_back();
        lowest_open = std::min(lowest_open, stack.size());
    };

    {
        sys::Dir rd;
        std::error_code ec;
        if (!sys::Dir::open(root, options.follow_root_link, rd, ec)) {
            on_error(root, ec);
            return !(token && token->is_cancelled());
        }
        open_frame(root, fs::path(), 0, -1, std::move(rd));
    }
    while (!stack.empty()) {
        if (token && token->is_cancelled()) return false;
        Frame& top = stack.back();
        if (top.next >= top.children.size()) {
            pop_frame();
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
        if (descend) {
            sys::Dir sub;
            std::error_code ec;
            if (!top.dir.ok()) {
                // Dropped for the budget: reopen it, and only if it is still this directory.
                const bool is_root = stack.size() == 1;
                if (reopen_dir(top.path, top.id, is_root && options.follow_root_link, top.dir, ec)) {
                    ++open_handles;
                    lowest_open = std::min(lowest_open, stack.size() - 1);
                } else {
                    on_error(node.path, ec);
                    continue;
                }
            }
            if (top.dir.open_child(child.name, &node.st.id, sub, ec)) {
                open_frame(node.path, node.rel, node.depth + 1, node.index, std::move(sub)); // invalidates `top`
            } else {
                on_error(node.path, ec);
            }
        }
    }
    return !(token && token->is_cancelled());
}

const sys::Dir* DirChain::get(int64_t index, std::error_code& ec, int64_t* failed) {
    if (failed) *failed = index;
    if (index < 0) {
        if (!root_.ok()) {
            ec = make_error_code(Errc::invalid_argument);
            return nullptr;
        }
        return &root_;
    }
    std::vector<int64_t> chain;
    for (int64_t i = index; i >= 0; i = parent_(i)) chain.push_back(i);
    std::reverse(chain.begin(), chain.end());
    size_t keep = 0;
    while (keep < stack_.size() && keep < chain.size() && stack_[keep].first == chain[keep]) ++keep;
    while (stack_.size() > keep) stack_.pop_back();
    if (!root_.ok()) {
        ec = make_error_code(Errc::invalid_argument);
        return nullptr;
    }
    // The deepest kept level may have been dropped for the budget: reopen it by path.
    if (keep > 0 && !stack_[keep - 1].second.ok()) {
        int64_t i = stack_[keep - 1].first;
        if (!reopen_dir(path_(i), id_(i), false, stack_[keep - 1].second, ec)) {
            if (failed) *failed = i;
            stack_.pop_back();
            return nullptr;
        }
    }
    for (size_t k = keep; k < chain.size(); ++k) {
        const sys::Dir& parent = k == 0 ? root_ : stack_[k - 1].second;
        sys::Dir d;
        FileId id = id_(chain[k]);
        if (!parent.open_child(name_(chain[k]), &id, d, ec)) {
            if (failed) *failed = chain[k];
            return nullptr;
        }
        stack_.emplace_back(chain[k], std::move(d));
        // Keep the root's handle and the deepest budget-1 levels; the next level down is opened
        // from the one just opened, so only levels above it can be dropped.
        const size_t keep_open = budget() - 1;
        if (stack_.size() > keep_open) stack_[stack_.size() - 1 - keep_open].second.close();
    }
    return &stack_.back().second;
}

} // namespace bro::vfs::detail
