// Permanent delete. Each root is planned with a no-follow walk; deletion then runs bottom-up
// over the plan through directory handles: every directory is reopened relative to its
// parent's handle and checked against its planned identity, and every object is deleted by
// name relative to its parent's handle after its identity is checked (on the object's own
// handle on Windows, by fstatat on POSIX). A directory swapped for a link after planning is
// refused rather than descended, and an ancestor swapped mid-operation cannot redirect a
// delete into another tree. Links are removed as links: a junction or directory symlink is
// never entered.
#include "src/engine.h"
#include "src/walk.h"

#include "brovfs/path.h"

#include <set>
#include <vector>

namespace bro::vfs::detail {

namespace {

struct Node {
    fs::path path;
    fs::path name;
    sys::Stat st;
    std::error_code stat_error;
    int64_t parent = -1;
    bool incomplete = false;
};

class Remover {
public:
    explicit Remover(Progress& p) : prog_(p) {}

    OpResult run(const std::vector<fs::path>& paths) {
        prog_.phase(Phase::Deleting);
        for (const auto& raw : paths) {
            if (prog_.stopped()) break;
            remove_root(strip_trailing_separators(raw));
        }
        finish_result(res_, prog_.stopped());
        return std::move(res_);
    }

private:
    void fail(const fs::path& p, std::error_code ec, const char* op) { res_.errors.push_back({p, {}, ec, op}); }

    bool delete_one(const sys::Dir& parent, const fs::path& name, const fs::path& p, const sys::Stat& st) {
        std::error_code ec;
        const bool is_dir = st.kind == FileKind::Directory;
        if (!parent.remove_child(name, is_dir, &st.id, ec)) {
            if (is_dir && sys::is_exists_error(ec)) {
                ec = std::make_error_code(std::errc::directory_not_empty); // entries appeared after planning
            }
            fail(p, ec, "delete");
            return false;
        }
        if (st.kind == FileKind::Regular) {
            ++res_.files_done;
            res_.bytes_done += st.size;
        } else if (is_dir) {
            ++res_.dirs_done;
        } else {
            ++res_.links_done;
        }
        return true;
    }

    void remove_root(const fs::path& root) {
        const fs::path leaf = leaf_name(root);
        if (leaf.empty() || leaf == "." || leaf == "..") {
            fail(root, make_error_code(Errc::invalid_argument), "delete");
            return;
        }
        sys::Stat rs;
        std::error_code ec;
        if (!sys::lstat(root, rs, ec)) {
            fail(root, ec, "stat");
            return;
        }
        // The root's parent is reached as the caller spelled it (links included); everything
        // below is reached through handles.
        sys::Dir parent;
        if (!sys::Dir::open(root.parent_path(), true, parent, ec)) {
            fail(root, ec, "open parent");
            return;
        }
        if (rs.kind != FileKind::Directory) {
            prog_.add_totals(rs.size, 1);
            if (!prog_.begin_item(root)) return;
            if (delete_one(parent, leaf, root, rs)) prog_.bytes(rs.size);
            prog_.end_item();
            return;
        }
        sys::Dir root_dir;
        if (!parent.open_child(leaf, &rs.id, root_dir, ec)) {
            fail(root, ec, "open");
            return;
        }

        std::vector<Node> nodes;
        bool root_incomplete = false;
        uint64_t total = 0;
        WalkOptions wo;
        walk(
            root, wo, nullptr,
            [&](const WalkNode& n) {
                nodes.push_back({n.path, n.path.filename(), n.st, n.stat_error, n.parent, false});
                total += n.st.size;
                return !prog_.stopped();
            },
            [&](const fs::path& p, const std::error_code& e) {
                fail(p, e, "scan");
                if (!nodes.empty() && nodes.back().path == p) {
                    nodes.back().incomplete = true;
                } else {
                    root_incomplete = true;
                }
            });
        if (prog_.stopped()) return;
        prog_.add_totals(total, nodes.size() + 1);

        DirChain chain(
            std::move(root_dir), [&](int64_t i) { return nodes[static_cast<size_t>(i)].parent; },
            [&](int64_t i) { return nodes[static_cast<size_t>(i)].name; },
            [&](int64_t i) { return nodes[static_cast<size_t>(i)].st.id; },
            [&](int64_t i) { return nodes[static_cast<size_t>(i)].path; });

        // Reverse pre-order visits every child before its parent.
        std::vector<char> blocked(nodes.size(), 0);
        std::set<int64_t> unopenable;
        bool root_blocked = root_incomplete;
        auto block_parent = [&](const Node& nd) {
            if (nd.parent < 0) {
                root_blocked = true;
            } else {
                blocked[static_cast<size_t>(nd.parent)] = 1;
            }
        };
        for (size_t k = nodes.size(); k-- > 0;) {
            Node& nd = nodes[k];
            if (prog_.stopped()) return;
            if (nd.stat_error) {
                fail(nd.path, nd.stat_error, "stat");
                block_parent(nd);
                continue;
            }
            if (nd.st.kind == FileKind::Directory && (blocked[k] || nd.incomplete)) {
                block_parent(nd); // a child failed: already reported, do not add an ENOTEMPTY
                continue;
            }
            if (!prog_.begin_item(nd.path)) return;
            const sys::Dir* pd = nullptr;
            if (!unopenable.count(nd.parent)) {
                std::error_code oec;
                int64_t bad = nd.parent;
                pd = chain.get(nd.parent, oec, &bad);
                if (!pd) {
                    // Report the directory that could not be opened once, not every child.
                    const bool fresh = !unopenable.count(bad);
                    unopenable.insert(nd.parent);
                    unopenable.insert(bad);
                    if (fresh) fail(bad < 0 ? root : nodes[static_cast<size_t>(bad)].path, oec, "open");
                }
            }
            if (!pd) {
                block_parent(nd);
                prog_.end_item();
                continue;
            }
            if (delete_one(*pd, nd.name, nd.path, nd.st)) {
                prog_.bytes(nd.st.size);
            } else {
                block_parent(nd);
            }
            prog_.end_item();
        }
        chain.close();
        if (root_blocked) return;
        if (!prog_.begin_item(root)) return;
        delete_one(parent, leaf, root, rs);
        prog_.end_item();
    }

    Progress& prog_;
    OpResult res_;
};

} // namespace

OpResult run_remove(const std::vector<fs::path>& paths, Progress& progress) {
    Remover r(progress);
    return r.run(paths);
}

} // namespace bro::vfs::detail
