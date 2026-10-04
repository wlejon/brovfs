// Copy and move. The source tree is planned first (a no-follow walk that records every
// object's kind, size, mtime and identity); execution works from that model:
//   * every non-directory is staged under a temp name in the destination directory and
//     committed with a rename (no-replace unless the decision was Overwrite);
//   * conflicts are decided per item before any data is written, by policy or resolver;
//   * a move renames when it can, and only a cross-device error falls back to copying; each
//     source object is then deleted only after its copy is committed and flushed and the
//     source still matches the plan. Source directories are removed with rmdir, so anything
//     not moved (failed, skipped, appeared meanwhile) keeps its directory alive.
#include "src/engine.h"
#include "src/walk.h"

#include "brovfs/path.h"

#include <string>
#include <vector>

namespace bro::vfs::detail {

namespace {

enum class ItemState : uint8_t { Pending = 0, Done, Skipped, Failed };

struct Resolution {
    enum Act : uint8_t { Write = 0, Overwrite, Skip, Abort, Fail } act = Write;
    fs::path dst;
    std::error_code ec;
};

class Transfer {
public:
    Transfer(TransferMode mode, const FileOpOptions& options, Progress& progress)
        : mode_(mode), opt_(options), prog_(progress) {}

    OpResult run(const std::vector<TransferPair>& pairs) {
        prog_.phase(mode_ == TransferMode::Copy ? Phase::Copying : Phase::Moving);
        for (const auto& pair : pairs) {
            if (stop()) break;
            run_root(pair);
        }
        finish_result(res_, stop());
        return std::move(res_);
    }

private:
    bool stop() const { return abort_ || prog_.stopped(); }

    void fail(const fs::path& s, const fs::path& d, std::error_code ec, const char* op) {
        res_.errors.push_back({s, d, ec, op});
    }

    void count(const sys::Stat& st) {
        if (st.kind == FileKind::Regular) {
            ++res_.files_done;
        } else if (st.kind == FileKind::Directory) {
            ++res_.dirs_done;
        } else {
            ++res_.links_done;
        }
    }

    Resolution resolve(ConflictKind kind, const fs::path& src, const sys::Stat& ss, const fs::path& dst,
                       const sys::Stat& ds) {
        Conflict c;
        c.kind = kind;
        c.source = src;
        c.destination = dst;
        c.source_kind = ss.kind;
        c.destination_kind = ds.kind;
        c.source_size = ss.size;
        c.destination_size = ds.size;
        c.source_mtime_ms = ss.mtime_ns / 1000000;
        c.destination_mtime_ms = ds.mtime_ns / 1000000;
        ConflictAction a = ConflictAction::Skip;
        switch (opt_.conflict) {
            case ConflictPolicy::Ask:
                if (!opt_.on_conflict) return {Resolution::Fail, dst, make_error_code(Errc::conflict_unresolved)};
                a = opt_.on_conflict(c);
                break;
            case ConflictPolicy::Overwrite: a = ConflictAction::Overwrite; break;
            case ConflictPolicy::Skip: a = ConflictAction::Skip; break;
            case ConflictPolicy::KeepBoth: a = ConflictAction::KeepBoth; break;
            case ConflictPolicy::KeepNewer:
                a = ss.mtime_ns > ds.mtime_ns ? ConflictAction::Overwrite : ConflictAction::Skip;
                break;
        }
        switch (a) {
            case ConflictAction::Overwrite:
                if (kind == ConflictKind::SameFile) return {Resolution::Fail, dst, make_error_code(Errc::same_file)};
                if (kind == ConflictKind::TypeMismatch) {
                    return {Resolution::Fail, dst, make_error_code(Errc::type_mismatch)};
                }
                return {Resolution::Overwrite, dst, {}};
            case ConflictAction::Skip: return {Resolution::Skip, dst, {}};
            case ConflictAction::KeepBoth:
                return {Resolution::Write, unique_sibling(dst, ss.kind == FileKind::Directory), {}};
            case ConflictAction::Abort: abort_ = true; return {Resolution::Abort, dst, {}};
        }
        return {Resolution::Skip, dst, {}};
    }

    static ConflictKind classify(const sys::Stat& ss, const sys::Stat& ds) {
        if (ss.id == ds.id) return ConflictKind::SameFile;
        bool sd = ss.kind == FileKind::Directory, dd = ds.kind == FileKind::Directory;
        return sd != dd ? ConflictKind::TypeMismatch : ConflictKind::Exists;
    }

    // Would `dst` land inside the source directory (or be it)? Resolved on the real path of
    // the nearest existing ancestor, so an alias (symlink / junction into the source) is seen.
    static bool dest_inside_source(const sys::Stat& ss, const fs::path& dst) {
        std::error_code ec;
        fs::path p = fs::absolute(dst, ec);
        if (ec) p = dst;
        sys::Stat st;
        for (;;) {
            std::error_code sec;
            if (sys::stat_follow(p, st, sec)) break;
            fs::path parent = p.parent_path();
            if (parent.empty() || parent == p) return false;
            p = parent;
        }
        fs::path real = fs::canonical(p, ec);
        if (ec) real = p;
        for (fs::path q = real;;) {
            std::error_code sec;
            if (sys::stat_follow(q, st, sec) && st.id == ss.id) return true;
            fs::path parent = q.parent_path();
            if (parent.empty() || parent == q) return false;
            q = parent;
        }
    }

    // The rename a move tries first; the test hook can force the cross-device fallback here.
    static bool move_rename(const fs::path& from, const fs::path& to, bool replace, std::error_code& ec) {
        if (sys::g_force_cross_device.load()) {
            ec = sys::cross_device_error();
            return false;
        }
        return replace ? sys::rename_replace(from, to, ec) : sys::rename_noreplace(from, to, ec);
    }

    void run_root(const TransferPair& pair) {
        fs::path src = strip_trailing_separators(pair.src);
        fs::path dst = strip_trailing_separators(pair.dst);
        if (leaf_name(src).empty() || leaf_name(dst).empty()) {
            fail(src, dst, make_error_code(Errc::invalid_argument), "plan");
            return;
        }
        sys::Stat ss;
        std::error_code ec;
        if (!sys::lstat(src, ss, ec)) {
            fail(src, dst, ec, "stat");
            return;
        }
        sys::Stat ds;
        std::error_code dec;
        bool dst_exists = sys::lstat(dst, ds, dec);
        if (dst_exists && ds.id == ss.id) {
            if (mode_ == TransferMode::Move && sys::is_case_variant(src, dst)) {
                // Case-only rename on a case-insensitive volume.
                if (sys::rename_noreplace(src, dst, ec)) {
                    count(ss);
                    res_.created.push_back(dst);
                } else {
                    fail(src, dst, ec, "rename");
                }
                return;
            }
            if (mode_ == TransferMode::Move) {
                fail(src, dst, make_error_code(Errc::same_file), "move");
                return;
            }
            Resolution r = resolve(ConflictKind::SameFile, src, ss, dst, ds);
            if (r.act == Resolution::Skip) {
                ++res_.skipped;
                return;
            }
            if (r.act == Resolution::Fail) fail(src, dst, r.ec, "conflict");
            if (r.act != Resolution::Write) return;
            dst = r.dst;
        }
        if (ss.kind == FileKind::Directory && dest_inside_source(ss, dst)) {
            fail(src, dst, make_error_code(Errc::destination_inside_source), "plan");
            return;
        }
        if (mode_ == TransferMode::Copy) {
            copy_tree(src, ss, dst, false, false, true);
        } else {
            move_root(src, ss, dst, true);
        }
    }

    // ------------------------------------------------------------ move by rename

    void move_root(const fs::path& src, const sys::Stat& ss, fs::path dst, bool top) {
        for (int attempt = 0; attempt < 8; ++attempt) {
            if (stop()) return;
            sys::Stat ds;
            std::error_code ec;
            bool exists = sys::lstat(dst, ds, ec);
            if (!exists && !sys::is_not_found(ec)) {
                fail(src, dst, ec, "stat");
                return;
            }
            if (!exists) {
                if (!prog_.begin_item(src)) return;
                if (move_rename(src, dst, false, ec)) {
                    count(ss);
                    if (top) res_.created.push_back(dst);
                    prog_.add_totals(0, 1);
                    prog_.end_item();
                    return;
                }
                if (sys::is_cross_device(ec)) {
                    copy_tree(src, ss, dst, true, false, top);
                    return;
                }
                if (sys::is_exists_error(ec)) continue; // appeared meanwhile: decide again
                fail(src, dst, ec, "rename");
                return;
            }
            if (ds.id == ss.id) {
                fail(src, dst, make_error_code(Errc::same_file), "move");
                return;
            }
            if (ss.kind == FileKind::Directory && ds.kind == FileKind::Directory) {
                merge_move(src, ss, dst);
                return;
            }
            Resolution r = resolve(classify(ss, ds), src, ss, dst, ds);
            switch (r.act) {
                case Resolution::Skip: ++res_.skipped; return;
                case Resolution::Abort: return;
                case Resolution::Fail: fail(src, dst, r.ec, "conflict"); return;
                case Resolution::Write: dst = r.dst; continue;
                case Resolution::Overwrite:
                    if (!prog_.begin_item(src)) return;
                    if (move_rename(src, dst, true, ec)) {
                        count(ss);
                        if (top) res_.created.push_back(dst);
                        prog_.add_totals(0, 1);
                        prog_.end_item();
                        return;
                    }
                    if (sys::is_cross_device(ec)) {
                        copy_tree(src, ss, dst, true, true, top);
                        return;
                    }
                    fail(src, dst, ec, "rename");
                    return;
            }
        }
        fail(src, dst, make_error_code(Errc::conflict_unresolved), "move");
    }

    // Destination directory exists: move each child into it, then rmdir the source if empty.
    void merge_move(const fs::path& src, const sys::Stat& ss, const fs::path& dst) {
        std::vector<sys::RawEntry> children;
        std::error_code ec;
        if (!sys::list_dir(src, [&](sys::RawEntry&& e) { children.push_back(std::move(e)); return true; }, ec)) {
            fail(src, {}, ec, "scan");
            return;
        }
        bool all_moved = true;
        for (auto& c : children) {
            if (stop()) return;
            fs::path cs = src / c.name;
            if (c.stat_error) {
                fail(cs, {}, c.stat_error, "stat");
                all_moved = false;
                continue;
            }
            move_root(cs, c.st, dst / c.name, false);
            if (sys::exists_nofollow(cs)) all_moved = false;
        }
        if (!all_moved || stop()) return;
        if (!sys::remove_dir(src, ec, &ss.id)) {
            fail(src, {}, sys::is_exists_error(ec) ? make_error_code(Errc::directory_not_empty_after_move) : ec,
                 "remove source");
        }
    }

    // ------------------------------------------------------------ copy (and cross-device move)

    // Copy content of one non-directory into a temp sibling of `tmp`'s final name.
    bool stage(const fs::path& src, const sys::Stat& st, const fs::path& tmp, const fs::path& dst, bool remove_source) {
        std::error_code ec;
        switch (st.kind) {
            case FileKind::Regular: {
                sys::DataCopyHooks hooks;
                hooks.on_chunk = [this](uint64_t delta) { return prog_.bytes(delta) && !abort_; };
                hooks.allow_reflink = opt_.allow_reflink;
                hooks.allow_kernel_copy = opt_.allow_kernel_copy;
                hooks.sync = opt_.sync || remove_source;
                hooks.preserve_metadata = opt_.preserve_metadata;
                hooks.buffer_size = opt_.buffer_size;
                hooks.warnings = &res_.warnings;
                uint64_t n = 0;
                CopyMethod m = sys::copy_file_data(src, st, tmp, hooks, n, ec);
                if (m == CopyMethod::None) {
                    if (ec != Errc::cancelled) fail(src, dst, ec, "copy");
                    return false;
                }
                if (remove_source && n != st.size) {
                    std::error_code rec;
                    sys::remove_nondir(tmp, rec);
                    fail(src, dst, make_error_code(Errc::source_changed), "copy");
                    return false;
                }
                res_.bytes_done += n;
                if (m == CopyMethod::Reflink) ++res_.reflinked;
                if (m == CopyMethod::KernelCopy) ++res_.kernel_copied;
                return true;
            }
            case FileKind::Symlink:
            case FileKind::Junction:
                if (!sys::copy_link(src, st, tmp, ec)) {
                    fail(src, dst, ec, "create link");
                    return false;
                }
                if (opt_.preserve_metadata) sys::apply_metadata(tmp, st, &res_.warnings);
                return true;
            default:
                if (!sys::copy_special(st, tmp, ec)) {
                    fail(src, dst, ec, "create");
                    return false;
                }
                if (opt_.preserve_metadata) sys::apply_metadata(tmp, st, &res_.warnings);
                return true;
        }
    }

    bool remove_moved_source(const fs::path& src, const sys::Stat& planned) {
        sys::Stat now;
        std::error_code ec;
        if (!sys::lstat(src, now, ec)) {
            fail(src, {}, ec, "verify source");
            return false;
        }
        if (!(now.id == planned.id) || now.kind != planned.kind || now.size != planned.size ||
            now.mtime_ns != planned.mtime_ns) {
            fail(src, {}, make_error_code(Errc::source_changed), "remove source");
            return false;
        }
        if (!sys::remove_nondir(src, ec, &planned.id)) {
            fail(src, {}, ec, "remove source");
            return false;
        }
        return true;
    }

    ItemState place_nondir(const fs::path& src, const sys::Stat& st, fs::path dst, bool remove_source,
                           bool preset_overwrite, fs::path* final_dst) {
        if (st.kind == FileKind::Socket || st.kind == FileKind::CharDevice || st.kind == FileKind::BlockDevice ||
            st.kind == FileKind::Unknown) {
            fail(src, dst, make_error_code(Errc::unsupported_file_type), "copy");
            return ItemState::Failed;
        }
        for (int attempt = 0; attempt < 8; ++attempt) {
            if (stop()) return ItemState::Pending;
            Resolution r{Resolution::Write, dst, {}};
            if (preset_overwrite && attempt == 0) {
                r.act = Resolution::Overwrite;
            } else {
                sys::Stat ds;
                std::error_code ec;
                if (sys::lstat(dst, ds, ec)) {
                    r = resolve(classify(st, ds), src, st, dst, ds);
                } else if (!sys::is_not_found(ec)) {
                    fail(src, dst, ec, "stat");
                    return ItemState::Failed;
                }
            }
            switch (r.act) {
                case Resolution::Skip: ++res_.skipped; return ItemState::Skipped;
                case Resolution::Abort: return ItemState::Pending;
                case Resolution::Fail: fail(src, dst, r.ec, "conflict"); return ItemState::Failed;
                default: break;
            }
            dst = r.dst;
            const bool overwrite = r.act == Resolution::Overwrite;
            fs::path parent = dst.parent_path();
            fs::path tmp = sys::temp_sibling(parent.empty() ? fs::path(".") : parent);
            if (!stage(src, st, tmp, dst, remove_source)) {
                return stop() ? ItemState::Pending : ItemState::Failed;
            }
            std::error_code ec;
            bool ok = overwrite ? sys::rename_replace(tmp, dst, ec) : sys::rename_noreplace(tmp, dst, ec);
            if (!ok) {
                std::error_code rec;
                sys::remove_nondir(tmp, rec);
                if (!overwrite && sys::is_exists_error(ec)) continue; // created meanwhile: decide again
                fail(src, dst, ec, "commit");
                return ItemState::Failed;
            }
            count(st);
            if (final_dst) *final_dst = dst;
            if (remove_source) {
                sys::sync_dir(parent);
                if (!remove_moved_source(src, st)) return ItemState::Failed;
            }
            return ItemState::Done;
        }
        fail(src, dst, make_error_code(Errc::conflict_unresolved), "commit");
        return ItemState::Failed;
    }

    ItemState place_dir(const fs::path& src, const sys::Stat& st, fs::path& dst, bool& created) {
        created = false;
        for (int attempt = 0; attempt < 8; ++attempt) {
            if (stop()) return ItemState::Pending;
            sys::Stat ds;
            std::error_code ec;
            if (!sys::lstat(dst, ds, ec)) {
                if (!sys::is_not_found(ec)) {
                    fail(src, dst, ec, "stat");
                    return ItemState::Failed;
                }
                if (sys::make_dir(dst, ec)) {
                    created = true;
                    return ItemState::Done;
                }
                if (sys::is_exists_error(ec)) continue;
                fail(src, dst, ec, "mkdir");
                return ItemState::Failed;
            }
            if (ds.kind == FileKind::Directory) {
                if (ds.id == st.id) {
                    fail(src, dst, make_error_code(Errc::destination_inside_source), "plan");
                    return ItemState::Failed;
                }
                return ItemState::Done; // merge into the existing directory
            }
            // A file or a link (never merged through) is in the way.
            Resolution r = resolve(ConflictKind::TypeMismatch, src, st, dst, ds);
            switch (r.act) {
                case Resolution::Skip: ++res_.skipped; return ItemState::Skipped;
                case Resolution::Abort: return ItemState::Pending;
                case Resolution::Fail: fail(src, dst, r.ec, "conflict"); return ItemState::Failed;
                default: dst = r.dst; continue;
            }
        }
        fail(src, dst, make_error_code(Errc::conflict_unresolved), "mkdir");
        return ItemState::Failed;
    }

    struct Node {
        fs::path src;
        fs::path leaf;
        sys::Stat st;
        std::error_code stat_error;
        int64_t parent = -1;
        bool incomplete = false; // directory could not be fully listed
    };

    void copy_tree(const fs::path& src, const sys::Stat& ss, const fs::path& dst, bool remove_source,
                   bool preset_overwrite, bool top) {
        if (ss.kind != FileKind::Directory) {
            prog_.add_totals(ss.kind == FileKind::Regular ? ss.size : 0, 1);
            if (!prog_.begin_item(src)) return;
            fs::path final_dst;
            if (place_nondir(src, ss, dst, remove_source, preset_overwrite, &final_dst) == ItemState::Done && top) {
                res_.created.push_back(final_dst);
            }
            prog_.end_item();
            return;
        }

        // Plan.
        std::vector<Node> nodes;
        bool root_incomplete = false;
        uint64_t total_bytes = 0;
        WalkOptions wo;
        walk(
            src, wo, nullptr,
            [&](const WalkNode& n) {
                Node nd;
                nd.src = n.path;
                nd.leaf = n.path.filename();
                nd.st = n.st;
                nd.stat_error = n.stat_error;
                nd.parent = n.parent;
                if (n.st.kind == FileKind::Regular) total_bytes += n.st.size;
                nodes.push_back(std::move(nd));
                return !stop();
            },
            [&](const fs::path& p, const std::error_code& ec) {
                fail(p, {}, ec, "scan");
                if (!nodes.empty() && nodes.back().src == p) {
                    nodes.back().incomplete = true;
                } else {
                    root_incomplete = true;
                }
            });
        if (stop()) return;
        prog_.add_totals(total_bytes, nodes.size() + 1);

        // Root directory.
        fs::path root_dst = dst;
        bool root_created = false;
        if (!prog_.begin_item(src)) return;
        if (place_dir(src, ss, root_dst, root_created) != ItemState::Done) return;
        ++res_.dirs_done;
        if (top && root_created) res_.created.push_back(root_dst);
        prog_.end_item();

        // Execute in pre-order: parents exist before children.
        const size_t n = nodes.size();
        std::vector<ItemState> state(n, ItemState::Pending);
        std::vector<fs::path> dsts(n);
        std::vector<char> created(n, 0), blocked(n, 0);
        for (size_t i = 0; i < n && !stop(); ++i) {
            Node& nd = nodes[i];
            ItemState ps = nd.parent < 0 ? ItemState::Done : state[static_cast<size_t>(nd.parent)];
            if (ps != ItemState::Done) continue; // parent skipped or failed: subtree untouched
            const fs::path& pdst = nd.parent < 0 ? root_dst : dsts[static_cast<size_t>(nd.parent)];
            if (nd.stat_error) {
                fail(nd.src, {}, nd.stat_error, "stat");
                state[i] = ItemState::Failed;
                continue;
            }
            if (!prog_.begin_item(nd.src)) break;
            dsts[i] = pdst / nd.leaf;
            if (nd.st.kind == FileKind::Directory) {
                bool cr = false;
                state[i] = place_dir(nd.src, nd.st, dsts[i], cr);
                created[i] = cr;
                if (state[i] == ItemState::Done) ++res_.dirs_done;
            } else {
                state[i] = place_nondir(nd.src, nd.st, dsts[i], remove_source, false, nullptr);
            }
            prog_.end_item();
        }

        // Finish in post-order: directory metadata after contents; for a move, rmdir each
        // source directory whose every descendant was moved.
        bool root_blocked = root_incomplete;
        auto block_parent = [&](const Node& nd) {
            if (nd.parent < 0) {
                root_blocked = true;
            } else {
                blocked[static_cast<size_t>(nd.parent)] = 1;
            }
        };
        for (size_t k = n; k-- > 0;) {
            Node& nd = nodes[k];
            if (state[k] != ItemState::Done) {
                block_parent(nd);
                continue;
            }
            if (nd.st.kind != FileKind::Directory) continue;
            if (created[k] && opt_.preserve_metadata) sys::apply_metadata(dsts[k], nd.st, &res_.warnings);
            if (!remove_source) continue;
            if (blocked[k] || nd.incomplete || stop()) {
                block_parent(nd);
                continue;
            }
            std::error_code ec;
            if (!sys::remove_dir(nd.src, ec, &nd.st.id)) {
                fail(nd.src, {}, sys::is_exists_error(ec) ? make_error_code(Errc::directory_not_empty_after_move) : ec,
                     "remove source");
                block_parent(nd);
            }
        }
        if (root_created && opt_.preserve_metadata) sys::apply_metadata(root_dst, ss, &res_.warnings);
        if (remove_source && !root_blocked && !stop()) {
            std::error_code ec;
            if (!sys::remove_dir(src, ec, &ss.id)) {
                fail(src, {}, sys::is_exists_error(ec) ? make_error_code(Errc::directory_not_empty_after_move) : ec,
                     "remove source");
            }
        }
    }

    TransferMode mode_;
    const FileOpOptions& opt_;
    Progress& prog_;
    OpResult res_;
    bool abort_ = false;
};

} // namespace

void finish_result(OpResult& r, bool cancelled) {
    if (cancelled) {
        r.outcome = Outcome::Cancelled;
    } else if (r.errors.empty()) {
        r.outcome = Outcome::Success;
    } else if (r.files_done + r.dirs_done + r.links_done + r.skipped > 0) {
        r.outcome = Outcome::Partial;
    } else {
        r.outcome = Outcome::Failed;
    }
}

fs::path unique_sibling(const fs::path& path, bool is_dir) {
    fs::path parent = path.parent_path();
    fs::path leaf = path.filename();
    fs::path stem = is_dir ? leaf : leaf.stem();
    fs::path ext = is_dir ? fs::path() : leaf.extension();
    if (!sys::exists_nofollow(path)) return path;
    for (unsigned n = 2;; ++n) {
        fs::path name = stem;
        name += " (" + std::to_string(n) + ")";
        name += ext;
        fs::path candidate = parent / name;
        if (!sys::exists_nofollow(candidate)) return candidate;
    }
}

OpResult run_transfer(TransferMode mode, const std::vector<TransferPair>& pairs, const FileOpOptions& options,
                      Progress& progress) {
    Transfer t(mode, options, progress);
    return t.run(pairs);
}

} // namespace bro::vfs::detail
