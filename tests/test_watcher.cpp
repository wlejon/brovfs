// Directory watching against real churn. The oracle is a consumer that keeps a model of the
// tree purely from events (statting each named path, rescanning on Created-directory /
// Renamed / Rescan, as the watcher contract says) and must end equal to a fresh scan of the
// disk after every storm: bulk create/delete/rename, renames across watched and unwatched
// directories, kernel-queue overflow, and the root itself going away.
#include "harness.h"

#include "brovfs/watcher.h"
#include "src/watch_core.h"

#include <functional>
#include <set>
#include <thread>

using namespace t;
using K = vfs::WatchEventKind;

namespace {

bool path_within_root(const fs::path& p, const fs::path& root) { return bro::vfs::detail::path_within(p, root); }

std::string rel_of(const fs::path& p, const fs::path& root) {
    std::string s = u8(p.lexically_relative(root));
    for (auto& c : s) {
        if (c == '\\') c = '/';
    }
    return s == "." ? std::string() : s;
}

std::string show(const vfs::WatchEvent& e, const fs::path& root) {
    std::string s = std::string(vfs::to_string(e.kind)) + " " + rel_of(e.path, root);
    if (e.kind == K::Renamed) s += " <- " + rel_of(e.old_path, root);
    if (e.error) s += " (" + e.error.message() + ")";
    return s;
}

class Feed {
public:
    explicit Feed(std::shared_ptr<vfs::WatchEventQueue> q = nullptr) : w(std::move(q)) {}

    void pump(int ms) {
        double end = now_ms() + ms;
        while (now_ms() < end) {
            w.queue()->wait_for(std::chrono::milliseconds(20));
            for (auto& e : w.queue()->drain()) events.push_back(std::move(e));
        }
    }
    bool until(const std::function<bool(const vfs::WatchEvent&)>& pred, int timeout_ms = 10000) {
        size_t seen = 0;
        double end = now_ms() + timeout_ms;
        for (;;) {
            for (; seen < events.size(); ++seen) {
                if (pred(events[seen])) return true;
            }
            if (now_ms() > end) return false;
            pump(20);
        }
    }
    // Until no event arrives for `quiet_ms` (bounded).
    void quiesce(int quiet_ms = 600, int max_ms = 60000) {
        double end = now_ms() + max_ms;
        size_t n = events.size();
        double last = now_ms();
        while (now_ms() < end) {
            pump(50);
            if (events.size() != n) {
                n = events.size();
                last = now_ms();
            } else if (now_ms() - last >= quiet_ms) {
                return;
            }
        }
    }
    size_t count(K kind) const {
        size_t n = 0;
        for (auto& e : events) n += e.kind == kind;
        return n;
    }

    vfs::DirectoryWatcher w;
    std::vector<vfs::WatchEvent> events;
};

// The consumer the contract is written for.
class Model {
public:
    explicit Model(fs::path root) : root_(std::move(root)) { deep(root_); }

    void apply(const vfs::WatchEvent& e) {
        switch (e.kind) {
            case K::Modified: shallow(e.path); break;
            case K::Created:
            case K::Removed:
            case K::Rescan: deep(e.path); break;
            case K::Renamed:
                deep(e.old_path);
                deep(e.path);
                break;
            default: break;
        }
    }
    void apply_all(const std::vector<vfs::WatchEvent>& evs, size_t from = 0) {
        for (size_t i = from; i < evs.size(); ++i) apply(evs[i]);
    }

    static std::set<std::string> disk(const fs::path& root) {
        std::set<std::string> out;
        std::error_code ec;
        for (auto it = fs::recursive_directory_iterator(L(root), ec); !ec && it != fs::recursive_directory_iterator();
             it.increment(ec)) {
            out.insert(rel_of(it->path(), L(root)));
        }
        return out;
    }

    std::set<std::string> items;

private:
    void erase_subtree(const std::string& r) {
        if (r.empty()) {
            items.clear();
            return;
        }
        items.erase(r);
        std::string prefix = r + "/";
        for (auto it = items.lower_bound(prefix); it != items.end() && it->compare(0, prefix.size(), prefix) == 0;) {
            it = items.erase(it);
        }
    }
    void shallow(const fs::path& p) {
        std::string r = rel_of(p, root_);
        if (r.rfind("..", 0) == 0) return;
        if (path_exists(p)) {
            if (!r.empty()) items.insert(r);
        } else {
            erase_subtree(r);
        }
    }
    void deep(const fs::path& p) {
        std::string r = rel_of(p, root_);
        if (r.rfind("..", 0) == 0) return;
        erase_subtree(r);
        std::error_code ec;
        auto st = fs::symlink_status(L(p), ec);
        if (ec || !fs::exists(st)) return;
        if (!r.empty()) items.insert(r);
        if (!fs::is_directory(st)) return;
        for (auto it = fs::recursive_directory_iterator(L(p), ec); !ec && it != fs::recursive_directory_iterator();
             it.increment(ec)) {
            items.insert(rel_of(it->path(), L(root_)));
        }
    }

    fs::path root_;
};

bool same_model(const Model& m, const fs::path& root, std::string& diff) {
    auto d = Model::disk(root);
    if (m.items == d) return true;
    int shown = 0;
    for (auto& x : d) {
        if (!m.items.count(x) && shown++ < 5) diff += " missing:" + x;
    }
    for (auto& x : m.items) {
        if (!d.count(x) && shown++ < 10) diff += " stale:" + x;
    }
    diff += " (model " + std::to_string(m.items.size()) + " vs disk " + std::to_string(d.size()) + ")";
    return false;
}

auto is(K kind, const fs::path& p) {
    return [kind, p](const vfs::WatchEvent& e) { return e.kind == kind && e.path == p; };
}

vfs::WatchId watch(Feed& f, const fs::path& root, bool recursive = true, int latency = 50) {
    vfs::WatchOptions o;
    o.recursive = recursive;
    o.latency = std::chrono::milliseconds(latency);
    std::error_code ec;
    vfs::WatchId id = f.w.add(root, o, ec);
    CHECK_MSG(id != 0, ec.message());
    return id;
}

void touch_more(const fs::path& p) {
    std::ofstream out(L(p), std::ios::binary | std::ios::app);
    out << "more";
}

// ------------------------------------------------------------------------------------------

void test_basic(const Scratch& s) {
    section("basic events: create, modify, rename, delete, nested");
    fs::path root = s / "basic";
    fs::create_directories(root / "sub");
    Feed f;
    watch(f, root);

    write_file(root / "a.txt", "a");
    CHECK(f.until(is(K::Created, root / "a.txt")));
    f.pump(150); // let the coalescing window close so the modification is its own event
    size_t mark = f.events.size();
    touch_more(root / "a.txt");
    CHECK(f.until([&](const vfs::WatchEvent& e) { return e.kind == K::Modified && e.path == root / "a.txt"; }));
    (void)mark;

    fs::rename(L(root / "a.txt"), L(root / "b.txt"));
    CHECK(f.until([&](const vfs::WatchEvent& e) {
        return e.kind == K::Renamed && e.path == root / "b.txt" && e.old_path == root / "a.txt";
    }));
    write_file(root / "sub" / "c.txt", "c");
    CHECK(f.until(is(K::Created, root / "sub" / "c.txt")));
    fs::remove(L(root / "b.txt"));
    CHECK(f.until(is(K::Removed, root / "b.txt")));

    fs::create_directories(L(root / "d1" / "d2"));
    CHECK(f.until(is(K::Created, root / "d1")));
    f.pump(100);
    write_file(root / "d1" / "d2" / "f.txt", "f");
    CHECK(f.until(is(K::Created, root / "d1" / "d2" / "f.txt")));

    bool kinds_ok = true;
    for (auto& e : f.events) {
        if (e.kind == K::Created && e.path == root / "d1" && e.file_kind != vfs::FileKind::Directory) kinds_ok = false;
        if (e.kind == K::Created && e.path == root / "sub" / "c.txt" && e.file_kind == vfs::FileKind::Directory) {
            kinds_ok = false;
        }
    }
    CHECK_MSG(kinds_ok, "file_kind of Created events");
    CHECK(f.count(K::Error) == 0 && f.count(K::RootRemoved) == 0);
}

void test_non_recursive(const Scratch& s) {
    section("non-recursive: direct children only");
    fs::path root = s / "flat";
    fs::create_directories(root / "sub");
    Feed f;
    watch(f, root, false);
    write_file(root / "x.txt", "x");
    CHECK(f.until(is(K::Created, root / "x.txt")));
    write_file(root / "sub" / "deep.txt", "y");
    fs::create_directories(L(root / "sub" / "deeper"));
    f.pump(500);
    bool deep_seen = false;
    for (auto& e : f.events) {
        if (path_within_root(e.path, root / "sub") && e.path != root / "sub") deep_seen = true;
    }
    CHECK_MSG(!deep_seen, "events below a direct child");
    fs::rename(L(root / "x.txt"), L(root / "z.txt"));
    CHECK(f.until([&](const vfs::WatchEvent& e) { return e.kind == K::Renamed && e.path == root / "z.txt"; }));
}

void test_bulk_storm(const Scratch& s) {
    section("bulk create / delete / rename storm reconciles");
    fs::path root = s / "storm";
    fs::create_directories(root);
    Feed f;
    watch(f, root);
    Model m(root);

    const int dirs = 40, files = 100;
    for (int d = 0; d < dirs; ++d) {
        fs::path dir = root / ("d" + std::to_string(d));
        fs::create_directory(L(dir));
        for (int i = 0; i < files; ++i) write_file(dir / ("f" + std::to_string(i) + ".txt"), "data");
    }
    f.quiesce();
    m.apply_all(f.events);
    std::string diff;
    CHECK_MSG(same_model(m, root, diff), "after create:" + diff);
    note("create: " + std::to_string(f.events.size()) + " events, " + std::to_string(f.count(K::Rescan)) + " rescans");

    size_t mark = f.events.size();
    for (int d = 0; d < dirs; ++d) {
        fs::path dir = root / ("d" + std::to_string(d));
        std::error_code ec;
        if (d % 4 == 0) {
            fs::remove_all(L(dir), ec);
        } else if (d % 4 == 1) {
            fs::rename(L(dir), L(root / ("r" + std::to_string(d))), ec);
        } else {
            for (int i = 0; i < files; i += 2) {
                fs::path a = dir / ("f" + std::to_string(i) + ".txt");
                if (i % 4 == 0) {
                    fs::remove(L(a), ec);
                } else {
                    fs::rename(L(a), L(dir / ("g" + std::to_string(i) + ".txt")), ec);
                }
            }
        }
    }
    // A renamed directory keeps reporting under its new name.
    write_file(root / "r1" / "late.txt", "late");
    f.quiesce();
    m.apply_all(f.events, mark);
    diff.clear();
    CHECK_MSG(same_model(m, root, diff), "after churn:" + diff);
    CHECK(f.until(is(K::Created, root / "r1" / "late.txt"), 100) || f.count(K::Rescan) > 0);
    CHECK(f.count(K::Error) == 0 && f.count(K::RootRemoved) == 0);
}

void test_rename_storm(const Scratch& s) {
    section("rename storm: back-and-forth renames pair and reconcile");
    fs::path root = s / "renames";
    fs::create_directories(root / "dir");
    for (int i = 0; i < 200; ++i) write_file(root / ("f" + std::to_string(i)), "x");
    Feed f;
    watch(f, root);
    Model m(root);
    for (int round = 0; round < 5; ++round) {
        for (int i = 0; i < 200; ++i) {
            fs::rename(L(root / ("f" + std::to_string(i))), L(root / ("g" + std::to_string(i))));
        }
        for (int i = 0; i < 200; ++i) {
            fs::rename(L(root / ("g" + std::to_string(i))), L(root / ("f" + std::to_string(i))));
        }
        fs::rename(L(root / "dir"), L(root / "dir2"));
        write_file(root / "dir2" / ("in" + std::to_string(round)), "y");
        fs::rename(L(root / "dir2"), L(root / "dir"));
    }
    // One isolated rename, after the storm, must arrive as a pair.
    f.quiesce();
    fs::rename(L(root / "f7"), L(root / "dir" / "f7-moved"));
    CHECK(f.until([&](const vfs::WatchEvent& e) {
        return e.kind == K::Renamed && e.path == root / "dir" / "f7-moved" && e.old_path == root / "f7";
    }));
    f.quiesce();
    m.apply_all(f.events);
    std::string diff;
    CHECK_MSG(same_model(m, root, diff), diff);
    note(std::to_string(f.count(K::Renamed)) + " renamed events, " + std::to_string(f.count(K::Rescan)) + " rescans");
    CHECK(f.count(K::Renamed) > 0);
}

void test_cross_boundary(const Scratch& s) {
    section("renames across watched and unwatched directories");
    fs::path W = s / "watched", U = s / "unwatched";
    fs::create_directories(W);
    fs::create_directories(U);
    write_file(W / "out.txt", "o");
    write_file(W / "tree2" / "x" / "y.txt", "y");
    Feed f;
    watch(f, W);
    Model m(W);

    write_file(U / "in.txt", "i");
    fs::rename(L(U / "in.txt"), L(W / "in.txt"));
    CHECK(f.until(is(K::Created, W / "in.txt")));
    fs::rename(L(W / "out.txt"), L(U / "out.txt"));
    CHECK(f.until(is(K::Removed, W / "out.txt")));

    write_file(U / "tree" / "a" / "b" / "f1.txt", "1");
    write_file(U / "tree" / "f2.txt", "2");
    fs::rename(L(U / "tree"), L(W / "tree"));
    CHECK(f.until(is(K::Created, W / "tree")));
    f.pump(100);
    write_file(W / "tree" / "a" / "b" / "new.txt", "n");
    CHECK_MSG(f.until(is(K::Created, W / "tree" / "a" / "b" / "new.txt")), "a directory moved in is watched");

    fs::rename(L(W / "tree2"), L(U / "tree2"));
    CHECK(f.until(is(K::Removed, W / "tree2")));
    f.pump(100);
    write_file(U / "tree2" / "x" / "late.txt", "late");

    fs::rename(L(W / "tree"), L(W / "tree_renamed"));
    CHECK(f.until([&](const vfs::WatchEvent& e) { return e.kind == K::Renamed && e.path == W / "tree_renamed"; }));
    write_file(W / "tree_renamed" / "a" / "b" / "after.txt", "a");
    CHECK_MSG(f.until(is(K::Created, W / "tree_renamed" / "a" / "b" / "after.txt")),
              "a directory renamed inside the watch reports under its new name");
    f.quiesce();
    bool outside = false;
    for (auto& e : f.events) {
        if (!path_within_root(e.path, W) || (e.kind == K::Renamed && !path_within_root(e.old_path, W))) outside = true;
    }
    CHECK_MSG(!outside, "an event named a path outside the watched root");
    m.apply_all(f.events);
    std::string diff;
    CHECK_MSG(same_model(m, W, diff), diff);
}

void test_root_removed(const Scratch& s) {
    section("the watched root deleted or renamed: RootRemoved, then silence");
    fs::path R = s / "doomed";
    write_file(R / "inner" / "f.txt", "f");
    Feed f;
    vfs::WatchId id = watch(f, R);
    auto r = vfs::remove({R});
    CHECK_MSG(r.ok(), describe(r));
    CHECK(f.until([&](const vfs::WatchEvent& e) { return e.kind == K::RootRemoved && e.watch == id; }));
    size_t at = f.events.size();
    fs::create_directories(L(R));
    write_file(R / "reborn.txt", "r");
    f.pump(400);
    CHECK_MSG(f.events.size() == at, "events after RootRemoved");
    CHECK(f.w.remove(id));

    fs::path R2 = s / "moving";
    write_file(R2 / "f.txt", "f");
    vfs::WatchId id2 = watch(f, R2);
    fs::rename(L(R2), L(s / "moved_away"));
    CHECK(f.until([&](const vfs::WatchEvent& e) { return e.kind == K::RootRemoved && e.watch == id2; }));
}

void test_overflow(const Scratch& s) {
    section("kernel queue overflow becomes Rescan, and the watch keeps working");
    fs::path root = s / "overflow";
    fs::create_directories(root);
    Feed f;
    watch(f, root);
    Model m(root);
    bro::vfs::detail::g_watch_stall_ms = 2500;
    double start = now_ms();
    int n = 0;
    while (f.count(K::Rescan) == 0 && now_ms() - start < 60000 && n < 40000) {
        for (int i = 0; i < 500; ++i, ++n) write_file(root / ("o" + std::to_string(n)), "z");
        f.pump(1);
    }
    bro::vfs::detail::g_watch_stall_ms = 0;
    double took = now_ms() - start;
    f.quiesce(3500); // longer than one stalled callback, so the backlog has drained
    note(std::to_string(n) + " files in " + std::to_string(static_cast<int>(took)) + " ms, " +
         std::to_string(f.events.size()) + " events, " + std::to_string(f.count(K::Rescan)) + " rescans");
    for (size_t i = 0; i < f.events.size() && i < 4; ++i) note(show(f.events[i], root));
    bool root_rescan = false;
    for (auto& e : f.events) root_rescan |= e.kind == K::Rescan && e.path == root;
    if (f.w.backend_name() == "FSEvents" && f.count(K::Rescan) == 0) {
        // fseventsd may buffer a stalled client's backlog instead of dropping it; then every
        // event must still arrive, which the model check below demands.
        note("FSEvents delivered the whole backlog without dropping; no Rescan to check");
    } else {
        CHECK_MSG(f.count(K::Rescan) > 0, "no overflow was reported");
        CHECK(root_rescan);
    }
    m.apply_all(f.events);
    std::string diff;
    CHECK_MSG(same_model(m, root, diff), diff);
    // A read stalled before the reset may still overflow once more; a later root Rescan
    // covers the new file as well.
    size_t mark = f.events.size();
    write_file(root / "after-overflow.txt", "a");
    CHECK(f.until([&](const vfs::WatchEvent& e) {
        return (e.kind == K::Created && e.path == root / "after-overflow.txt") ||
               (e.kind == K::Rescan && e.path == root && &e - f.events.data() >= static_cast<std::ptrdiff_t>(mark));
    }));
}

void test_overlap_and_remove(const Scratch& s) {
    section("overlapping watches, remove() silences, zero latency");
    fs::path root = s / "overlap";
    fs::create_directories(root / "sub");
    Feed f;
    vfs::WatchId outer = watch(f, root, true, 0);
    vfs::WatchId inner = watch(f, root / "sub", true, 0);
    write_file(root / "sub" / "z.txt", "z");
    CHECK(f.until([&](const vfs::WatchEvent& e) { return e.watch == outer && e.path == root / "sub" / "z.txt"; }));
    CHECK(f.until([&](const vfs::WatchEvent& e) { return e.watch == inner && e.path == root / "sub" / "z.txt"; }));
    CHECK(f.w.remove(inner));
    CHECK(!f.w.remove(inner));
    f.pump(200);
    size_t at = f.events.size();
    write_file(root / "sub" / "after.txt", "a");
    CHECK(f.until([&](const vfs::WatchEvent& e) { return e.watch == outer && e.path == root / "sub" / "after.txt"; }));
    bool leaked = false;
    for (size_t i = at; i < f.events.size(); ++i) leaked |= f.events[i].watch == inner;
    CHECK_MSG(!leaked, "event for a removed watch");

    std::error_code ec;
    CHECK(f.w.add(root / "missing", vfs::WatchOptions(), ec) == 0 && ec);
    write_file(root / "plain.txt", "p");
    CHECK(f.w.add(root / "plain.txt", vfs::WatchOptions(), ec) == 0 && ec);
}

} // namespace

int main() {
    std::cout << "backend: " << vfs::DirectoryWatcher::backend_name() << "\n";
    Scratch s("watch");
    test_basic(s);
    test_non_recursive(s);
    test_bulk_storm(s);
    test_rename_storm(s);
    test_cross_boundary(s);
    test_root_removed(s);
    test_overflow(s);
    test_overlap_and_remove(s);
    return finish("test_watcher");
}
