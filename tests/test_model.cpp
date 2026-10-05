// File-view plumbing: natural sort order, the directory model (live, filtered, sorted, stable
// keys, incremental diffs) and background selection totals.
//
// Oracles: the model's diffs are applied to a host-side list and must reproduce the model's
// own list, which must equal an independent recomputation (filter + sort of a fresh scan).
#include "harness.h"

#include "brovfs/aggregate.h"
#include "brovfs/collate.h"
#include "brovfs/dir_model.h"
#include "src/dir_model_view.h"

#include <algorithm>
#include <map>
#include <random>
#include <thread>

using namespace t;
namespace detail = bro::vfs::detail;

namespace {

// ------------------------------------------------------------------ natural order

void test_natural() {
    section("natural order: numbers by value, case-insensitive, total");
    std::vector<std::string> want = {
        "1.txt", "2.txt", "10.txt", "a", "A1", "a1", "a01", "a2", "a10", "B", "b", "file 9", "file9.txt",
        "file10.txt", "file010.txt", "x99999999999999999999999", "x100000000000000000000000",
        "\xc3\x84pfel", "\xc3\xa4pfel", "\xc3\xa9t\xc3\xa9", "\xce\x91\xce\xbb\xcf\x86\xce\xb1",
        "\xd0\x96\xd1\x83\xd0\xba", "\xe6\x96\x87\xe4\xbb\xb6",
    };
    std::vector<std::string> got = want;
    std::mt19937 rng(7);
    std::shuffle(got.begin(), got.end(), rng);
    std::sort(got.begin(), got.end(), vfs::NaturalLess());
    std::string diff;
    for (size_t i = 0; i < got.size(); ++i) {
        if (got[i] != want[i]) diff += " [" + std::to_string(i) + "] " + got[i] + " vs " + want[i];
    }
    CHECK_MSG(diff.empty(), diff);
    CHECK(vfs::natural_compare("abc", "abc") == 0);
    CHECK(vfs::natural_compare("a", "A") != 0 && vfs::natural_compare("a", "A") == -vfs::natural_compare("A", "a"));

    // Properties over random names: antisymmetric, zero only for equal, transitive.
    const std::vector<std::string> atoms = {"a", "A", "b", "0", "00", "1", "9", "10", ".", "-", " ", "\xc3\xa4",
                                            "\xc3\x84", "\xe6\x96\x87", "\xff"};
    auto rnd = [&] {
        std::string s;
        int n = static_cast<int>(rng() % 5);
        for (int i = 0; i < n; ++i) s += atoms[rng() % atoms.size()];
        return s;
    };
    bool ok = true;
    for (int i = 0; i < 20000 && ok; ++i) {
        std::string a = rnd(), b = rnd(), c = rnd();
        int ab = vfs::natural_compare(a, b), ba = vfs::natural_compare(b, a);
        ok &= (ab == -ba) && ((ab == 0) == (a == b));
        int bc = vfs::natural_compare(b, c), ac = vfs::natural_compare(a, c);
        if (ab < 0 && bc < 0) ok &= ac < 0;
        if (!ok) note("violation: '" + a + "' '" + b + "' '" + c + "'");
    }
    CHECK(ok);
}

// ------------------------------------------------------------------ view diffs (no I/O)

vfs::FileEntry fake(const std::string& name, uint64_t size, int64_t mtime, bool dir, uint64_t ino) {
    vfs::FileEntry e;
    e.name = name;
    e.path = name;
    e.kind = dir ? vfs::FileKind::Directory : vfs::FileKind::Regular;
    e.size = size;
    e.mtime_ms = mtime;
    e.is_hidden = !name.empty() && name[0] == '.';
    e.id = {1, 0, ino, true};
    return e;
}

// Independent order: the documented rules, written out again.
bool oracle_less(const vfs::SortSpec& s, const vfs::FileEntry& a, const vfs::FileEntry& b) {
    bool da = a.kind == vfs::FileKind::Directory, db = b.kind == vfs::FileKind::Directory;
    if (s.directories_first && da != db) return da;
    long long c = 0;
    if (s.field == vfs::SortField::Size) {
        uint64_t sa = da ? 0 : a.size, sb = db ? 0 : b.size; // directories sort as size 0
        c = sa < sb ? -1 : sa > sb ? 1 : 0;
    }
    if (s.field == vfs::SortField::Modified) c = a.mtime_ms < b.mtime_ms ? -1 : a.mtime_ms > b.mtime_ms ? 1 : 0;
    if (c == 0) c = vfs::natural_compare(a.name, b.name);
    return s.descending ? c > 0 : c < 0;
}

void test_view_random() {
    section("view diffs reproduce the list; the list equals an independent filter + sort");
    std::mt19937 rng(11);
    detail::ModelView view;
    std::map<std::string, vfs::FileEntry> truth;     // name -> entry
    std::vector<vfs::ModelItem> host;
    vfs::SortSpec sort;
    bool show_hidden = false;
    bool filter_txt = false;
    uint64_t ino = 1;
    bool ok = true, keys_ok = true;
    auto pick = [&]() -> std::string {
        if (truth.empty()) return {};
        auto it = truth.begin();
        std::advance(it, static_cast<long>(rng() % truth.size()));
        return it->first;
    };
    for (int step = 0; step < 3000 && ok; ++step) {
        int ops = 1 + static_cast<int>(rng() % 6);
        for (int k = 0; k < ops; ++k) {
            int what = static_cast<int>(rng() % 10);
            std::string name = (rng() % 4 == 0 ? "." : "") + std::string("f") + std::to_string(rng() % 60) +
                               (rng() % 2 ? ".txt" : ".bin");
            if (what < 4) {
                auto e = fake(name, rng() % 5, static_cast<int64_t>(rng() % 5), rng() % 5 == 0, ino++);
                if (truth.count(name)) e.id = truth[name].id;
                truth[name] = e;
                view.put(e);
            } else if (what < 6) {
                std::string n = pick();
                if (!n.empty()) {
                    truth.erase(n);
                    view.erase(n);
                }
            } else if (what < 8) {
                std::string from = pick();
                if (!from.empty() && from != name) {
                    vfs::FileEntry e = truth[from];
                    e.name = name;
                    e.path = name;
                    e.is_hidden = name[0] == '.';
                    truth.erase(from);
                    truth[name] = e;
                    const vfs::ModelItem* before = view.find_name(from);
                    vfs::ItemKey kept = before ? before->key : 0;
                    view.rename(from, e);
                    const vfs::ModelItem* after = view.find_name(name);
                    keys_ok &= after && after->key == kept;
                }
            } else if (what == 8) {
                show_hidden = rng() % 2;
                filter_txt = rng() % 2;
                view.set_filter(filter_txt ? vfs::EntryFilter([](const vfs::FileEntry& e) {
                                    return e.name.size() > 4 && e.name.substr(e.name.size() - 4) == ".txt";
                                })
                                           : vfs::EntryFilter(),
                                show_hidden);
            } else {
                // A sort change is a reset in the model; here: commit, re-sort, reload the host.
                std::vector<vfs::ModelOp> pending;
                view.commit(pending);
                vfs::ModelUpdate u0;
                u0.ops = std::move(pending);
                vfs::apply_update(host, u0);
                sort.field = static_cast<vfs::SortField>(rng() % 3);
                sort.descending = rng() % 2;
                sort.directories_first = rng() % 2;
                view.set_sort(sort);
                host = view.visible_items();
            }
        }
        vfs::ModelUpdate u;
        view.commit(u.ops);
        vfs::apply_update(host, u);
        auto mine = view.visible_items();
        // (a) the ops reproduce the model's list
        bool same = host.size() == mine.size();
        for (size_t i = 0; same && i < host.size(); ++i) {
            same = host[i].key == mine[i].key && host[i].entry.name == mine[i].entry.name &&
                   host[i].entry.size == mine[i].entry.size;
        }
        // (b) the model's list is the independent recomputation
        std::vector<vfs::FileEntry> want;
        for (auto& [n, e] : truth) {
            if (!show_hidden && e.is_hidden) continue;
            if (filter_txt && !(n.size() > 4 && n.substr(n.size() - 4) == ".txt")) continue;
            want.push_back(e);
        }
        std::sort(want.begin(), want.end(), [&](auto& a, auto& b) { return oracle_less(sort, a, b); });
        bool right = want.size() == mine.size();
        for (size_t i = 0; right && i < want.size(); ++i) right = want[i].name == mine[i].entry.name;
        if (!same || !right) {
            std::string m, w;
            for (auto& i : mine) m += i.entry.name + (i.entry.kind == vfs::FileKind::Directory ? "/" : "") + ":" + std::to_string(i.entry.size) + " ";
            for (auto& e : want) w += e.name + (e.kind == vfs::FileKind::Directory ? "/" : "") + ":" + std::to_string(e.size) + " ";
            note("step " + std::to_string(step) + (same ? "" : ": ops diverge") + (right ? "" : ": list wrong") +
                 " sort=" + std::to_string(static_cast<int>(sort.field)) + (sort.descending ? "d" : "a") +
                 (sort.directories_first ? "D" : "") + "\n model: " + m + "\n want:  " + w);
            ok = false;
        }
    }
    CHECK(ok);
    CHECK(keys_ok);
}

// ------------------------------------------------------------------ live model

struct Host {
    explicit Host(vfs::DirectoryModel& m) : model(m) {}
    // Applies every update drained so far; returns how many arrived.
    size_t pump() {
        size_t n = 0;
        for (auto& u : model.queue()->drain()) {
            ++n;
            if (u.generation <= generation) continue;
            if (u.generation != generation + 1) gap = true;
            generation = u.generation;
            state = u.state;
            vfs::apply_update(list, u);
            if (u.state == vfs::ModelState::Loading && !u.reset) ++loading_updates;
        }
        return n;
    }
    bool settle() {
        bool s = model.settle(std::chrono::seconds(20));
        pump();
        return s;
    }
    std::vector<std::string> names() const {
        std::vector<std::string> out;
        for (auto& i : list) out.push_back(i.entry.name);
        return out;
    }
    vfs::ItemKey key(const std::string& name) const {
        for (auto& i : list) {
            if (i.entry.name == name) return i.key;
        }
        return 0;
    }
    vfs::DirectoryModel& model;
    std::vector<vfs::ModelItem> list;
    uint64_t generation = 0;
    vfs::ModelState state = vfs::ModelState::Loading;
    bool gap = false;
    size_t loading_updates = 0;
};

// What the view should show: a fresh scan, filtered and sorted by the oracle.
std::vector<std::string> expected(const fs::path& dir, const vfs::SortSpec& sort, bool show_hidden,
                                  const std::function<bool(const vfs::FileEntry&)>& filter = nullptr) {
    auto r = vfs::scan_directory(dir);
    std::vector<vfs::FileEntry> v;
    for (auto& e : r.entries) {
        if ((!show_hidden && e.is_hidden) || (filter && !filter(e))) continue;
        v.push_back(e);
    }
    std::sort(v.begin(), v.end(), [&](auto& a, auto& b) { return oracle_less(sort, a, b); });
    std::vector<std::string> out;
    for (auto& e : v) out.push_back(e.name);
    return out;
}

std::string join(const std::vector<std::string>& v) {
    std::string s;
    for (size_t i = 0; i < v.size() && i < 12; ++i) s += v[i] + ",";
    return s + " (" + std::to_string(v.size()) + ")";
}

void test_live(const Scratch& s) {
    section("live model: load, churn, rename keeps the key, filter, sort, directory removed");
    fs::path dir = s / "live";
    for (int i = 0; i < 1500; ++i) write_file(dir / ("item" + std::to_string(i) + (i % 3 ? ".txt" : ".dat")), "x");
    fs::create_directories(dir / "folder10");
    fs::create_directories(dir / "folder9");
    write_file(dir / ".hidden", "h");
#ifdef _WIN32
    SetFileAttributesW((dir / ".hidden").c_str(), FILE_ATTRIBUTE_HIDDEN);
#endif
    vfs::ModelOptions mo;
    mo.batch_size = 256;
    mo.latency = std::chrono::milliseconds(30);
    vfs::DirectoryModel model(dir, mo);
    Host h(model);
    CHECK(h.settle());
    CHECK(h.state == vfs::ModelState::Ready && !h.gap);
    CHECK_MSG(h.loading_updates >= 3, std::to_string(h.loading_updates)); // streamed in batches
    vfs::SortSpec sort;
    CHECK_MSG(h.names() == expected(dir, sort, false), join(h.names()));
    CHECK(h.list.size() >= 2 && h.list[0].entry.name == "folder9" && h.list[1].entry.name == "folder10");

    // Churn: create, modify, delete, rename, mkdir.
    vfs::ItemKey k5 = h.key("item5.txt");
    for (int i = 0; i < 200; ++i) write_file(dir / ("new" + std::to_string(i) + ".txt"), "n");
    for (int i = 0; i < 300; i += 3) fs::remove(L(dir / ("item" + std::to_string(i) + ".dat")));
    write_file(dir / "item7.txt", "modified, longer");
    fs::rename(L(dir / "item5.txt"), L(dir / "renamed5.txt"));
    fs::create_directories(dir / "newdir");
    CHECK(h.settle());
    CHECK_MSG(h.names() == expected(dir, sort, false), join(h.names()));
    CHECK(k5 != 0 && h.key("renamed5.txt") == k5);
    bool size_ok = false;
    for (auto& i : h.list) size_ok |= i.entry.name == "item7.txt" && i.entry.size == 16;
    CHECK(size_ok);

    // Snapshot + later updates agree with the host that followed every update.
    auto snap = model.snapshot();
    std::vector<vfs::ModelItem> from_snap = snap.items;
    write_file(dir / "after-snapshot.txt", "a");
    CHECK(model.settle(std::chrono::seconds(20)));
    for (auto& u : model.queue()->drain()) {
        if (u.generation > snap.generation) vfs::apply_update(from_snap, u);
        if (u.generation > h.generation) {
            h.generation = u.generation;
            vfs::apply_update(h.list, u);
        }
    }
    bool snap_ok = from_snap.size() == h.list.size();
    for (size_t i = 0; snap_ok && i < from_snap.size(); ++i) snap_ok = from_snap[i].key == h.list[i].key;
    CHECK(snap_ok);

    // Filter: only .txt, hidden shown.
    auto txt = [](const vfs::FileEntry& e) { return e.name.size() > 4 && e.name.substr(e.name.size() - 4) == ".txt"; };
    model.set_filter(txt, true);
    CHECK(h.settle());
    CHECK_MSG(h.names() == expected(dir, sort, true, txt), join(h.names()));
    model.set_filter(nullptr, true);
    CHECK(h.settle());
    CHECK_MSG(h.names() == expected(dir, sort, true), join(h.names()));

    // Sort by size, descending, directories not first.
    vfs::SortSpec by_size;
    by_size.field = vfs::SortField::Size;
    by_size.descending = true;
    by_size.directories_first = false;
    model.set_sort(by_size);
    CHECK(h.settle());
    CHECK_MSG(h.names() == expected(dir, by_size, true), join(h.names()));
    write_file(dir / "item1.txt", std::string(100, 'x')); // grows: the largest file now
    CHECK(h.settle());
    std::string first_file;
    for (auto& i : h.list) {
        if (i.entry.kind == vfs::FileKind::Regular) {
            first_file = i.entry.name;
            break;
        }
    }
    CHECK_MSG(first_file == "item1.txt", first_file);
    CHECK_MSG(h.names() == expected(dir, by_size, true), join(h.names()));

    // refresh() reconciles with a full listing; on a live model nothing changes.
    model.refresh();
    CHECK(h.settle());
    CHECK_MSG(h.names() == expected(dir, by_size, true), join(h.names()));

    // The directory itself goes away.
    std::error_code ec;
    fs::rename(L(dir), L(s / "live-moved"), ec);
    if (ec) {
        note("cannot rename the watched directory here (" + ec.message() + "); removal case skipped");
        return;
    }
    bool gone = false;
    for (int i = 0; i < 200 && !gone; ++i) {
        model.queue()->wait_for(std::chrono::milliseconds(50));
        h.pump();
        gone = h.state == vfs::ModelState::Gone;
    }
    CHECK(gone && h.list.empty());
}

void test_failed(const Scratch& s) {
    section("a directory that cannot be listed is Failed, with the reason");
    vfs::DirectoryModel model(s / "does-not-exist");
    Host h(model);
    CHECK(h.settle());
    CHECK(h.state == vfs::ModelState::Failed && h.list.empty());
    CHECK(model.snapshot().error);
}

// ------------------------------------------------------------------ selection totals

void test_aggregate(const Scratch& s) {
    section("selection totals: counts, bytes, hard links once, cancellation");
    fs::path a = s / "agg" / "a";
    for (int i = 0; i < 50; ++i) write_file(a / "sub" / ("f" + std::to_string(i)), std::string(static_cast<size_t>(i), 'x'));
    write_file(s / "agg" / "single.bin", std::string(1000, 'y'));
    fs::create_directories(s / "agg" / "a" / "empty");
    std::error_code ec;
    fs::create_hard_link(L(a / "sub" / "f10"), L(a / "sub" / "f10-link"), ec);
    const bool linked = !ec;
    int calls = 0;
    auto agg = vfs::aggregate_selection({a, s / "agg" / "single.bin", s / "agg" / "missing"},
                                        [&](const vfs::SelectionTotals&) { ++calls; });
    auto t = agg->wait();
    CHECK(t.finished && !t.cancelled && calls >= 1);
    // a, a/sub, a/empty = 3 directories; 50 files + single.bin (+ the link, counted once on POSIX).
    CHECK_MSG(t.directories == 3, std::to_string(t.directories));
    uint64_t want_files = 51;
    uint64_t want_bytes = 49 * 50 / 2 + 1000;
#ifdef _WIN32
    if (linked) { // Windows listings carry no link count: each name counts
        ++want_files;
        want_bytes += 10;
    }
#endif
    CHECK_MSG(t.files == want_files && t.bytes == want_bytes, std::to_string(t.files) + " " + std::to_string(t.bytes));
    CHECK(t.errors == 1 && agg->errors().size() == 1); // the missing path
    (void)linked;

    // Cancellation of a large selection stops early and says so.
    fs::path big = s / "agg" / "big";
    for (int d = 0; d < 40; ++d) {
        for (int i = 0; i < 100; ++i) write_file(big / std::to_string(d) / std::to_string(i), "z");
    }
    std::atomic<bool> seen{false};
    auto slow = vfs::aggregate_selection({big}, [&](const vfs::SelectionTotals&) {
        seen = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }, vfs::AggregateOptions{true, true, std::chrono::milliseconds(0)});
    while (!seen) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    slow->cancel();
    auto ct = slow->wait();
    CHECK(ct.cancelled && !ct.finished && ct.items() < 4041);
}

} // namespace

int main() {
    Scratch s("model");
    test_natural();
    test_view_random();
    test_live(s);
    test_failed(s);
    test_aggregate(s);
    return finish("test_model");
}
