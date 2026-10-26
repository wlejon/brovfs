// bro.vfs under a path gate (api.h, "Path gate"): every native that takes a path
// asks the gate first, a refusal is an Error carrying the gate's sentence, code
// EACCES and the path, nothing is touched, and with the gate removed everything
// behaves as before. Run from test_vfs_api.cpp's main against its realm.

#include "../src/api/api.h"
#include "embed/embed.h"
#include "eval/eval.h"
#include "brovfs/path.h"
#include "brovfs/vfs.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
namespace ev = bronze::embed;

#define GCHECK(cond, msg)                                                      \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "CHECK failed: " #cond " (" << __FILE__ << ":"        \
                      << __LINE__ << "): " << (msg) << std::endl;              \
            std::exit(1);                                                      \
        }                                                                      \
    } while (0)

namespace {

void writeFile(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << content;
}

std::string jsStr(const fs::path& p) {
    std::string out = "'";
    for (char c : bro::vfs::path_to_utf8(p)) {
        if (c == '\\' || c == '\'') out += '\\';
        out += c;
    }
    return out + "'";
}

// The path as the gate is handed it.
std::string gatePath(const fs::path& p) {
    return bro::vfs::path_to_utf8(fs::absolute(p).lexically_normal());
}

std::string evalString(const std::string& src) {
    auto r = bronze::eval::evalScript(src);
    if (r.thrown) return "<thrown>";
    return ev::isString(r.value) ? ev::toUtf8(r.value) : "<not a string>";
}

// What a refusal looks like from JS, as one comparable string.
std::string refusal(const fs::path& p) {
    std::string path = gatePath(p);
    return "denied|no files access: " + path + "|EACCES|" + path;
}

const char* kOutcome =
    "  v => 'ok:' + (typeof v === 'object' && v !== null ? JSON.stringify(v.ok ?? v.length ?? true) : String(v)),\n"
    "  e => 'denied|' + e.message + '|' + e.code + '|' + e.path";

// Runs `expr` (a promise) to completion; "ok:<value>" or the refusal string.
std::string awaitJs(const std::string& expr) {
    bronze::eval::evalScript("globalThis._gateOut = undefined;\n"
                             "Promise.resolve().then(() => " + expr + ").then(\n" + kOutcome +
                             ").then(s => { globalThis._gateOut = s; });");
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < std::chrono::seconds(10)) {
        brovfs::api::tickVfsAsync();
        ev::drainMicrotasks();
        std::string s = evalString("typeof globalThis._gateOut === 'string' ? globalThis._gateOut : ''");
        if (!s.empty()) return s;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return "<timeout>";
}

// Runs `stmt` synchronously; "ok" or the refusal string.
std::string syncJs(const std::string& stmt) {
    return evalString("(function() { try { " + stmt + "; return 'ok'; } catch (e) {\n"
                      "  return 'denied|' + e.message + '|' + e.code + '|' + e.path; } })()");
}

// A trash in a folder of its own, so these tests never touch the system's.
class FolderTrash : public bro::vfs::Trash {
public:
    explicit FolderTrash(fs::path dir) : dir_(std::move(dir)) { fs::create_directories(dir_); }
    bool trash(const fs::path& path, std::string* out_id, std::error_code& ec) override {
        std::lock_guard lock(mu_);
        bro::vfs::TrashItem item;
        item.id = std::to_string(++next_);
        item.original_path = path;
        item.stored_path = dir_ / item.id;
        item.name = path.filename().string();
        fs::rename(path, item.stored_path, ec);
        if (ec) return false;
        if (out_id) *out_id = item.id;
        items_.push_back(item);
        return true;
    }
    std::vector<bro::vfs::TrashItem> list(std::vector<bro::vfs::ItemError>*) override {
        std::lock_guard lock(mu_);
        return items_;
    }
    bool restore(const std::string& id, bro::vfs::RestoreConflict, fs::path* restored_to,
                 std::error_code& ec) override {
        std::lock_guard lock(mu_);
        for (auto it = items_.begin(); it != items_.end(); ++it) {
            if (it->id != id) continue;
            fs::rename(it->stored_path, it->original_path, ec);
            if (ec) return false;
            if (restored_to) *restored_to = it->original_path;
            items_.erase(it);
            return true;
        }
        ec = std::make_error_code(std::errc::no_such_file_or_directory);
        return false;
    }
    bool erase(const std::string& id, std::error_code& ec) override {
        std::lock_guard lock(mu_);
        for (auto it = items_.begin(); it != items_.end(); ++it) {
            if (it->id != id) continue;
            fs::remove_all(it->stored_path, ec);
            items_.erase(it);
            return true;
        }
        return false;
    }
    bro::vfs::OpResult empty() override {
        std::lock_guard lock(mu_);
        std::error_code ec;
        for (const auto& it : items_) fs::remove_all(it.stored_path, ec);
        items_.clear();
        return {};
    }

private:
    std::mutex mu_;
    fs::path dir_;
    int next_ = 0;
    std::vector<bro::vfs::TrashItem> items_;
};

// The gate under test: refuses reading under the noRead prefixes and writing
// under those and the noWrite ones.
struct TestGate {
    std::mutex mu;
    std::vector<std::string> noRead, noWrite;
    std::atomic<int> calls{0};

    static bool under(const std::string& path, const std::vector<std::string>& prefixes) {
        for (const auto& p : prefixes) {
            if (path.compare(0, p.size(), p) == 0) return true;
        }
        return false;
    }
    std::string ask(const std::string& path, brovfs::api::PathAccess access) {
        ++calls;
        std::lock_guard lock(mu);
        const bool refused = under(path, noRead) ||
                             (access == brovfs::api::PathAccess::Write && under(path, noWrite));
        return refused ? "no files access: " + path : "";
    }
    void denyWrite(const fs::path& p) {
        std::lock_guard lock(mu);
        noWrite.push_back(gatePath(p));
    }
    void allowWrite(const fs::path& p) {
        std::lock_guard lock(mu);
        std::erase(noWrite, gatePath(p));
    }
};

} // namespace

void runPathGateTests(const fs::path& tmpDir) {
    std::cout << "Testing the path gate..." << std::endl;

    const fs::path root = tmpDir / "gate";
    const fs::path ok = root / "ok";
    const fs::path hidden = root / "hidden";
    const fs::path readOnly = root / "ro";
    writeFile(ok / "a.txt", "alpha");
    writeFile(hidden / "secret.txt", "secret");
    writeFile(readOnly / "keep.txt", "keep");

    auto prevTrash = brovfs::api::getTrash();
    auto prevJournal = brovfs::api::getJournal();
    auto trash = std::make_shared<FolderTrash>(root / "trash_store");
    brovfs::api::setTrash(trash);
    brovfs::api::setJournal(std::make_shared<bro::vfs::UndoJournal>(trash, 100));

    auto gate = std::make_shared<TestGate>();
    gate->noRead.push_back(gatePath(hidden));
    gate->noWrite.push_back(gatePath(readOnly));
    brovfs::api::setPathGate([gate](const std::string& path, brovfs::api::PathAccess access) {
        return gate->ask(path, access);
    });

    std::string r;

    // Synchronous natives throw.
    r = syncJs("bro.vfs.getMime(" + jsStr(hidden / "secret.txt") + ")");
    GCHECK(r == refusal(hidden / "secret.txt"), r);
    r = syncJs("if (typeof bro.vfs.getMime(" + jsStr(ok / "a.txt") + ") !== 'string') throw new Error('mime')");
    GCHECK(r == "ok", r);
    r = syncJs("bro.vfs.watch(" + jsStr(hidden) + ", () => {})");
    GCHECK(r == refusal(hidden), r);
    r = syncJs("new bro.vfs.DirectoryModel(" + jsStr(hidden) + ")");
    GCHECK(r == refusal(hidden), r);
    r = syncJs("bro.vfs.usage(" + jsStr(hidden) + ")");
    GCHECK(r == refusal(hidden), r);
    r = syncJs("bro.vfs.usage(" + jsStr(ok) + ").cancel()");
    GCHECK(r == "ok", r);

    // Asynchronous natives reject, and leave the disk alone.
    r = awaitJs("bro.vfs.scan(" + jsStr(hidden) + ")");
    GCHECK(r == refusal(hidden), r);
    r = awaitJs("bro.vfs.scan(" + jsStr(ok) + ")");
    GCHECK(r == "ok:1", r);

    r = awaitJs("bro.vfs.copy(" + jsStr(ok / "a.txt") + ", " + jsStr(hidden / "b.txt") + ")");
    GCHECK(r == refusal(hidden / "b.txt"), r);
    GCHECK(!fs::exists(hidden / "b.txt"), "copy wrote a refused destination");
    r = awaitJs("bro.vfs.copy(" + jsStr(hidden / "secret.txt") + ", " + jsStr(ok / "leak.txt") + ")");
    GCHECK(r == refusal(hidden / "secret.txt"), r);
    GCHECK(!fs::exists(ok / "leak.txt"), "copy read a refused source");
    // A read-only source may be copied from but not moved or removed.
    r = awaitJs("bro.vfs.copy(" + jsStr(readOnly / "keep.txt") + ", " + jsStr(ok / "copy.txt") + ")");
    GCHECK(r == "ok:true", r);
    GCHECK(fs::exists(ok / "copy.txt"), "allowed copy did not happen");
    r = awaitJs("bro.vfs.move(" + jsStr(readOnly / "keep.txt") + ", " + jsStr(ok / "moved.txt") + ")");
    GCHECK(r == refusal(readOnly / "keep.txt"), r);
    r = awaitJs("bro.vfs.remove([" + jsStr(ok / "copy.txt") + ", " + jsStr(readOnly / "keep.txt") + "])");
    GCHECK(r == refusal(readOnly / "keep.txt"), r);
    GCHECK(fs::exists(readOnly / "keep.txt") && fs::exists(ok / "copy.txt"), "refused remove removed");
    r = awaitJs("bro.vfs.trash(" + jsStr(readOnly / "keep.txt") + ")");
    GCHECK(r == refusal(readOnly / "keep.txt"), r);
    GCHECK(fs::exists(readOnly / "keep.txt"), "refused trash trashed");
    r = awaitJs("bro.vfs.move(" + jsStr(ok / "copy.txt") + ", " + jsStr(ok / "moved.txt") + ")");
    GCHECK(r == "ok:true", r);
    r = awaitJs("bro.vfs.remove(" + jsStr(ok / "moved.txt") + ")");
    GCHECK(r == "ok:true", r);
    GCHECK(!fs::exists(ok / "moved.txt"), "allowed remove did not remove");

    // Undo and redo ask about what the step will touch.
    r = awaitJs("bro.vfs.copy(" + jsStr(ok / "a.txt") + ", " + jsStr(ok / "u.txt") + ")");
    GCHECK(r == "ok:true", r);
    gate->denyWrite(ok / "u.txt");
    r = awaitJs("bro.vfs.undo()");
    GCHECK(r == refusal(ok / "u.txt"), r);
    GCHECK(fs::exists(ok / "u.txt"), "refused undo removed the copy");
    gate->allowWrite(ok / "u.txt");
    r = awaitJs("bro.vfs.undo()");
    GCHECK(r == "ok:true", r);
    GCHECK(!fs::exists(ok / "u.txt"), "undo did not remove the copy");
    gate->denyWrite(ok / "u.txt");
    r = awaitJs("bro.vfs.redo()");
    GCHECK(r == refusal(ok / "u.txt"), r);
    GCHECK(!fs::exists(ok / "u.txt"), "refused redo copied");
    gate->allowWrite(ok / "u.txt");
    r = awaitJs("bro.vfs.redo()");
    GCHECK(r == "ok:true", r);
    GCHECK(fs::exists(ok / "u.txt"), "redo did not copy");

    // The trash: trashing, listing, restoring and emptying ask about the
    // item's original path.
    trash->empty();  // the undone copy above went to the trash
    writeFile(ok / "t1.txt", "t1");
    writeFile(ok / "t2.txt", "t2");
    r = awaitJs("bro.vfs.trash(" + jsStr(ok / "t1.txt") + ")");
    GCHECK(r == "ok:true", r);
    r = awaitJs("bro.vfs.trash(" + jsStr(ok / "t2.txt") + ")");
    GCHECK(r == "ok:true", r);
    gate->denyWrite(ok / "t2.txt");
    r = awaitJs("bro.vfs.undo()");  // the newest record: t2 back to ok/t2.txt
    GCHECK(r == refusal(ok / "t2.txt"), r);
    r = awaitJs("bro.vfs.emptyTrash()");
    GCHECK(r == refusal(ok / "t2.txt"), r);
    GCHECK(trash->list(nullptr).size() == 2,
           "refused emptyTrash erased: " + std::to_string(trash->list(nullptr).size()) + " left");
    {
        std::lock_guard lock(gate->mu);
        gate->noRead.push_back(gatePath(ok / "t2.txt"));
    }
    r = awaitJs("bro.vfs.listTrash().then(items => items.map(i => i.name).join(','))");
    GCHECK(r == "ok:t1.txt", r);
    std::string t2Id;
    for (const auto& it : trash->list(nullptr)) {
        if (it.name == "t2.txt") t2Id = it.id;
    }
    r = awaitJs("bro.vfs.restoreTrash('" + t2Id + "')");
    GCHECK(r == refusal(ok / "t2.txt"), r);
    GCHECK(!fs::exists(ok / "t2.txt"), "refused restore restored");
    {
        std::lock_guard lock(gate->mu);
        std::erase(gate->noRead, gatePath(ok / "t2.txt"));
    }
    gate->allowWrite(ok / "t2.txt");
    r = awaitJs("bro.vfs.restoreTrash('" + t2Id + "')");
    GCHECK(r == "ok:true", r);
    GCHECK(fs::exists(ok / "t2.txt"), "allowed restore did not restore");
    r = awaitJs("bro.vfs.emptyTrash()");
    GCHECK(r == "ok:undefined", r);
    GCHECK(trash->list(nullptr).empty(), "allowed emptyTrash left items");

    // With the gate removed, nothing asks and everything works as before.
    brovfs::api::setPathGate(nullptr);
    const int callsBefore = gate->calls.load();
    r = syncJs("if (typeof bro.vfs.getMime(" + jsStr(hidden / "secret.txt") + ") !== 'string') throw new Error('mime')");
    GCHECK(r == "ok", r);
    r = awaitJs("bro.vfs.copy(" + jsStr(ok / "a.txt") + ", " + jsStr(hidden / "b.txt") + ")");
    GCHECK(r == "ok:true", r);
    GCHECK(fs::exists(hidden / "b.txt"), "ungated copy did not copy");
    r = awaitJs("bro.vfs.remove(" + jsStr(readOnly / "keep.txt") + ")");
    GCHECK(r == "ok:true", r);
    GCHECK(gate->calls.load() == callsBefore, "a removed gate was still asked");

    brovfs::api::setTrash(prevTrash);
    brovfs::api::setJournal(prevJournal);
    std::cout << "  path gate [PASS]" << std::endl;
}
