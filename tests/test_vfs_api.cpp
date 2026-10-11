#include "../src/api/api.h"
#include "embed/embed.h"
#include "eval/eval.h"
#include "brovfs/vfs.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "CHECK failed: " #cond " (" << __FILE__ << ":"        \
                      << __LINE__ << ")" << std::endl;                         \
            std::exit(1);                                                      \
        }                                                                      \
    } while (0)

#define CHECK_MSG(cond, msg)                                                   \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::cerr << "CHECK failed: " #cond " (" << __FILE__ << ":"        \
                      << __LINE__ << "): " << (msg) << std::endl;              \
            std::exit(1);                                                      \
        }                                                                      \
    } while (0)

namespace {

void writeFile(const std::filesystem::path& p, const std::string& content) {
    std::filesystem::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << content;
}

std::string readFile(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
}

// A path as the body of a single-quoted JS string literal. Windows paths are
// full of backslashes ("C:\Users\...\Temp\brovfs_api_test_..."), which JS
// would read as escapes (\b is a backspace), so they are escaped here.
std::string jsPath(const std::filesystem::path& p) {
    std::string out;
    for (char c : p.string()) {
        if (c == '\\' || c == '\'') out += '\\';
        out += c;
    }
    return out;
}

bool pumpUntil(const std::function<bool()>& condition, int timeoutMs = 5000) {
    namespace ev = bronze::embed;
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start)
               .count() < timeoutMs) {
        brovfs::api::tickVfsAsync();
        ev::drainMicrotasks();
        if (condition()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    brovfs::api::tickVfsAsync();
    ev::drainMicrotasks();
    return condition();
}

} // namespace

int main() {
    namespace ev = bronze::embed;
    using namespace bronze::eval;

    std::cout << "Starting brovfs JavaScript API test..." << std::endl;

    // 1. Create temporary directory
    auto tmpDir = std::filesystem::temp_directory_path() /
                  ("brovfs_api_test_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(tmpDir);

    // Create an isolated trash backend for tests so we don't touch system trash
    std::filesystem::path trashHome = tmpDir / "home_trash";
    std::filesystem::create_directories(trashHome);

#ifndef _WIN32
    bro::vfs::FreedesktopTrashConfig trashCfg;
    trashCfg.home_trash = trashHome;
    trashCfg.allow_home_trash_across_devices = true;
    auto testTrash = bro::vfs::make_freedesktop_trash(trashCfg);
#else

    auto testTrash = bro::vfs::system_trash();
#endif
    brovfs::api::setTrash(testTrash);
    auto testJournal = std::make_shared<bro::vfs::UndoJournal>(testTrash, 100);
    brovfs::api::setJournal(testJournal);

    // 2. Install bro.vfs into Bronze realm
    brovfs::api::installVfs();

    auto g = ev::globalValue("bro");
    CHECK(g.found);
    CHECK(ev::isObject(g.value));

    ev::Persistent vfs(ev::getProperty(g.value, "vfs"));
    CHECK(ev::isObject(vfs.get()));
    std::cout << "  Mounted bro.vfs successfully." << std::endl;

    // Verify expected methods and classes exist
    const char* methods[] = {
        "scan", "copy", "move", "remove", "trash", "restoreTrash",
        "listTrash", "emptyTrash", "undo", "redo", "canUndo", "canRedo",
        "watch", "getMime", "listVolumes"
    };
    for (const char* m : methods) {
        auto fn = ev::getProperty(vfs.get(), m);
        CHECK_MSG(ev::isFunction(fn), std::string("Expected bro.vfs.") + m + " to be a function");
        std::cout << "  Found bro.vfs." << m << std::endl;
    }
    auto dmCtor = ev::getProperty(vfs.get(), "DirectoryModel");
    CHECK_MSG(ev::isFunction(dmCtor), "Expected bro.vfs.DirectoryModel constructor");
    std::cout << "  Found bro.vfs.DirectoryModel" << std::endl;

    // 3. Test getMime and listVolumes
    std::cout << "Testing getMime and listVolumes..." << std::endl;
    {
        auto testFile = tmpDir / "test.txt";
        writeFile(testFile, "Hello text world\n");
        auto jsonFile = tmpDir / "data.json";
        writeFile(jsonFile, "{\"name\":\"bro\"}\n");

        std::string script =
            "(function() {\n"
            "  const mTxt = bro.vfs.getMime('" + jsPath(testFile) + "');\n"
            "  const mJson = bro.vfs.getMime('" + jsPath(jsonFile) + "');\n"
            "  if (mTxt !== 'text/plain') return false;\n"
            "  if (mJson !== 'application/json') return false;\n"
            "  const vols = bro.vfs.listVolumes();\n"
            "  if (!Array.isArray(vols) || vols.length === 0) return false;\n"
            "  if (typeof vols[0].mountPoint !== 'string') return false;\n"
            "  if (typeof vols[0].totalBytes !== 'number') return false;\n"
            "  return true;\n"
            "})()\n";
        auto r = evalScript(script);
        CHECK(!r.thrown);
        CHECK(ev::isBool(r.value) && ev::toBool(r.value));
        std::cout << "  getMime and listVolumes [PASS]" << std::endl;
    }

    // 4. Test scan(path, options)
    std::cout << "Testing scan (Promise)..." << std::endl;
    {
        auto scanDir = tmpDir / "scan_target";
        writeFile(scanDir / "file1.txt", "1");
        writeFile(scanDir / "file2.txt", "22");
        writeFile(scanDir / "sub" / "file3.txt", "333");
        writeFile(scanDir / ".hidden.txt", "secret");
#ifdef _WIN32
        // A leading dot hides a file on POSIX only; Windows hides by attribute.
        SetFileAttributesW((scanDir / ".hidden.txt").c_str(), FILE_ATTRIBUTE_HIDDEN);
#endif

        std::string script =
            "(function() {\n"
            "  globalThis._scanDone = false;\n"
            "  globalThis._scanEntries = null;\n"
            "  bro.vfs.scan('" + jsPath(scanDir) + "', { recursive: true, includeHidden: true })\n"
            "    .then(entries => {\n"
            "      globalThis._scanDone = true;\n"
            "      globalThis._scanEntries = entries;\n"
            "    }).catch(err => {\n"
            "      globalThis._scanDone = true;\n"
            "      globalThis._scanError = err.message;\n"
            "    });\n"
            "  return true;\n"
            "})()\n";
        auto r = evalScript(script);
        CHECK(!r.thrown);

        bool finished = pumpUntil([]() {
            auto v = evalScript("globalThis._scanDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK(finished);

        auto checkRes = evalScript(
            "(function() {\n"
            "  const entries = globalThis._scanEntries;\n"
            "  if (!Array.isArray(entries)) return 'no entries: ' + globalThis._scanError;\n"
            "  const names = entries.map(e => e.name);\n"
            "  if (entries.length !== 5) return 'expected 5 entries, got ' + names.join(',');\n" // file1, file2, sub, file3, .hidden
            "  for (const n of ['file1.txt', 'sub', 'file3.txt', '.hidden.txt'])\n"
            "    if (!names.includes(n)) return 'missing ' + n + ' in ' + names.join(',');\n"
            "  const f1 = entries.find(e => e.name === 'file1.txt');\n"
            "  if (!f1.isRegular || f1.size !== 1) return 'file1.txt: ' + JSON.stringify(f1);\n"
            "  const sub = entries.find(e => e.name === 'sub');\n"
            "  if (!sub.isDirectory) return 'sub: ' + JSON.stringify(sub);\n"
            "  const hid = entries.find(e => e.name === '.hidden.txt');\n"
            "  if (!hid.isHidden) return '.hidden.txt: ' + JSON.stringify(hid);\n"
            "  return true;\n"
            "})()\n"
        );
        CHECK(!checkRes.thrown);
        CHECK_MSG(ev::isBool(checkRes.value) && ev::toBool(checkRes.value),
                  ev::isString(checkRes.value) ? ev::toUtf8(checkRes.value) : std::string("?"));
        std::cout << "  scan [PASS]" << std::endl;
    }

    // 5. Test copy(src, dst, options), undo(), redo(), canUndo(), canRedo()
    std::cout << "Testing copy, undo, redo..." << std::endl;
    {
        auto srcFile = tmpDir / "copy_src.txt";
        auto dstFile = tmpDir / "copy_dst.txt";
        writeFile(srcFile, "copy contents");

        std::string script =
            "(function() {\n"
            "  globalThis._copyDone = false;\n"
            "  globalThis._copyRes = null;\n"
            "  bro.vfs.copy('" + jsPath(srcFile) + "', '" + jsPath(dstFile) + "')\n"
            "    .then(res => {\n"
            "      globalThis._copyDone = true;\n"
            "      globalThis._copyRes = res;\n"
            "    });\n"
            "  return true;\n"
            "})()\n";
        evalScript(script);

        bool finished = pumpUntil([]() {
            auto v = evalScript("globalThis._copyDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK(finished);
        CHECK(readFile(dstFile) == "copy contents");

        auto canUndoRes = evalScript("bro.vfs.canUndo();");
        CHECK(!canUndoRes.thrown && ev::isBool(canUndoRes.value) && ev::toBool(canUndoRes.value));

        // Test undo
        evalScript(
            "(function() {\n"
            "  globalThis._undoDone = false;\n"
            "  globalThis._undoOk = false;\n"
            "  bro.vfs.undo().then(ok => {\n"
            "    globalThis._undoDone = true;\n"
            "    globalThis._undoOk = ok;\n"
            "  });\n"
            "  return true;\n"
            "})()\n"
        );
        finished = pumpUntil([]() {
            auto v = evalScript("globalThis._undoDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK(finished);
        CHECK(!std::filesystem::exists(dstFile)); // destination removed by undo
        CHECK(std::filesystem::exists(srcFile));  // source preserved

        auto canRedoRes = evalScript("bro.vfs.canRedo();");
        CHECK(!canRedoRes.thrown && ev::isBool(canRedoRes.value) && ev::toBool(canRedoRes.value));

        // Test redo
        evalScript(
            "(function() {\n"
            "  globalThis._redoDone = false;\n"
            "  globalThis._redoOk = false;\n"
            "  bro.vfs.redo().then(ok => {\n"
            "    globalThis._redoDone = true;\n"
            "    globalThis._redoOk = ok;\n"
            "  });\n"
            "  return true;\n"
            "})()\n"
        );
        finished = pumpUntil([]() {
            auto v = evalScript("globalThis._redoDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK(finished);
        CHECK(readFile(dstFile) == "copy contents"); // re-copied
        std::cout << "  copy, undo, redo [PASS]" << std::endl;
    }

    // 6. Test move(src, dst) and remove(path)
    std::cout << "Testing move and remove..." << std::endl;
    {
        auto fileA = tmpDir / "move_a.txt";
        auto fileB = tmpDir / "move_b.txt";
        writeFile(fileA, "to be moved");

        std::string script =
            "(function() {\n"
            "  globalThis._moveDone = false;\n"
            "  bro.vfs.move('" + jsPath(fileA) + "', '" + jsPath(fileB) + "')\n"
            "    .then(res => {\n"
            "      globalThis._moveDone = true;\n"
            "      globalThis._moveRes = res;\n"
            "    });\n"
            "  return true;\n"
            "})()\n";
        evalScript(script);

        bool finished = pumpUntil([]() {
            auto v = evalScript("globalThis._moveDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK(finished);
        CHECK(!std::filesystem::exists(fileA));
        CHECK(readFile(fileB) == "to be moved");

        // Remove fileB
        script =
            "(function() {\n"
            "  globalThis._rmDone = false;\n"
            "  bro.vfs.remove('" + jsPath(fileB) + "')\n"
            "    .then(res => {\n"
            "      globalThis._rmDone = true;\n"
            "    });\n"
            "  return true;\n"
            "})()\n";
        evalScript(script);

        finished = pumpUntil([]() {
            auto v = evalScript("globalThis._rmDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK(finished);
        CHECK(!std::filesystem::exists(fileB));
        std::cout << "  move and remove [PASS]" << std::endl;
    }

    // 7. Test trash(path), listTrash(), restoreTrash(id)
    std::cout << "Testing trash, listTrash, restoreTrash..." << std::endl;
    {
        auto fileToTrash = tmpDir / "trash_victim.txt";
        writeFile(fileToTrash, "rubbish");

        std::string script =
            "(function() {\n"
            "  globalThis._trashDone = false;\n"
            "  globalThis._trashEntry = null;\n"
            "  bro.vfs.trash('" + jsPath(fileToTrash) + "')\n"
            "    .then(entry => {\n"
            "      globalThis._trashDone = true;\n"
            "      globalThis._trashEntry = entry;\n"
            "    });\n"
            "  return true;\n"
            "})()\n";
        evalScript(script);

        bool finished = pumpUntil([]() {
            auto v = evalScript("globalThis._trashDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK(finished);
        CHECK(!std::filesystem::exists(fileToTrash));

        auto rCheck = evalScript(
            "(function() {\n"
            "  const e = globalThis._trashEntry;\n"
            "  if (!e || typeof e.id !== 'string' || e.id.length === 0) return false;\n"
            "  if (e.name !== 'trash_victim.txt') return false;\n"
            "  return true;\n"
            "})()\n"
        );
        CHECK(!rCheck.thrown && ev::isBool(rCheck.value) && ev::toBool(rCheck.value));

        // List trash
        evalScript(
            "(function() {\n"
            "  globalThis._listDone = false;\n"
            "  globalThis._listTrash = null;\n"
            "  bro.vfs.listTrash().then(items => {\n"
            "    globalThis._listDone = true;\n"
            "    globalThis._listTrash = items;\n"
            "  });\n"
            "  return true;\n"
            "})()\n"
        );
        finished = pumpUntil([]() {
            auto v = evalScript("globalThis._listDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK(finished);

        auto rListCheck = evalScript(
            "(function() {\n"
            "  const list = globalThis._listTrash;\n"
            "  if (!Array.isArray(list) || list.length === 0) return false;\n"
            "  return list.some(item => item.id === globalThis._trashEntry.id);\n"
            "})()\n"
        );
        CHECK(!rListCheck.thrown && ev::isBool(rListCheck.value) && ev::toBool(rListCheck.value));

        // Restore trash
        evalScript(
            "(function() {\n"
            "  globalThis._restoreDone = false;\n"
            "  globalThis._restoreOk = false;\n"
            "  bro.vfs.restoreTrash(globalThis._trashEntry.id).then(ok => {\n"
            "    globalThis._restoreDone = true;\n"
            "    globalThis._restoreOk = ok;\n"
            "  });\n"
            "  return true;\n"
            "})()\n"
        );
        finished = pumpUntil([]() {
            auto v = evalScript("globalThis._restoreDone;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        });
        CHECK(finished);
        CHECK(std::filesystem::exists(fileToTrash));
        CHECK(readFile(fileToTrash) == "rubbish");
        std::cout << "  trash, listTrash, restoreTrash [PASS]" << std::endl;
    }

    // 8. Test watch(path, cb)
    std::cout << "Testing watch..." << std::endl;
    {
        auto watchDir = tmpDir / "watched_folder";
        std::filesystem::create_directories(watchDir);

        std::string script =
            "(function() {\n"
            "  globalThis._events = [];\n"
            "  globalThis._watchHandle = bro.vfs.watch('" + jsPath(watchDir) + "', (events) => {\n"
            "    for (const e of events) globalThis._events.push(e);\n"
            "  }, { latency: 20 });\n"
            "  return (typeof globalThis._watchHandle === 'object' && typeof globalThis._watchHandle.unwatch === 'function');\n"
            "})()\n";
        auto r = evalScript(script);
        CHECK(!r.thrown && ev::isBool(r.value) && ev::toBool(r.value));

        // Allow watcher to settle and start
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        // Create a file in watched directory
        auto newFile = watchDir / "created_by_test.txt";
        writeFile(newFile, "watch me");

        bool received = pumpUntil([]() {
            auto v = evalScript("globalThis._events.length;");
            return !v.thrown && ev::isNumber(v.value) && ev::toDouble(v.value) > 0.0;
        }, 3000);
        CHECK(received);

        auto rEventCheck = evalScript(
            "(function() {\n"
            "  if (globalThis._events.length === 0) return false;\n"
            "  const ev0 = globalThis._events[0];\n"
            "  if (typeof ev0.kind !== 'string') return false;\n"
            "  if (typeof ev0.path !== 'string') return false;\n"
            "  return true;\n"
            "})()\n"
        );
        CHECK(!rEventCheck.thrown && ev::isBool(rEventCheck.value) && ev::toBool(rEventCheck.value));

        // Unwatch
        evalScript("globalThis._watchHandle.unwatch();");
        std::cout << "  watch [PASS]" << std::endl;
    }

    // 9. Test DirectoryModel
    std::cout << "Testing DirectoryModel..." << std::endl;
    {
        auto modelDir = tmpDir / "model_folder";
        writeFile(modelDir / "c_file.txt", "c");
        writeFile(modelDir / "a_file.txt", "a");
        writeFile(modelDir / "b_file.txt", "b");

        std::string script =
            "(function() {\n"
            "  globalThis._model = new bro.vfs.DirectoryModel('" + jsPath(modelDir) + "');\n"
            "  return (typeof globalThis._model.entries === 'function');\n"
            "})()\n";
        auto r = evalScript(script);
        CHECK(!r.thrown && ev::isBool(r.value) && ev::toBool(r.value));

        // Wait for model initial load
        bool loaded = pumpUntil([]() {
            auto v = evalScript("globalThis._model.entries().length;");
            return !v.thrown && ev::isNumber(v.value) && ev::toDouble(v.value) == 3.0;
        }, 3000);
        CHECK(loaded);

        // The setters are asynchronous (dir_model.h): each takes effect on the
        // model thread, so wait for the entries to show it.
        auto modelShows = [](const char* check) {
            return pumpUntil([check]() {
                auto v = evalScript(std::string("(function() {\n"
                                                "  const entries = globalThis._model.entries();\n") +
                                    check + "\n})()\n");
                return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
            }, 3000);
        };

        // Test sorting
        evalScript("globalThis._model.setSort('name', true);");
        CHECK(modelShows("  return entries.length === 3 && entries[0].name === 'a_file.txt' &&\n"
                         "         entries[1].name === 'b_file.txt' && entries[2].name === 'c_file.txt';"));

        // Test filtering
        evalScript("globalThis._model.setFilter('b_');");
        CHECK(modelShows("  return entries.length === 1 && entries[0].name === 'b_file.txt';"));

        // Reset filter
        evalScript("globalThis._model.setFilter('');");
        CHECK(modelShows("  return entries.length === 3;"));

        // Test change callback
        evalScript(
            "(function() {\n"
            "  globalThis._modelChanged = false;\n"
            "  globalThis._model.on('change', () => {\n"
            "    globalThis._modelChanged = true;\n"
            "  });\n"
            "  return true;\n"
            "})()\n"
        );

        // Add a new file to trigger change
        writeFile(modelDir / "d_file.txt", "d");
        evalScript("globalThis._model.refresh();");


        bool changeNotified = pumpUntil([]() {
            auto v = evalScript("globalThis._modelChanged;");
            return !v.thrown && ev::isBool(v.value) && ev::toBool(v.value);
        }, 3000);
        CHECK(changeNotified);

        auto rCount4 = evalScript("globalThis._model.entries().length;");
        CHECK(!rCount4.thrown && ev::isNumber(rCount4.value) && ev::toDouble(rCount4.value) == 4.0);

        std::cout << "  DirectoryModel [PASS]" << std::endl;
    }

    // 10. Clean up
    brovfs::api::shutdownVfsAsync();
    std::filesystem::remove_all(tmpDir);

    std::cout << "All brovfs API tests PASSED!" << std::endl;
    return 0;
}
