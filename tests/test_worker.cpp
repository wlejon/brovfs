// FileOpsWorker: pause / resume / cancel (running, paused, pending), wait_all, completion
// callbacks, conflict resolver on the worker thread, destruction with work in flight.
#include "brovfs/worker.h"
#include "harness.h"

#include <atomic>
#include <thread>

using namespace t;

static void wait_until(const std::function<bool()>& pred, int ms = 10000) {
    for (int i = 0; i < ms && !pred(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

static void test_pause_resume(const Scratch& s) {
    section("pause holds still; resume completes byte-identical");
    fs::path src = s / "big" / "big.bin";
    write_big(src, 256ull << 20, 'k');
    fs::create_directories(s / "out1");
    vfs::FileOpsWorker w;
    vfs::FileOpOptions o;
    o.allow_reflink = false;
    auto id = w.submit_copy({src}, s / "out1", o);
    wait_until([&] { return w.progress(id).bytes_processed > 0 || w.status(id) == vfs::OpStatus::Completed; });
    bool paused = w.pause(id);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto b1 = w.progress(id).bytes_processed;
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    auto b2 = w.progress(id).bytes_processed;
    note("paused at " + std::to_string(b1) + " -> " + std::to_string(b2));
    if (w.status(id) != vfs::OpStatus::Completed) {
        CHECK(paused && w.status(id) == vfs::OpStatus::Paused);
        CHECK(b1 == b2 && b1 < (256ull << 20));
    } else {
        note("copy finished before pause took effect (fast disk); pause assertions skipped");
    }
    CHECK(w.resume(id) || w.status(id) == vfs::OpStatus::Completed);
    w.wait(id);
    CHECK(w.status(id) == vfs::OpStatus::Completed && w.result(id).ok());
    CHECK(same_content(src, s / "out1" / "big.bin"));
}

static void test_cancel(const Scratch& s) {
    section("cancel running, paused and pending jobs");
    fs::path src = s / "big" / "big.bin";
    fs::create_directories(s / "out2");
    fs::create_directories(s / "out3");
    fs::create_directories(s / "out4");
    vfs::FileOpsWorker w;
    vfs::FileOpOptions o;
    o.allow_reflink = false;
    std::atomic<int> completions{0};
    auto on_done = [&](vfs::JobId, const vfs::OpResult&) { ++completions; };

    // Hold the first job in Paused so the queue order is deterministic.
    auto running = w.submit_copy({src}, s / "out2", o, nullptr, on_done);
    w.pause(running);
    auto pending = w.submit_copy({src}, s / "out3", o, nullptr, on_done);
    CHECK(w.status(pending) == vfs::OpStatus::Pending);
    CHECK(w.cancel(pending));
    CHECK(w.status(pending) == vfs::OpStatus::Cancelled);
    w.wait(pending); // returns at once

    double c0 = now_ms();
    CHECK(w.cancel(running));
    w.wait(running);
    note("cancel of a paused job took " + std::to_string(now_ms() - c0) + " ms");
    CHECK(w.status(running) == vfs::OpStatus::Cancelled);

    std::atomic<bool> returned{false};
    std::thread waiter([&] {
        w.wait_all();
        returned = true;
    });
    wait_until([&] { return returned.load(); }, 3000);
    CHECK(returned.load());
    if (!returned) {
        std::cout << "wait_all() hung; aborting\n";
        std::_Exit(1);
    }
    waiter.join();
    CHECK(!path_exists(s / "out3" / "big.bin")); // the pending job never ran
    CHECK(!path_exists(s / "out2" / "big.bin"));
    CHECK(size_of(src) == (256ull << 20));

    auto live = w.submit_copy({src}, s / "out4", o, nullptr, on_done);
    wait_until([&] { return w.progress(live).bytes_processed > (8u << 20) || w.status(live) == vfs::OpStatus::Completed; });
    c0 = now_ms();
    w.cancel(live);
    w.wait(live);
    double latency = now_ms() - c0;
    note("cancel latency " + std::to_string(latency) + " ms");
    if (w.status(live) == vfs::OpStatus::Cancelled) {
        CHECK(!path_exists(s / "out4" / "big.bin"));
        CHECK(latency < 2000);
    }
    wait_until([&] { return completions.load() == 3; }, 2000);
    CHECK(completions.load() == 3);
}

static void test_resolver_and_results(const Scratch& s) {
    section("resolver runs on the worker thread; results are detailed");
    write_file(s / "cf" / "src" / "a.txt", "new");
    write_file(s / "cf" / "dst" / "a.txt", "old");
    vfs::FileOpsWorker w;
    std::thread::id resolver_thread;
    vfs::FileOpOptions o;
    o.on_conflict = [&](const vfs::Conflict&) {
        resolver_thread = std::this_thread::get_id();
        return vfs::ConflictAction::KeepBoth;
    };
    vfs::OpResult seen;
    auto id = w.submit_copy({s / "cf" / "src" / "a.txt"}, s / "cf" / "dst", o, nullptr,
                            [&](vfs::JobId, const vfs::OpResult& r) { seen = r; });
    w.wait(id);
    CHECK(resolver_thread != std::thread::id() && resolver_thread != std::this_thread::get_id());
    CHECK(w.result(id).ok() && read_file(s / "cf" / "dst" / "a (2).txt") == "new");

    auto bad = w.submit_copy({s / "cf" / "missing.txt"}, s / "cf" / "dst");
    w.wait(bad);
    CHECK(w.status(bad) == vfs::OpStatus::Failed && w.result(bad).errors.size() == 1);

    auto mv = w.submit_move({s / "cf" / "src" / "a.txt"}, s / "cf" / "moved_dir_missing");
    w.wait(mv);
    CHECK(w.status(mv) == vfs::OpStatus::Failed && path_exists(s / "cf" / "src" / "a.txt"));

    write_file(s / "cf" / "gone" / "x", "x");
    auto rm = w.submit_remove({s / "cf" / "gone"});
    w.wait(rm);
    CHECK(w.status(rm) == vfs::OpStatus::Completed && !path_exists(s / "cf" / "gone"));
    w.wait_all();
}

static void test_destroy_busy(const Scratch& s) {
    section("destroying the worker with jobs in flight does not hang");
    fs::create_directories(s / "out5");
    double t0 = now_ms();
    {
        vfs::FileOpsWorker w;
        w.submit_copy({s / "big" / "big.bin"}, s / "out5");
        w.submit_copy({s / "big" / "big.bin"}, s / "out5");
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    CHECK(now_ms() - t0 < 5000);
}

int main() {
    Scratch s("worker");
    test_pause_resume(s);
    test_cancel(s);
    test_resolver_and_results(s);
    test_destroy_busy(s);
    return finish("test_worker");
}
