#include "host_vfs_internal.h"
#include "brovfs/path.h"
#include "brovfs/watcher.h"

#include <filesystem>
#include <mutex>
#include <unordered_map>

namespace brovfs::api {

namespace {

struct ActiveWatch {
    bro::vfs::WatchId id{0};
    std::unique_ptr<ev::Persistent> callback;
    std::filesystem::path path;
    uint64_t held{0};  // the gate's ledger entry (holdPath), 0 when none
};

// A watch the host took the grant back from: already stopped, its callback
// told at the next drain with one 'error' event carrying the refusal.
struct RevokedWatch {
    bro::vfs::WatchId id{0};
    std::unique_ptr<ev::Persistent> callback;
    std::filesystem::path path;
    std::string refusal;
};

std::mutex g_watch_mu;
std::shared_ptr<bro::vfs::DirectoryWatcher> g_watcher;
std::unordered_map<bro::vfs::WatchId, ActiveWatch> g_watchers;
std::vector<RevokedWatch> g_revoked;

void revokeWatch(bro::vfs::WatchId wid, const std::string& refusal) {
    std::lock_guard lock(g_watch_mu);
    auto it = g_watchers.find(wid);
    if (it == g_watchers.end()) return;
    if (g_watcher) g_watcher->remove(wid);
    RevokedWatch r;
    r.id = wid;
    r.callback = std::move(it->second.callback);
    r.path = std::move(it->second.path);
    r.refusal = refusal;
    g_revoked.push_back(std::move(r));
    g_watchers.erase(it);
}

void deliverRevokedWatches() {
    std::vector<RevokedWatch> revoked;
    {
        std::lock_guard lock(g_watch_mu);
        revoked = std::move(g_revoked);
        g_revoked.clear();
    }
    for (auto& r : revoked) {
        if (!r.callback || !ev::isFunction(r.callback->get())) continue;
        ObjectBuilder b;
        b.set("kind", std::string("error"));
        b.set("watch", static_cast<double>(r.id));
        b.set("path", bro::vfs::path_to_utf8(r.path));
        ev::Persistent item(b.get());
        ev::Persistent err(newRevokedError(r.refusal, r.path));
        item.set(ev::setProperty(item.get(), "error", err.get()));
        ev::Persistent arr(ev::makeArray(1));
        arr.set(ev::setElement(arr.get(), 0, item.get()));
        const Value arg = arr.get();
        ev::call(r.callback->get(), ev::undefined(), std::span<const Value>(&arg, 1));
    }
}

} // namespace

void drainWatcherEvents() {
    deliverRevokedWatches();
    std::vector<bro::vfs::WatchEvent> events;
    {
        std::lock_guard lock(g_watch_mu);
        if (!g_watcher) return;
        events = g_watcher->queue()->drain();
    }
    if (events.empty()) return;

    // Group events by WatchId
    std::unordered_map<bro::vfs::WatchId, std::vector<bro::vfs::WatchEvent>> grouped;
    for (auto& evItem : events) {
        grouped[evItem.watch].push_back(std::move(evItem));
    }

    for (const auto& [wid, evList] : grouped) {
        ev::Persistent cb;
        {
            std::lock_guard lock(g_watch_mu);
            auto it = g_watchers.find(wid);
            if (it == g_watchers.end() || !it->second.callback) continue;
            cb.set(it->second.callback->get());
        }

        if (!ev::isFunction(cb.get())) continue;

        ev::Persistent arr(ev::makeArray(static_cast<uint32_t>(evList.size())));
        for (size_t i = 0; i < evList.size(); ++i) {
            ev::Persistent itemVal(watchEventToJs(evList[i]));
            arr.set(ev::setElement(arr.get(), static_cast<uint32_t>(i), itemVal.get()));
        }

        const Value arg = arr.get();
        ev::call(cb.get(), ev::undefined(), std::span<const Value>(&arg, 1));
    }
}

void clearWatchers() {
    std::lock_guard lock(g_watch_mu);
    for (auto& [wid, w] : g_watchers) releaseHeldPath(w.held);
    g_watchers.clear();
    g_revoked.clear();
    g_watcher.reset();
}

void installWatchOnto(Value vfsObj) {
    ObjectBuilder vfs(vfsObj);

    // bro.vfs.watch(path, callback, options?) -> WatchHandle { unwatch() }
    vfs.def("watch", 2, [](Value, std::span<const Value> args) -> Value {
        if (args.size() < 2 || !ev::isString(args[0]) || !ev::isFunction(args[1])) {
            return ev::throwError("bro.vfs.watch requires (path: string, callback: function, options?: object)");
        }

        std::string pathStr = ev::toUtf8(args[0]);
        std::filesystem::path path = std::filesystem::path(pathStr);
        if (auto refused = checkPath(path, PathAccess::Read)) return throwAccessError(refused);

        ev::Persistent cb(args[1]);

        bro::vfs::WatchOptions opts;
        if (args.size() > 2 && ev::isObject(args[2])) {
            ev::Persistent opt(args[2]);
            Value recVal = ev::getProperty(opt.get(), "recursive");
            if (ev::isBool(recVal)) opts.recursive = ev::toBool(recVal);

            Value latVal = ev::getProperty(opt.get(), "latency");
            if (ev::isNumber(latVal)) {
                double ms = ev::toDouble(latVal);
                if (ms >= 0.0) opts.latency = std::chrono::milliseconds(static_cast<int64_t>(ms));
            }
        }

        bro::vfs::WatchId wid = 0;
        {
            std::lock_guard lock(g_watch_mu);
            if (!g_watcher) {
                g_watcher = std::make_shared<bro::vfs::DirectoryWatcher>();
            }
            std::error_code ec;
            wid = g_watcher->add(path, opts, ec);
            if (wid == 0) {
                return ev::throwError("Failed to watch path: " + ec.message());
            }

            ActiveWatch w;
            w.id = wid;
            w.callback = std::make_unique<ev::Persistent>(cb.get());
            w.path = path;
            g_watchers[wid] = std::move(w);
        }
        // Held by its id: a revoke after unwatch finds nothing and does nothing.
        if (uint64_t held = holdPath(path, [wid](const std::string& refusal) { revokeWatch(wid, refusal); })) {
            std::lock_guard lock(g_watch_mu);
            if (auto it = g_watchers.find(wid); it != g_watchers.end()) it->second.held = held;
        }

        ObjectBuilder handle;
        handle.set("id", static_cast<double>(wid));
        handle.def("unwatch", 0, [wid](Value, std::span<const Value>) -> Value {
            std::lock_guard lock(g_watch_mu);
            if (g_watcher) {
                g_watcher->remove(wid);
            }
            if (auto it = g_watchers.find(wid); it != g_watchers.end()) {
                releaseHeldPath(it->second.held);
                g_watchers.erase(it);
            }
            return ev::undefined();
        });

        return handle.get();
    });
}

} // namespace brovfs::api
