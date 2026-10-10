#include "host_vfs_internal.h"
#include "brovfs/path.h"
#include "brovfs/usage.h"

#include <mutex>
#include <vector>

namespace brovfs::api {

namespace {

HostClass g_usageScanClass;

struct WrappedUsage {
    std::unique_ptr<bro::vfs::UsageScan> scan;
    ev::Persistent done; // settles once the scan finishes or is cancelled
    bool settled = false;
};

std::mutex g_usage_mu;
// Held until the scan settles, so `done` settles even if the page drops the scan object.
std::vector<std::shared_ptr<WrappedUsage>> g_active_usage;

std::shared_ptr<WrappedUsage> unwrapUsage(Value self) {
    auto p = static_cast<std::shared_ptr<WrappedUsage>*>(g_usageScanClass.unwrap(self));
    return p ? *p : nullptr;
}

Value progressToJs(const bro::vfs::UsageProgress& p) {
    ObjectBuilder b;
    b.set("files", static_cast<double>(p.files));
    b.set("directories", static_cast<double>(p.directories));
    b.set("bytes", static_cast<double>(p.bytes));
    b.set("errors", static_cast<double>(p.errors));
    b.set("version", static_cast<double>(p.version));
    b.set("finished", p.finished);
    b.set("cancelled", p.cancelled);
    b.set("elapsedMs", p.elapsed_ms);
    return b.get();
}

Value usageItemToJs(const bro::vfs::UsageItem& it) {
    ObjectBuilder b;
    b.set("name", it.name);
    b.set("path", bro::vfs::path_to_utf8(it.path));
    b.set("kind", std::string(to_string(it.kind)));
    b.set("isDirectory", it.is_directory());
    b.set("bytes", static_cast<double>(it.bytes));
    b.set("files", static_cast<double>(it.files));
    b.set("directories", static_cast<double>(it.directories));
    b.set("children", static_cast<double>(it.children));
    b.set("mtime", static_cast<double>(it.mtime_ms));
    b.set("hidden", it.hidden);
    b.set("complete", it.complete);
    return b.get();
}

bool pathArg(std::span<const Value> args, size_t i, std::filesystem::path& out) {
    if (args.size() <= i || !ev::isString(args[i])) return false;
    out = bro::vfs::path_from_utf8(ev::toUtf8(args[i]));
    return true;
}

} // namespace

void drainUsageScans() {
    std::vector<std::shared_ptr<WrappedUsage>> finished;
    {
        std::lock_guard lock(g_usage_mu);
        for (auto it = g_active_usage.begin(); it != g_active_usage.end();) {
            auto p = (*it)->scan->progress();
            if (p.finished || p.cancelled) {
                finished.push_back(*it);
                it = g_active_usage.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& w : finished) {
        if (w->settled) continue;
        w->settled = true;
        ev::Persistent prog(progressToJs(w->scan->progress()));
        ev::resolvePromise(w->done.get(), prog.get());
    }
}

void clearUsageScans() {
    std::vector<std::shared_ptr<WrappedUsage>> scans;
    {
        std::lock_guard lock(g_usage_mu);
        scans = std::move(g_active_usage);
        g_active_usage.clear();
    }
    for (auto& w : scans) w->scan->cancel();
}

void installUsageOnto(Value vfsObj) {
    g_usageScanClass.init("UsageScan", [](ObjectBuilder& proto) {
        // progress() -> { files, directories, bytes, errors, version, finished, cancelled, elapsedMs }
        proto.def("progress", 0, [](Value self, std::span<const Value>) -> Value {
            auto w = unwrapUsage(self);
            if (!w) return ev::undefined();
            return progressToJs(w->scan->progress());
        });

        // children(dir?, { sort: 'bytes' | 'name', limit }) -> Item[] | null
        proto.def("children", 2, [](Value self, std::span<const Value> args) -> Value {
            auto w = unwrapUsage(self);
            if (!w) return ev::null();
            std::filesystem::path dir;
            if (!pathArg(args, 0, dir)) dir = w->scan->root();
            bro::vfs::UsageSort sort = bro::vfs::UsageSort::Bytes;
            size_t limit = 0;
            if (args.size() > 1 && ev::isObject(args[1])) {
                ev::Persistent opt(args[1]);
                Value sortVal = ev::getProperty(opt.get(), "sort");
                if (ev::isString(sortVal) && ev::toUtf8(sortVal) == "name") sort = bro::vfs::UsageSort::Name;
                Value limitVal = ev::getProperty(opt.get(), "limit");
                if (ev::isNumber(limitVal) && ev::toDouble(limitVal) > 0) {
                    limit = static_cast<size_t>(ev::toDouble(limitVal));
                }
            }
            std::vector<bro::vfs::UsageItem> items;
            if (!w->scan->children(dir, items, sort, limit)) return ev::null();
            ev::Persistent arr(ev::makeArray(static_cast<uint32_t>(items.size())));
            for (size_t i = 0; i < items.size(); ++i) {
                ev::Persistent item(usageItemToJs(items[i]));
                arr.set(ev::setElement(arr.get(), static_cast<uint32_t>(i), item.get()));
            }
            return arr.get();
        });

        // entry(path?) -> Item | null
        proto.def("entry", 1, [](Value self, std::span<const Value> args) -> Value {
            auto w = unwrapUsage(self);
            if (!w) return ev::null();
            std::filesystem::path p;
            if (!pathArg(args, 0, p)) p = w->scan->root();
            bro::vfs::UsageItem it;
            if (!w->scan->entry(p, it)) return ev::null();
            return usageItemToJs(it);
        });

        // remove(path) -> boolean
        proto.def("remove", 1, [](Value self, std::span<const Value> args) -> Value {
            auto w = unwrapUsage(self);
            std::filesystem::path p;
            if (!w || !pathArg(args, 0, p)) return ev::fromBool(false);
            return ev::fromBool(w->scan->remove(p));
        });

        // cancel()
        proto.def("cancel", 0, [](Value self, std::span<const Value>) -> Value {
            if (auto w = unwrapUsage(self)) w->scan->cancel();
            return ev::undefined();
        });

        // errors() -> [{ path, message, code }] (the first 100)
        proto.def("errors", 0, [](Value self, std::span<const Value>) -> Value {
            auto w = unwrapUsage(self);
            if (!w) return ev::makeArray(0);
            auto errs = w->scan->errors();
            ev::Persistent arr(ev::makeArray(static_cast<uint32_t>(errs.size())));
            for (size_t i = 0; i < errs.size(); ++i) {
                ObjectBuilder b;
                b.set("path", bro::vfs::path_to_utf8(errs[i].path));
                b.set("message", errs[i].code.message());
                b.set("code", static_cast<double>(errs[i].code.value()));
                arr.set(ev::setElement(arr.get(), static_cast<uint32_t>(i), b.get()));
            }
            return arr.get();
        });
    });

    ObjectBuilder vfs(vfsObj);

    // usage(path, { includeHidden, threads }) -> UsageScan, already running
    vfs.def("usage", 2, [](Value, std::span<const Value> args) -> Value {
        std::filesystem::path root;
        if (!pathArg(args, 0, root)) {
            return ev::throwError("bro.vfs.usage requires a directory path as the first argument");
        }
        bro::vfs::UsageOptions opts;
        if (args.size() > 1 && ev::isObject(args[1])) {
            ev::Persistent opt(args[1]);
            Value hidVal = ev::getProperty(opt.get(), "includeHidden");
            if (ev::isBool(hidVal)) opts.include_hidden = ev::toBool(hidVal);
            Value thrVal = ev::getProperty(opt.get(), "threads");
            if (ev::isNumber(thrVal) && ev::toDouble(thrVal) >= 1) {
                opts.threads = static_cast<unsigned>(std::min(64.0, ev::toDouble(thrVal)));
            }
        }

        auto w = std::make_shared<WrappedUsage>();
        w->done.set(ev::createPromise());
        w->scan = bro::vfs::start_usage_scan(root, opts);
        {
            std::lock_guard lock(g_usage_mu);
            g_active_usage.push_back(w);
        }

        ev::Persistent obj(g_usageScanClass.make(new std::shared_ptr<WrappedUsage>(w), [](void* p) {
            delete static_cast<std::shared_ptr<WrappedUsage>*>(p);
        }));
        ObjectBuilder inst(obj.get());
        inst.set("root", bro::vfs::path_to_utf8(w->scan->root()));
        inst.set("done", w->done.get());
        return inst.get();
    });
}

} // namespace brovfs::api
