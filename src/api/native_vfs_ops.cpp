#include "host_vfs_internal.h"
#include "brovfs/file_ops.h"
#include "brovfs/undo.h"

#include <filesystem>

namespace brovfs::api {

namespace {

std::vector<std::filesystem::path> parsePaths(Value val) {
    std::vector<std::filesystem::path> paths;
    if (ev::isString(val)) {
        paths.push_back(std::filesystem::path(ev::toUtf8(val)));
        return paths;
    }

    if (ev::isObject(val)) {
        ev::Persistent arr(val);
        Value lenVal = ev::getProperty(arr.get(), "length");
        if (ev::isNumber(lenVal)) {
            uint32_t len = static_cast<uint32_t>(ev::toDouble(lenVal));
            for (uint32_t i = 0; i < len; ++i) {
                Value elem = ev::getElement(arr.get(), i);
                if (ev::isString(elem)) {
                    paths.push_back(std::filesystem::path(ev::toUtf8(elem)));
                }
            }
        }
    }
    return paths;
}


bro::vfs::FileOpOptions parseFileOpOptions(Value optVal) {
    bro::vfs::FileOpOptions opts;
    if (!ev::isObject(optVal)) return opts;
    ev::Persistent opt(optVal);

    Value conflictVal = ev::getProperty(opt.get(), "conflict");
    if (ev::isString(conflictVal)) {
        std::string s = ev::toUtf8(conflictVal);
        if (s == "overwrite") opts.conflict = bro::vfs::ConflictPolicy::Overwrite;
        else if (s == "skip") opts.conflict = bro::vfs::ConflictPolicy::Skip;
        else if (s == "keepBoth") opts.conflict = bro::vfs::ConflictPolicy::KeepBoth;
        else if (s == "keepNewer") opts.conflict = bro::vfs::ConflictPolicy::KeepNewer;
        else if (s == "ask") opts.conflict = bro::vfs::ConflictPolicy::Ask;
    }

    Value owVal = ev::getProperty(opt.get(), "overwrite");
    if (ev::isBool(owVal) && ev::toBool(owVal)) {
        opts.conflict = bro::vfs::ConflictPolicy::Overwrite;
    }

    Value pmVal = ev::getProperty(opt.get(), "preserveMetadata");
    if (ev::isBool(pmVal)) opts.preserve_metadata = ev::toBool(pmVal);

    Value arVal = ev::getProperty(opt.get(), "allowReflink");
    if (ev::isBool(arVal)) opts.allow_reflink = ev::toBool(arVal);

    Value syncVal = ev::getProperty(opt.get(), "sync");
    if (ev::isBool(syncVal)) opts.sync = ev::toBool(syncVal);

    return opts;
}

bool isDirectoryDestination(const std::filesystem::path& p, const std::string& raw) {
    if (raw.ends_with('/') || raw.ends_with('\\')) return true;
    std::error_code ec;
    return std::filesystem::is_directory(p, ec);
}

} // namespace

void installOpsOnto(Value vfsObj) {
    ObjectBuilder vfs(vfsObj);

    // bro.vfs.copy(src, dst, options?) -> Promise<OpResult>
    vfs.def("copy", 2, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent promise(ev::createPromise());

        if (args.size() < 2 || !ev::isString(args[1])) {
            ev::Persistent err(makeError("bro.vfs.copy requires source and destination arguments"));
            ev::rejectPromise(promise.get(), err.get());
            return promise.get();
        }

        auto sources = parsePaths(args[0]);
        if (sources.empty()) {
            ev::Persistent err(makeError("bro.vfs.copy: no valid source paths provided"));
            ev::rejectPromise(promise.get(), err.get());
            return promise.get();
        }

        std::string dstStr = ev::toUtf8(args[1]);
        std::filesystem::path dstPath = std::filesystem::path(dstStr);

        bro::vfs::FileOpOptions opts = args.size() > 2 ? parseFileOpOptions(args[2]) : bro::vfs::FileOpOptions();

        auto job = std::make_shared<VfsAsyncJob>();
        job->promise.set(promise.get());

        auto resPtr = std::make_shared<bro::vfs::OpResult>();
        job->run = [sources, dstPath, dstStr, opts, resPtr]() {
            bool isDir = isDirectoryDestination(dstPath, dstStr);
            if (sources.size() == 1 && !isDir) {
                *resPtr = bro::vfs::copy_to(sources[0], dstPath, opts);
            } else {
                *resPtr = bro::vfs::copy_into(sources, dstPath, opts);
            }
            if (resPtr->ok()) {
                activeJournal()->record(bro::vfs::UndoKind::Copy, *resPtr, "Copy");
            }
        };

        job->settle = [resPtr](Value pVal) {
            ev::Persistent rVal(opResultToJs(*resPtr));
            ev::resolvePromise(pVal, rVal.get());
        };

        job->worker = std::thread([job]() {
            try {
                job->run();
            } catch (const std::exception& e) {
                job->error = e.what();
            }
            job->done.store(true, std::memory_order_release);
        });

        trackAsyncJob(job);
        return promise.get();
    });

    // bro.vfs.move(src, dst, options?) -> Promise<OpResult>
    vfs.def("move", 2, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent promise(ev::createPromise());

        if (args.size() < 2 || !ev::isString(args[1])) {
            ev::Persistent err(makeError("bro.vfs.move requires source and destination arguments"));
            ev::rejectPromise(promise.get(), err.get());
            return promise.get();
        }

        auto sources = parsePaths(args[0]);
        if (sources.empty()) {
            ev::Persistent err(makeError("bro.vfs.move: no valid source paths provided"));
            ev::rejectPromise(promise.get(), err.get());
            return promise.get();
        }

        std::string dstStr = ev::toUtf8(args[1]);
        std::filesystem::path dstPath = std::filesystem::path(dstStr);


        bro::vfs::FileOpOptions opts = args.size() > 2 ? parseFileOpOptions(args[2]) : bro::vfs::FileOpOptions();

        auto job = std::make_shared<VfsAsyncJob>();
        job->promise.set(promise.get());

        auto resPtr = std::make_shared<bro::vfs::OpResult>();
        job->run = [sources, dstPath, dstStr, opts, resPtr]() {
            bool isDir = isDirectoryDestination(dstPath, dstStr);
            if (sources.size() == 1 && !isDir) {
                *resPtr = bro::vfs::move_to(sources[0], dstPath, opts);
            } else {
                *resPtr = bro::vfs::move_into(sources, dstPath, opts);
            }
            if (resPtr->ok()) {
                activeJournal()->record(bro::vfs::UndoKind::Move, *resPtr, "Move");
            }
        };

        job->settle = [resPtr](Value pVal) {
            ev::Persistent rVal(opResultToJs(*resPtr));
            ev::resolvePromise(pVal, rVal.get());
        };

        job->worker = std::thread([job]() {
            try {
                job->run();
            } catch (const std::exception& e) {
                job->error = e.what();
            }
            job->done.store(true, std::memory_order_release);
        });

        trackAsyncJob(job);
        return promise.get();
    });

    // bro.vfs.remove(path, options?) -> Promise<OpResult>
    vfs.def("remove", 1, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent promise(ev::createPromise());

        if (args.empty()) {
            ev::Persistent err(makeError("bro.vfs.remove requires path argument"));
            ev::rejectPromise(promise.get(), err.get());
            return promise.get();
        }

        auto paths = parsePaths(args[0]);
        if (paths.empty()) {
            ev::Persistent err(makeError("bro.vfs.remove: no valid paths provided"));
            ev::rejectPromise(promise.get(), err.get());
            return promise.get();
        }

        auto job = std::make_shared<VfsAsyncJob>();
        job->promise.set(promise.get());

        auto resPtr = std::make_shared<bro::vfs::OpResult>();
        job->run = [paths, resPtr]() {
            *resPtr = bro::vfs::remove(paths);
        };

        job->settle = [resPtr](Value pVal) {
            ev::Persistent rVal(opResultToJs(*resPtr));
            ev::resolvePromise(pVal, rVal.get());
        };

        job->worker = std::thread([job]() {
            try {
                job->run();
            } catch (const std::exception& e) {
                job->error = e.what();
            }
            job->done.store(true, std::memory_order_release);
        });

        trackAsyncJob(job);
        return promise.get();
    });

    // bro.vfs.canUndo() -> boolean
    vfs.def("canUndo", 0, [](Value, std::span<const Value>) -> Value {
        auto j = activeJournal();
        return ev::fromBool(j && j->next_undo() != nullptr);
    });

    // bro.vfs.canRedo() -> boolean
    vfs.def("canRedo", 0, [](Value, std::span<const Value>) -> Value {
        auto j = activeJournal();
        return ev::fromBool(j && j->next_redo() != nullptr);
    });

    // bro.vfs.undo() -> Promise<boolean>
    vfs.def("undo", 0, [](Value, std::span<const Value>) -> Value {
        ev::Persistent promise(ev::createPromise());
        auto job = std::make_shared<VfsAsyncJob>();
        job->promise.set(promise.get());

        auto resPtr = std::make_shared<bro::vfs::OpResult>();
        job->run = [resPtr]() {
            auto j = activeJournal();
            if (j) {
                *resPtr = j->undo();
            } else {
                resPtr->outcome = bro::vfs::Outcome::Failed;
            }
        };

        job->settle = [resPtr](Value pVal) {
            ev::resolvePromise(pVal, ev::fromBool(resPtr->ok()));
        };

        job->worker = std::thread([job]() {
            try {
                job->run();
            } catch (const std::exception& e) {
                job->error = e.what();
            }
            job->done.store(true, std::memory_order_release);
        });

        trackAsyncJob(job);
        return promise.get();
    });

    // bro.vfs.redo() -> Promise<boolean>
    vfs.def("redo", 0, [](Value, std::span<const Value>) -> Value {
        ev::Persistent promise(ev::createPromise());
        auto job = std::make_shared<VfsAsyncJob>();
        job->promise.set(promise.get());

        auto resPtr = std::make_shared<bro::vfs::OpResult>();
        job->run = [resPtr]() {
            auto j = activeJournal();
            if (j) {
                *resPtr = j->redo();
            } else {
                resPtr->outcome = bro::vfs::Outcome::Failed;
            }
        };

        job->settle = [resPtr](Value pVal) {
            ev::resolvePromise(pVal, ev::fromBool(resPtr->ok()));
        };

        job->worker = std::thread([job]() {
            try {
                job->run();
            } catch (const std::exception& e) {
                job->error = e.what();
            }
            job->done.store(true, std::memory_order_release);
        });

        trackAsyncJob(job);
        return promise.get();
    });
}

} // namespace brovfs::api
