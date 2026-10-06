#include "host_vfs_internal.h"
#include "brovfs/trash.h"
#include "brovfs/undo.h"

#include <filesystem>

namespace brovfs::api {

void installTrashOnto(Value vfsObj) {
    ObjectBuilder vfs(vfsObj);

    // bro.vfs.trash(path) -> Promise<TrashEntry>
    vfs.def("trash", 1, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent promise(ev::createPromise());

        if (args.empty() || !ev::isString(args[0])) {
            ev::Persistent err(makeError("bro.vfs.trash requires a path argument"));
            ev::rejectPromise(promise.get(), err.get());
            return promise.get();
        }

        std::string pathStr = ev::toUtf8(args[0]);
        std::filesystem::path path = std::filesystem::path(pathStr);


        auto job = std::make_shared<VfsAsyncJob>();
        job->promise.set(promise.get());

        auto resPtr = std::make_shared<bro::vfs::OpResult>();
        auto itemPtr = std::make_shared<bro::vfs::TrashItem>();

        job->run = [path, resPtr, itemPtr]() {
            auto trash = activeTrash();
            if (!trash) {
                resPtr->outcome = bro::vfs::Outcome::Failed;
                return;
            }
            *resPtr = bro::vfs::trash_paths(*trash, {path});
            if (resPtr->ok()) {
                activeJournal()->record(bro::vfs::UndoKind::Trash, *resPtr, "Trash");
                std::string id = resPtr->trash_ids.empty() ? "" : resPtr->trash_ids[0];
                itemPtr->id = id;
                itemPtr->original_path = path;
                itemPtr->name = path.filename().string();

                // Look up in trash list for full metadata
                auto list = trash->list();
                for (const auto& it : list) {
                    if (it.id == id) {
                        *itemPtr = it;
                        break;
                    }
                }
            }
        };

        job->settle = [resPtr, itemPtr](Value pVal) {
            if (!resPtr->ok()) {
                std::string msg = "Trash failed";
                if (!resPtr->errors.empty()) {
                    msg = resPtr->errors[0].message();
                }
                ev::Persistent err(makeError(msg));
                ev::rejectPromise(pVal, err.get());
                return;
            }
            ev::Persistent itemVal(trashItemToJs(*itemPtr));
            ev::resolvePromise(pVal, itemVal.get());
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

    // bro.vfs.restoreTrash(trashId) -> Promise<boolean>
    vfs.def("restoreTrash", 1, [](Value, std::span<const Value> args) -> Value {
        ev::Persistent promise(ev::createPromise());

        if (args.empty() || !ev::isString(args[0])) {
            ev::Persistent err(makeError("bro.vfs.restoreTrash requires a trashId argument"));
            ev::rejectPromise(promise.get(), err.get());
            return promise.get();
        }

        std::string trashId = ev::toUtf8(args[0]);

        auto job = std::make_shared<VfsAsyncJob>();
        job->promise.set(promise.get());

        auto successPtr = std::make_shared<bool>(false);
        job->run = [trashId, successPtr]() {
            auto trash = activeTrash();
            if (trash) {
                std::filesystem::path restoredTo;
                std::error_code ec;
                *successPtr = trash->restore(trashId, bro::vfs::RestoreConflict::KeepBoth, &restoredTo, ec);
            }
        };

        job->settle = [successPtr](Value pVal) {
            ev::resolvePromise(pVal, ev::fromBool(*successPtr));
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

    // bro.vfs.listTrash() -> Promise<TrashEntry[]>
    vfs.def("listTrash", 0, [](Value, std::span<const Value>) -> Value {
        ev::Persistent promise(ev::createPromise());

        auto job = std::make_shared<VfsAsyncJob>();
        job->promise.set(promise.get());

        auto itemsPtr = std::make_shared<std::vector<bro::vfs::TrashItem>>();
        job->run = [itemsPtr]() {
            auto trash = activeTrash();
            if (trash) {
                *itemsPtr = trash->list();
            }
        };

        job->settle = [itemsPtr](Value pVal) {
            ev::Persistent arr(ev::makeArray(static_cast<uint32_t>(itemsPtr->size())));
            for (size_t i = 0; i < itemsPtr->size(); ++i) {
                ev::Persistent itemVal(trashItemToJs((*itemsPtr)[i]));
                arr.set(ev::setElement(arr.get(), static_cast<uint32_t>(i), itemVal.get()));
            }
            ev::resolvePromise(pVal, arr.get());
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

    // bro.vfs.emptyTrash() -> Promise<void>
    vfs.def("emptyTrash", 0, [](Value, std::span<const Value>) -> Value {
        ev::Persistent promise(ev::createPromise());

        auto job = std::make_shared<VfsAsyncJob>();
        job->promise.set(promise.get());

        job->run = []() {
            auto trash = activeTrash();
            if (trash) {
                trash->empty();
            }
        };

        job->settle = [](Value pVal) {
            ev::resolvePromise(pVal, ev::undefined());
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
