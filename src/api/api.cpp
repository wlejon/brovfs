#include "api.h"
#include "host_vfs_internal.h"

#include <mutex>
#include <vector>

namespace brovfs::api {

namespace {

std::mutex g_trash_mu;
std::shared_ptr<bro::vfs::Trash> g_custom_trash;

std::mutex g_journal_mu;
std::shared_ptr<bro::vfs::UndoJournal> g_custom_journal;

std::mutex g_jobs_mu;
uint64_t g_next_job_id = 1;
std::vector<std::shared_ptr<VfsAsyncJob>> g_jobs;

} // namespace

std::shared_ptr<bro::vfs::Trash> activeTrash() {
    std::lock_guard lock(g_trash_mu);
    if (g_custom_trash) return g_custom_trash;
    static std::shared_ptr<bro::vfs::Trash> sysTrash = bro::vfs::system_trash();
    return sysTrash;
}

void setTrash(std::shared_ptr<bro::vfs::Trash> trash) {
    std::lock_guard lock(g_trash_mu);
    g_custom_trash = std::move(trash);
}

std::shared_ptr<bro::vfs::Trash> getTrash() {
    return activeTrash();
}

std::shared_ptr<bro::vfs::UndoJournal> activeJournal() {
    std::lock_guard lock(g_journal_mu);
    if (g_custom_journal) return g_custom_journal;
    static std::shared_ptr<bro::vfs::UndoJournal> defJournal =
        std::make_shared<bro::vfs::UndoJournal>(activeTrash(), 100);
    return defJournal;
}

void setJournal(std::shared_ptr<bro::vfs::UndoJournal> journal) {
    std::lock_guard lock(g_journal_mu);
    g_custom_journal = std::move(journal);
}

std::shared_ptr<bro::vfs::UndoJournal> getJournal() {
    return activeJournal();
}

Value makeError(const std::string& msg) {
    ev::Persistent text(ev::fromUtf8(msg));
    auto ctor = ev::globalValue("Error");
    if (ctor.found && ev::isFunction(ctor.value)) {
        ev::Persistent c(ctor.value);
        const Value arg = text.get();
        auto r = ev::construct(c.get(), std::span<const Value>(&arg, 1));
        if (!r.thrown) return r.value;
    }
    return text.get();
}

Value ensureBroVfs() {
    ev::Persistent globalThisVal;
    auto gt = ev::globalValue("globalThis");
    if (gt.found && ev::isObject(gt.value)) {
        globalThisVal.set(gt.value);
    }

    ev::Persistent broP;
    auto bro = ev::globalValue("bro");
    if (bro.found && ev::isObject(bro.value)) broP.set(bro.value);
    if (!ev::isObject(broP.get()) && ev::isObject(globalThisVal.get())) {
        Value candidate = ev::getProperty(globalThisVal.get(), "bro");
        if (ev::isObject(candidate)) broP.set(candidate);
    }
    if (!ev::isObject(broP.get())) {
        broP.set(ev::createObject());
        ev::registerGlobal("bro", broP.get());
        if (ev::isObject(globalThisVal.get())) {
            globalThisVal.set(ev::setProperty(globalThisVal.get(), "bro", broP.get()));
        }
    }

    ev::Persistent vfsP(ev::getProperty(broP.get(), "vfs"));
    if (!ev::isObject(vfsP.get())) {
        vfsP.set(ev::createObject());
        broP.set(ev::setProperty(broP.get(), "vfs", vfsP.get()));
    }
    return vfsP.get();
}

void trackAsyncJob(std::shared_ptr<VfsAsyncJob> job) {
    std::lock_guard lock(g_jobs_mu);
    job->id = ++g_next_job_id;
    g_jobs.push_back(std::move(job));
}

bool drainAsyncJobs() {
    std::vector<std::shared_ptr<VfsAsyncJob>> completed;
    {
        std::lock_guard lock(g_jobs_mu);
        std::vector<std::shared_ptr<VfsAsyncJob>> remaining;
        for (auto& j : g_jobs) {
            if (j->done.load(std::memory_order_acquire)) {
                completed.push_back(std::move(j));
            } else {
                remaining.push_back(std::move(j));
            }
        }
        g_jobs = std::move(remaining);
    }

    if (completed.empty()) return false;

    for (auto& job : completed) {
        if (job->worker.joinable()) {
            job->worker.join();
        }
        if (!job->error.empty()) {
            ev::Persistent err(makeError(job->error));
            ev::rejectPromise(job->promise.get(), err.get());
        } else if (job->settle) {
            job->settle(job->promise.get());
        }
    }
    return true;
}

void cancelAllAsyncJobs() {
    std::vector<std::shared_ptr<VfsAsyncJob>> jobs;
    {
        std::lock_guard lock(g_jobs_mu);
        jobs = std::move(g_jobs);
        g_jobs.clear();
    }
    for (auto& j : jobs) {
        if (j->worker.joinable()) {
            j->worker.join();
        }
    }
}

Value entryToJs(const bro::vfs::FileEntry& entry) {
    ObjectBuilder b;
    b.set("path", entry.path.string());
    b.set("name", entry.name);
    b.set("kind", std::string(to_string(entry.kind)));
    b.set("isDirectory", entry.is_directory());
    b.set("isRegular", entry.is_regular());
    b.set("isLink", entry.is_link());
    b.set("isHidden", entry.is_hidden);
    b.set("size", static_cast<double>(entry.size));
    b.set("mtime", static_cast<double>(entry.mtime_ms));
    b.set("birthtime", static_cast<double>(entry.birthtime_ms));
    b.set("linkTarget", entry.link_target);
    b.set("depth", static_cast<double>(entry.depth));
    return b.get();
}

Value opResultToJs(const bro::vfs::OpResult& result) {
    ObjectBuilder b;
    b.set("outcome", std::string(to_string(result.outcome)));
    b.set("ok", result.ok());
    b.set("filesDone", static_cast<double>(result.files_done));
    b.set("dirsDone", static_cast<double>(result.dirs_done));
    b.set("bytesDone", static_cast<double>(result.bytes_done));
    b.set("linksDone", static_cast<double>(result.links_done));
    b.set("skipped", static_cast<double>(result.skipped));

    ev::Persistent errArr(ev::makeArray(static_cast<uint32_t>(result.errors.size())));
    for (size_t i = 0; i < result.errors.size(); ++i) {
        const auto& err = result.errors[i];
        ObjectBuilder eb;
        eb.set("source", err.source.string());
        eb.set("destination", err.destination.string());
        eb.set("operation", err.operation);
        eb.set("message", err.message());
        eb.set("code", static_cast<double>(err.code.value()));
        errArr.set(ev::setElement(errArr.get(), static_cast<uint32_t>(i), eb.get()));
    }
    b.set("errors", errArr.get());
    return b.get();
}

Value trashItemToJs(const bro::vfs::TrashItem& item) {
    ObjectBuilder b;
    b.set("id", item.id);
    b.set("originalPath", item.original_path.string());
    b.set("storedPath", item.stored_path.string());
    b.set("name", item.name);
    b.set("deletionTime", static_cast<double>(item.deletion_time_ms));
    b.set("size", static_cast<double>(item.size));
    b.set("isDirectory", item.is_directory);
    return b.get();
}

Value volumeInfoToJs(const bro::vfs::VolumeInfo& vol) {
    ObjectBuilder b;
    b.set("mountPoint", vol.mount_point.string());
    b.set("volumeLabel", vol.volume_label);
    b.set("fsType", vol.fs_type);
    b.set("totalBytes", static_cast<double>(vol.total_bytes));
    b.set("freeBytes", static_cast<double>(vol.free_bytes));
    b.set("availableBytes", static_cast<double>(vol.available_bytes));
    b.set("isReadOnly", vol.is_read_only);
    b.set("isRemovable", vol.is_removable);
    b.set("isNetwork", vol.is_network);
    b.set("usedPercentage", vol.used_percentage());
    return b.get();
}

Value watchEventToJs(const bro::vfs::WatchEvent& evItem) {
    ObjectBuilder b;
    b.set("kind", std::string(to_string(evItem.kind)));
    b.set("watch", static_cast<double>(evItem.watch));
    b.set("path", evItem.path.string());
    if (evItem.kind == bro::vfs::WatchEventKind::Renamed) {
        b.set("oldPath", evItem.old_path.string());
    }
    if (evItem.error) {
        b.set("error", evItem.error.message());
    }
    return b.get();
}

void installVfs() {
    ev::Persistent vfsObj(ensureBroVfs());
    installScanOnto(vfsObj.get());
    installOpsOnto(vfsObj.get());
    installTrashOnto(vfsObj.get());
    installWatchOnto(vfsObj.get());
    installModelOnto(vfsObj.get());
    installMiscOnto(vfsObj.get());
}

void tickVfsAsync() {
    drainAsyncJobs();
    drainWatcherEvents();
    drainModelUpdates();
}

void shutdownVfsAsync() {
    cancelAllAsyncJobs();
    clearWatchers();
    clearModels();
}

} // namespace brovfs::api
