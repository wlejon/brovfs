#pragma once

#include "embed/embed.h"
#include "host_class.h"
#include "object_builder.h"
#include "arg_reader.h"
#include "brovfs/vfs.h"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace brovfs::api {

namespace ev = bronze::embed;
using Value = bronze::Value;

Value makeError(const std::string& msg);
Value ensureBroVfs();

std::shared_ptr<bro::vfs::Trash> activeTrash();
void setTrash(std::shared_ptr<bro::vfs::Trash> trash);
std::shared_ptr<bro::vfs::Trash> getTrash();

std::shared_ptr<bro::vfs::UndoJournal> activeJournal();
void setJournal(std::shared_ptr<bro::vfs::UndoJournal> journal);
std::shared_ptr<bro::vfs::UndoJournal> getJournal();

struct VfsAsyncJob {
    uint64_t id{0};
    ev::Persistent promise;
    std::atomic<bool> done{false};
    std::thread worker;
    std::string error;
    std::function<void()> run;
    std::function<void(Value promiseVal)> settle;
};

void trackAsyncJob(std::shared_ptr<VfsAsyncJob> job);
bool drainAsyncJobs();
void cancelAllAsyncJobs();

Value entryToJs(const bro::vfs::FileEntry& entry);
Value opResultToJs(const bro::vfs::OpResult& result);
Value trashItemToJs(const bro::vfs::TrashItem& item);
Value volumeInfoToJs(const bro::vfs::VolumeInfo& vol);
Value watchEventToJs(const bro::vfs::WatchEvent& evItem);

extern HostClass g_directoryModelClass;

void installScanOnto(Value vfsObj);
void installOpsOnto(Value vfsObj);
void installTrashOnto(Value vfsObj);
void installWatchOnto(Value vfsObj);
void installModelOnto(Value vfsObj);
void installMiscOnto(Value vfsObj);
void installUsageOnto(Value vfsObj);

void drainWatcherEvents();
void clearWatchers();

void drainModelUpdates();
void clearModels();

void drainUsageScans();
void clearUsageScans();

} // namespace brovfs::api
