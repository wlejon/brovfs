#pragma once

#include <functional>
#include <memory>
#include <string>

namespace bro::vfs {
class Trash;
class UndoJournal;
} // namespace bro::vfs

namespace brovfs::api {

/// Mounts `bro.vfs` onto `bro` in the current Bronze realm.
void installVfs();

/// Pumps async filesystem jobs, watcher events, and directory model updates on the JS thread.
void tickVfsAsync();

/// Cleans up active watchers, jobs, and models.
void shutdownVfsAsync();

/// Sets custom trash backend (defaults to system_trash()).
void setTrash(std::shared_ptr<bro::vfs::Trash> trash);

/// Gets active trash backend.
std::shared_ptr<bro::vfs::Trash> getTrash();

/// Sets custom undo journal (defaults to journal on system_trash()).
void setJournal(std::shared_ptr<bro::vfs::UndoJournal> journal);

/// Gets active undo journal.
std::shared_ptr<bro::vfs::UndoJournal> getJournal();

} // namespace brovfs::api

using brovfs::api::installVfs;
using brovfs::api::tickVfsAsync;
using brovfs::api::shutdownVfsAsync;
using brovfs::api::setTrash;
using brovfs::api::getTrash;
using brovfs::api::setJournal;
using brovfs::api::getJournal;
