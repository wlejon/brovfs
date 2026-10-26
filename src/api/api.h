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

// ---- Access -----------------------------------------------------------------------
//
// Which paths a program may touch is the host's decision, not brovfs's: every
// native that takes a path asks the host's one access gate,
// bronze::embed::checkAccess (embed/embed_access.h), with AccessKind::Read or
// AccessKind::Write and the path, absolute and lexically normal (UTF-8); the host
// canonicalizes it (symlinks) before deciding, and a directory it allows covers
// what is inside. It is asked on the JS thread that made the call, synchronously,
// before any work is queued. With no gate installed every path is allowed and
// nothing below changes.
//
// What each native asks:
///   copy          every source Read, the destination Write
///   move          every source Write, the destination Write
///   remove        every path Write
///   trash         the path Write
///   restoreTrash  the item's original path Write
///   emptyTrash    every item's original path Write (one refusal erases nothing)
///   listTrash     every item's original path Read (refused items are left out)
///   undo / redo   what the step will touch: a copy's source Read and destination
///                 Write, a move's both ends Write, a trashed item's original path
///                 Write
///   scan, usage, watch, DirectoryModel, getMime   the path Read
///
// A refusal is bronze::embed::newAccessError: an Error whose `message` is the
// gate's sentence (named PermissionRevoked for a grant taken back), `code` is
// "EACCES" and `path` the absolute path asked about: thrown by a synchronous
// native, the promise rejected with it by an asynchronous one.

} // namespace brovfs::api

using brovfs::api::installVfs;
using brovfs::api::tickVfsAsync;
using brovfs::api::shutdownVfsAsync;
using brovfs::api::setTrash;
using brovfs::api::getTrash;
using brovfs::api::setJournal;
using brovfs::api::getJournal;
