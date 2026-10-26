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

// ---- Path gate ------------------------------------------------------------------
//
// Which paths a program may touch is the host's decision, not brovfs's: the host
// knows which app is running and what it was granted. With no gate set (the
// default), every path is allowed and nothing below changes.

enum class PathAccess { Read, Write };

/// Answers "" to allow, or the sentence the refusal carries (naming what the app
/// lacks and the path). `path` is absolute and lexically normal (UTF-8); the host
/// canonicalizes it (symlinks) before deciding, and a directory it allows covers
/// what is inside. The gate is called on the JS thread that made the call,
/// synchronously, before any work is queued, so it may block to ask the user; it
/// must be thread-safe (Workers run natives on their own threads).
///
/// What each native asks:
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
/// A refusal is an Error whose `message` is exactly the gate's sentence, `code` is
/// "EACCES" and `path` the absolute path asked about: thrown by a synchronous
/// native, the promise rejected with it by an asynchronous one.
using PathGate = std::function<std::string(const std::string& path, PathAccess access)>;

/// Installs `gate` process-wide (an empty function removes it). Safe to call while
/// realms run: calls already inside the old gate finish against it.
void setPathGate(PathGate gate);

} // namespace brovfs::api

using brovfs::api::installVfs;
using brovfs::api::tickVfsAsync;
using brovfs::api::shutdownVfsAsync;
using brovfs::api::setTrash;
using brovfs::api::getTrash;
using brovfs::api::setJournal;
using brovfs::api::getJournal;
using brovfs::api::setPathGate;
