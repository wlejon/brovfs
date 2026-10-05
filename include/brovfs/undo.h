#pragma once
// Undo for what brovfs does: an explicit journal of copy / move / rename / trash records the
// host can reverse (undo) or replay (redo), and save across sessions.
//
// A record is made from an operation's OpResult::done right after it ran, and captures each
// item's identity and state at that moment. Reversing or replaying checks that the world is
// still as the record left it and refuses otherwise, changing nothing:
//   Moved    undo moves the item back: it must still be the same object (identity) at its
//            destination, and nothing may occupy the original path. Changes made inside a
//            moved folder since travel back with it (as a file manager's undo does).
//   Copied   undo removes the copy (to `trash` when the journal has one, else permanently):
//            the copy must be unchanged since (identity, and size / mtime of every entry of
//            a copied tree), so nothing the user did afterwards is ever destroyed. A copy that
//            overwrote an existing destination cannot be undone (the old data is gone).
//   Trashed  undo restores from the trash (the trash refuses if the original path is taken).
// Redo replays the step with the same checks the other way round (the source must still be
// the object that was moved / trashed; a copy is made again).
// Each check runs for every step before any step acts; then steps act newest first. A step
// that fails while acting (a race) is reported and the record stays partly undone: undo()
// again retries what is left.

#include "brovfs/file_ops.h"
#include "brovfs/trash.h"

#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace bro::vfs {

struct UndoStep {
    DoneItem item;
    // State of the destination right after the operation (for Copied and Moved). Identity is
    // the file id plus the birth time and (Linux) inode generation where the file system keeps
    // them: inode numbers are reused at once on ext4 and others, and birth times have a coarse
    // (~4 ms) clock, so a name deleted and recreated within one tick has the same id and
    // birth time; ext4 / btrfs / xfs give the new inode a new generation.
    FileId id;
    int64_t btime_ns = 0;     // 0: unknown
    uint32_t generation = 0;  // 0: unknown
    FileKind kind = FileKind::Unknown;
    uint64_t size = 0;
    int64_t mtime_ms = 0;
    uint64_t tree_digest = 0; // Copied directories: every entry's relative path, kind, size, mtime
    // Source identity (for redo of Moved / Trashed: the object that was moved / trashed).
    FileId source_id;
    int64_t source_btime_ns = 0;
    uint32_t source_generation = 0;
    bool reversed = false;    // this step is currently undone
};

enum class UndoKind : uint8_t { Copy = 0, Move, Trash };

struct UndoRecord {
    uint64_t id = 0;
    UndoKind kind = UndoKind::Copy;
    std::string label;        // host text ("Move 3 items to Pictures")
    int64_t time_ms = 0;
    std::vector<UndoStep> steps;
    [[nodiscard]] bool undone() const noexcept; // every step reversed
};

class UndoJournal {
public:
    // `trash`: where undoing a copy puts the copies (null: removed permanently).
    explicit UndoJournal(std::shared_ptr<Trash> trash = nullptr, size_t capacity = 100);

    // Records what `result` did; returns the record id (0 if nothing was done). Clears redo.
    uint64_t record(UndoKind kind, const OpResult& result, std::string label = {});

    [[nodiscard]] const UndoRecord* next_undo() const; // newest not fully undone record
    [[nodiscard]] const UndoRecord* next_redo() const;

    // Reverses / replays the newest record. Refusals (Errc::source_changed,
    // restore_target_exists, not_reversible...) are in `errors` with nothing done.
    OpResult undo();
    OpResult redo();

    // Plain text, one record per block; paths as UTF-8 (WTF-8), percent-encoded.
    [[nodiscard]] std::string save() const;
    bool load(const std::string& text, std::error_code& ec);

    [[nodiscard]] const std::deque<UndoRecord>& undo_stack() const noexcept { return done_; }
    [[nodiscard]] const std::deque<UndoRecord>& redo_stack() const noexcept { return undone_; }

private:
    std::shared_ptr<Trash> trash_;
    size_t capacity_;
    uint64_t next_id_ = 1;
    std::deque<UndoRecord> done_;   // back = newest
    std::deque<UndoRecord> undone_; // back = most recently undone
};

// The digest UndoStep::tree_digest holds, for a path as it is now (0 for a non-directory).
[[nodiscard]] uint64_t tree_digest(const fs::path& root);

} // namespace bro::vfs
