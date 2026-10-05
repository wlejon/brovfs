// Undo / redo of copy, move (rename, cross-device, merged) and trash, through the journal
// built from OpResult::done; refusals when the world changed since; save / load.
#include "harness.h"

#include "brovfs/vfs.h" // the umbrella header, compiled here

#include <atomic>

namespace bro::vfs::sys {
extern std::atomic<bool> g_force_cross_device;
}

using namespace t;

namespace {

void test_copy(const Scratch& s) {
    section("copy: undo removes the copies, redo makes them again; changed copies are refused");
    fs::path src = s / "c" / "src";
    write_file(src / "f.txt", "file");
    write_file(src / "dir" / "a.txt", "a");
    write_file(src / "dir" / "sub" / "b.txt", "b");
    fs::create_directories(L(s / "c" / "dst"));
    vfs::UndoJournal j;
    auto r = vfs::copy_into({src / "f.txt", src / "dir"}, s / "c" / "dst");
    CHECK_MSG(r.ok() && r.done.size() == 2, describe(r));
    CHECK(j.record(vfs::UndoKind::Copy, r, "Copy 2 items") != 0);
    auto u = j.undo();
    CHECK_MSG(u.ok(), describe(u));
    CHECK(!path_exists(s / "c" / "dst" / "f.txt") && !path_exists(s / "c" / "dst" / "dir"));
    CHECK(read_file(src / "dir" / "sub" / "b.txt") == "b"); // sources untouched
    CHECK(j.next_undo() == nullptr && j.next_redo() != nullptr);
    auto rd = j.redo();
    CHECK_MSG(rd.ok(), describe(rd));
    CHECK(read_file(s / "c" / "dst" / "dir" / "sub" / "b.txt") == "b");

    // A file added inside the copied tree: undo refuses, removes nothing.
    write_file(s / "c" / "dst" / "dir" / "sub" / "mine.txt", "user data");
    u = j.undo();
    CHECK(!u.ok() && has_error(u, vfs::Errc::target_changed));
    CHECK(read_file(s / "c" / "dst" / "dir" / "sub" / "mine.txt") == "user data");
    CHECK(path_exists(s / "c" / "dst" / "f.txt")); // all-or-nothing: the unchanged file stays too
    fs::remove(L(s / "c" / "dst" / "dir" / "sub" / "mine.txt"));
    // Removing it again leaves the folder's mtime moved, unless the add and remove fell in one
    // tick of a coarse file system clock (Linux: ~4 ms); either way the tree holds only what
    // was copied, so undo may refuse or go ahead, but must do one of them whole.
    u = j.undo();
    bool refused = has_error(u, vfs::Errc::target_changed) && path_exists(s / "c" / "dst" / "dir" / "sub" / "b.txt");
    bool undone = u.ok() && !path_exists(s / "c" / "dst" / "dir") && !path_exists(s / "c" / "dst" / "f.txt");
    CHECK_MSG(refused || undone, describe(u));

    section("copy: KeepBoth records the renamed copy; undo removes only it");
    write_file(s / "c" / "dst" / "f.txt", "file");
    vfs::UndoJournal jk;
    vfs::FileOpOptions kb;
    kb.conflict = vfs::ConflictPolicy::KeepBoth;
    r = vfs::copy_into({src / "f.txt"}, s / "c" / "dst", kb);
    CHECK_MSG(r.ok() && r.done.size() == 1 && r.done[0].destination != s / "c" / "dst" / "f.txt", describe(r));
    fs::path renamed = r.done.empty() ? fs::path() : r.done[0].destination;
    jk.record(vfs::UndoKind::Copy, r);
    u = jk.undo();
    CHECK_MSG(u.ok() && !path_exists(renamed) && read_file(s / "c" / "dst" / "f.txt") == "file", describe(u));

    // A modified copied file: refused.
    vfs::UndoJournal j2;
    r = vfs::copy_to(src / "f.txt", s / "c" / "one.txt");
    j2.record(vfs::UndoKind::Copy, r);
    write_file(s / "c" / "one.txt", "edited");
    u = j2.undo();
    CHECK(has_error(u, vfs::Errc::target_changed) && read_file(s / "c" / "one.txt") == "edited");

    // An overwrite cannot be undone: the old data is gone.
    vfs::UndoJournal j3;
    write_file(s / "c" / "victim.txt", "old");
    vfs::FileOpOptions ow;
    ow.conflict = vfs::ConflictPolicy::Overwrite;
    r = vfs::copy_to(src / "f.txt", s / "c" / "victim.txt", ow);
    CHECK(r.ok() && r.done.size() == 1 && r.done[0].replaced);
    j3.record(vfs::UndoKind::Copy, r);
    u = j3.undo();
    CHECK(has_error(u, vfs::Errc::not_reversible) && read_file(s / "c" / "victim.txt") == "file");
}

void test_move(const Scratch& s) {
    section("move: rename, cross-device and merged moves go back; an occupied source is refused");
    fs::path m = s / "m";
    write_file(m / "a.txt", "a");
    write_file(m / "d" / "x.txt", "x");
    fs::create_directories(L(m / "to"));
    vfs::UndoJournal j;
    auto r = vfs::move_into({m / "a.txt", m / "d"}, m / "to");
    CHECK_MSG(r.ok() && r.done.size() == 2, describe(r));
    j.record(vfs::UndoKind::Move, r);
    // Edits inside the moved folder travel back with it.
    write_file(m / "to" / "d" / "new.txt", "n");
    auto u = j.undo();
    CHECK_MSG(u.ok(), describe(u));
    CHECK(read_file(m / "a.txt") == "a" && read_file(m / "d" / "new.txt") == "n" && !path_exists(m / "to" / "d"));
    auto rd = j.redo();
    CHECK_MSG(rd.ok() && read_file(m / "to" / "a.txt") == "a", describe(rd));

    // Something new at the original path: refused, nothing moved.
    write_file(m / "a.txt", "squatter");
    u = j.undo();
    CHECK(has_error(u, vfs::Errc::restore_target_exists));
    CHECK(read_file(m / "a.txt") == "squatter" && read_file(m / "to" / "a.txt") == "a" && path_exists(m / "to" / "d"));
    fs::remove(L(m / "a.txt"));
    // The moved file replaced by another object of the same name: refused.
    fs::remove(L(m / "to" / "a.txt"));
    write_file(m / "to" / "a.txt", "impostor");
    u = j.undo();
    CHECK(has_error(u, vfs::Errc::target_changed) && !path_exists(m / "a.txt"));

    section("move: cross-device (copy + delete) and a move merged into an existing folder");
    fs::path c = s / "x";
    write_file(c / "tree" / "1.txt", "1");
    write_file(c / "tree" / "deep" / "2.txt", "2");
    vfs::sys::g_force_cross_device = true;
    vfs::UndoJournal jx;
    r = vfs::move_to(c / "tree", c / "moved");
    CHECK_MSG(r.ok(), describe(r));
    jx.record(vfs::UndoKind::Move, r);
    u = jx.undo();
    vfs::sys::g_force_cross_device = false;
    CHECK_MSG(u.ok() && read_file(c / "tree" / "deep" / "2.txt") == "2" && !path_exists(c / "moved"), describe(u));

    write_file(c / "src" / "keep.txt", "k");
    write_file(c / "src" / "sub" / "s.txt", "s");
    write_file(c / "dst" / "src" / "existing.txt", "e");
    fs::create_directories(L(c / "dst" / "src" / "sub"));
    vfs::UndoJournal jm;
    r = vfs::move_into({c / "src"}, c / "dst");
    CHECK_MSG(r.ok() && !path_exists(c / "src"), describe(r));
    jm.record(vfs::UndoKind::Move, r);
    u = jm.undo();
    CHECK_MSG(u.ok(), describe(u));
    CHECK(read_file(c / "src" / "keep.txt") == "k" && read_file(c / "src" / "sub" / "s.txt") == "s");
    CHECK(read_file(c / "dst" / "src" / "existing.txt") == "e" && !path_exists(c / "dst" / "src" / "keep.txt"));
}

void test_trash(const Scratch& s, std::shared_ptr<vfs::Trash> trash, const std::string& tag) {
    section("trash: undo restores, redo trashes again");
    fs::path f = s / "t" / (tag + "_undo.txt");
    write_file(f, "t");
    vfs::UndoJournal j(trash);
    auto r = vfs::trash_paths(*trash, {f});
    CHECK_MSG(r.ok() && r.done.size() == 1, describe(r));
    j.record(vfs::UndoKind::Trash, r);
    auto u = j.undo();
    CHECK_MSG(u.ok() && read_file(f) == "t", describe(u));
    auto rd = j.redo();
    CHECK_MSG(rd.ok() && !path_exists(f), describe(rd));
    u = j.undo(); // leave nothing in the trash
    CHECK_MSG(u.ok() && read_file(f) == "t", describe(u));

    // Save / load: a journal restored from text undoes and redoes the same way.
    rd = j.redo();
    std::string text = j.save();
    vfs::UndoJournal k(trash);
    std::error_code ec;
    CHECK_MSG(k.load(text, ec), ec.message());
    CHECK(k.save() == text);
    u = k.undo();
    CHECK_MSG(u.ok() && read_file(f) == "t", describe(u));
}

void test_copy_to_trash(const Scratch& s, std::shared_ptr<vfs::Trash> trash) {
    section("undoing a copy with a trash puts the copy in the trash");
    write_file(s / "ct" / "src.txt", "s");
    vfs::UndoJournal j(trash);
    auto r = vfs::copy_to(s / "ct" / "src.txt", s / "ct" / "copy.txt");
    j.record(vfs::UndoKind::Copy, r);
    auto u = j.undo();
    CHECK_MSG(u.ok() && !path_exists(s / "ct" / "copy.txt"), describe(u));
    bool in_trash = false;
    for (auto& item : trash->list()) in_trash |= item.original_path == s / "ct" / "copy.txt";
    CHECK(in_trash);
}

} // namespace

int main() {
    Scratch s("undo");
    test_copy(s);
    test_move(s);
#ifdef _WIN32
    // The real Recycle Bin; every item is restored again by the test.
    test_trash(s, vfs::make_recycle_bin(), "brovfsundo");
#else
    fs::path xdg = s / "xdg";
    ::setenv("XDG_DATA_HOME", xdg.c_str(), 1); // nothing here may reach the real trash
    vfs::FreedesktopTrashConfig cfg;
    cfg.home_trash = xdg / "Trash";
    cfg.search_mounts = false;
    auto trash = vfs::make_freedesktop_trash(cfg);
    test_trash(s, trash, "brovfsundo");
    test_copy_to_trash(s, trash);
#endif
    return finish("test_undo");
}
