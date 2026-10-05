// Trash. Windows / macOS: the real Recycle Bin / Trash, touching only items this test created
// (all under its scratch dir), restoring or erasing every one of them. POSIX (macOS too): the freedesktop trash with the
// home trash and every top-directory trash inside scratch directories; trash-cli, when
// installed, is used as an independent oracle with XDG_DATA_HOME pointed at scratch.
#include "brovfs/trash.h"
#include "harness.h"

#include <ctime>
#include <optional>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif
#ifdef __APPLE__
#include <spawn.h>
#include <sys/wait.h>
#include <sys/xattr.h>

#include "src/trash_macos.h"
extern char** environ;
static const char* g_argv0 = "";
#endif

using namespace t;

static bool within(const fs::path& p, const fs::path& dir) {
    auto rel = p.lexically_relative(dir);
    return !rel.empty() && rel.native().rfind(fs::path("..").native(), 0) != 0;
}

// Returns a copy: callers routinely pass a temporary list().
static std::optional<vfs::TrashItem> find_id(const std::vector<vfs::TrashItem>& items, const std::string& id) {
    for (auto& i : items) {
        if (i.id == id) return i;
    }
    return std::nullopt;
}

static bool same_path(const fs::path& a, const fs::path& b) {
#ifdef _WIN32
    return _wcsicmp(a.c_str(), b.c_str()) == 0;
#else
    return a == b;
#endif
}

static void common_checks(vfs::Trash& trash, const Scratch& s, const std::string& tag) {
    section("trash, list, restore a file");
    fs::path f = s / p8(tag + "_file name & ü%25 #.txt");
    write_file(f, "to the trash");
    std::string id;
    std::error_code ec;
    CHECK_MSG(trash.trash(f, &id, ec), ec.message());
    CHECK(!path_exists(f) && !id.empty());
    auto items = trash.list();
    auto it = find_id(items, id);
    if (!CHECK(it.has_value())) {
        note("trash() id: " + id);
        for (auto& i : items) {
            if (within(i.original_path, s.root())) note("listed id: " + i.id);
        }
    }
    if (it) {
        CHECK_MSG(same_path(it->original_path, f), u8(it->original_path));
        CHECK(it->size == 12 && !it->is_directory);
        CHECK(it->name == tag + "_file name & ü%25 #.txt");
        int64_t now = static_cast<int64_t>(std::time(nullptr)) * 1000;
        CHECK_MSG(it->deletion_time_ms > now - 120000 && it->deletion_time_ms < now + 120000,
                  std::to_string(it->deletion_time_ms) + " vs " + std::to_string(now));
    }
    fs::path restored;
    CHECK_MSG(trash.restore(id, vfs::RestoreConflict::Fail, &restored, ec), ec.message());
    CHECK(read_file(f) == "to the trash" && same_path(restored, f));
    CHECK(!find_id(trash.list(), id));

    section("restore never overwrites what now occupies the original path");
    CHECK(trash.trash(f, &id, ec));
    write_file(f, "new work");
    CHECK(!trash.restore(id, vfs::RestoreConflict::Fail, &restored, ec) && ec == vfs::Errc::restore_target_exists);
    CHECK(read_file(f) == "new work" && find_id(trash.list(), id).has_value());
    CHECK_MSG(trash.restore(id, vfs::RestoreConflict::KeepBoth, &restored, ec), ec.message());
    CHECK(read_file(f) == "new work" && read_file(restored) == "to the trash" && !same_path(restored, f));

    section("directories (trailing separator), unicode names, missing parent on restore");
    fs::path d = s / p8(tag + "_dir 日本");
    write_file(d / "inner.txt", "in");
    write_file(d / "sub" / "deep.txt", "deeper");
    fs::path with_slash = d;
    with_slash += fs::path::preferred_separator;
    CHECK_MSG(trash.trash(with_slash, &id, ec), ec.message());
    CHECK(!path_exists(d));
    it = find_id(trash.list(), id);
    CHECK(it && it->is_directory && same_path(it->original_path, d));
    CHECK(trash.restore(id, vfs::RestoreConflict::Fail, nullptr, ec) && read_file(d / "sub" / "deep.txt") == "deeper");

    fs::path nested = s / p8(tag + "_parent") / "child.txt";
    write_file(nested, "child");
    CHECK(trash.trash(nested, &id, ec));
    vfs::remove({s / p8(tag + "_parent")});
    CHECK_MSG(trash.restore(id, vfs::RestoreConflict::Fail, nullptr, ec), ec.message());
    CHECK(read_file(nested) == "child");

    section("erase only what the id names; forged ids are refused");
    fs::path e = s / p8(tag + "_erase.txt");
    write_file(e, "bye");
    CHECK(trash.trash(e, &id, ec));
    CHECK_MSG(trash.erase(id, ec), ec.message());
    CHECK(!find_id(trash.list(), id) && !path_exists(e));
    CHECK(!trash.erase(id, ec)); // already gone

    write_file(s / "victim" / "precious.txt", "do not delete");
    for (const std::string& forged :
         {u8(s / "victim"), u8(s / "victim" / "precious.txt"), std::string("../../victim"), std::string(),
          std::string("12:/etc/passwd..")}) {
        CHECK_MSG(!trash.erase(forged, ec), forged);
        CHECK(!trash.restore(forged, vfs::RestoreConflict::Fail, nullptr, ec));
    }
    CHECK(read_file(s / "victim" / "precious.txt") == "do not delete");

    section("missing source");
    CHECK(!trash.trash(s / "missing.txt", &id, ec));
}

#if defined(_WIN32) || defined(__APPLE__)

// For the real system trash. Erases this run's items, plus orphans of an earlier run of this
// test that died before its cleanup: items from a "trash-*" scratch dir under the scratch
// base. Never anything else.
static bool own_item(const vfs::TrashItem& item, const Scratch& s) {
    if (within(item.original_path, s.root())) return true;
    std::error_code ec;
    fs::path base = fs::absolute(scratch_base(), ec);
    if (ec || !within(item.original_path, base)) return false;
    fs::path first = *item.original_path.lexically_relative(base).begin();
    return first.native().rfind(fs::path("trash-").native(), 0) == 0 &&
           item.name.find("brovfstest") != std::string::npos;
}

static int cleanup_own_items(vfs::Trash& trash, const Scratch& s) {
    int n = 0;
    for (auto& item : trash.list()) {
        if (!own_item(item, s)) continue; // never touch anything else
        std::error_code ec;
        if (trash.erase(item.id, ec)) ++n;
    }
    if (n) note("cleanup erased " + std::to_string(n) + " leftover test item(s)");
    return n;
}

#endif

#ifdef _WIN32

static void windows_specific(vfs::Trash& trash, const Scratch& s, const std::string& tag) {
    section("Recycle Bin: id names a $R entry of this user's bin");
    fs::path f = s / p8(tag + "_shape.txt");
    write_file(f, "x");
    std::string id;
    std::error_code ec;
    CHECK(trash.trash(f, &id, ec));
    fs::path stored = p8(id);
    CHECK(stored.filename().native().rfind(L"$R", 0) == 0);
    CHECK(_wcsicmp(stored.parent_path().parent_path().filename().c_str(), L"$Recycle.Bin") == 0);
    // A $R path with ".." or in another directory is not an id.
    fs::path forged = stored.parent_path() / L".." / stored.filename();
    CHECK(!trash.erase(u8(forged), ec) && ec == vfs::Errc::invalid_trash_id);
    CHECK(trash.restore(id, vfs::RestoreConflict::Fail, nullptr, ec) && path_exists(f));

    section("no Recycle Bin (UNC path): refused, nothing deleted");
    fs::path local = s / p8(tag + "_unc.txt");
    write_file(local, "network path victim");
    std::wstring dp = fs::absolute(local).native();
    fs::path unc = std::wstring(L"\\\\localhost\\") + dp[0] + L"$" + dp.substr(2);
    if (path_exists(unc)) {
        bool ok = trash.trash(unc, &id, ec);
        CHECK(!ok && ec == vfs::Errc::no_trash_available);
        CHECK(read_file(local) == "network path victim");
        if (ok) trash.restore(id, vfs::RestoreConflict::Fail, nullptr, ec);
    } else {
        note("admin share \\\\localhost\\X$ not reachable; UNC case skipped");
    }
}

int main() {
    Scratch s("trash");
    auto bin = vfs::make_recycle_bin();
    std::string tag = "brovfstest" + std::to_string(GetTickCount64() % 100000000);
    common_checks(*bin, s, tag);
    windows_specific(*bin, s, tag);
    cleanup_own_items(*bin, s);
    // The system trash is the Recycle Bin.
    CHECK(vfs::system_trash() != nullptr);
    return finish("test_trash");
}

#else

static std::string sh(const std::string& cmd) {
    std::string out;
    FILE* p = ::popen(cmd.c_str(), "r");
    if (!p) return out;
    char buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), p)) > 0) out.append(buf, n);
    ::pclose(p);
    return out;
}

static std::string quote(const fs::path& p) {
    std::string s = "'";
    for (char c : p.native()) s += c == '\'' ? std::string("'\\''") : std::string(1, c);
    return s + "'";
}

static std::string info_of(const fs::path& trash_dir, const std::string& name) {
    return read_file(trash_dir / "info" / (name + ".trashinfo"));
}

static void freedesktop_specific(const Scratch& s, const fs::path& home_trash) {
    vfs::FreedesktopTrashConfig cfg;
    cfg.home_trash = home_trash;
    cfg.search_mounts = false;
    auto trash = vfs::make_freedesktop_trash(cfg);
    std::error_code ec;
    std::string id;

    section("freedesktop: .trashinfo format (encoded absolute Path, local DeletionDate)");
    fs::path f = s / "work" / "a b%.txt";
    write_file(f, "x");
    CHECK(trash->trash(f, &id, ec));
    std::string info = info_of(home_trash, "a b%.txt");
    CHECK_MSG(info.rfind("[Trash Info]\n", 0) == 0, info);
    std::string enc = "Path=";
    for (unsigned char c : f.native()) {
        bool keep = std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/';
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%%%02X", c);
        enc += keep ? std::string(1, static_cast<char>(c)) : std::string(buf);
    }
    CHECK_MSG(info.find(enc + "\n") != std::string::npos, info);
    char hour[32];
    std::time_t now = std::time(nullptr);
    std::tm tm{};
    localtime_r(&now, &tm);
    std::strftime(hour, sizeof(hour), "DeletionDate=%Y-%m-%dT%H", &tm);
    CHECK_MSG(info.find(hour) != std::string::npos, info);
    struct stat st{};
    CHECK(::stat((home_trash / "info" / "a b%.txt.trashinfo").c_str(), &st) == 0 && (st.st_mode & 0777) == 0600);

    section("freedesktop: name collisions, including a stray info file");
    write_file(s / "w1" / "dup.txt", "1");
    write_file(s / "w2" / "dup.txt", "2");
    std::string id1, id2;
    CHECK(trash->trash(s / "w1" / "dup.txt", &id1, ec) && trash->trash(s / "w2" / "dup.txt", &id2, ec));
    CHECK(id1 != id2);
    CHECK(read_file(home_trash / "files" / "dup.txt") == "1" && read_file(home_trash / "files" / "dup.2.txt") == "2");
    write_file(home_trash / "info" / "stray.txt.trashinfo", "[Trash Info]\nPath=/nowhere\n");
    write_file(s / "w1" / "stray.txt", "s");
    CHECK(trash->trash(s / "w1" / "stray.txt", &id, ec));
    CHECK(read_file(home_trash / "files" / "stray.2.txt") == "s");
    CHECK(read_file(home_trash / "info" / "stray.txt.trashinfo") == "[Trash Info]\nPath=/nowhere\n");

    section("freedesktop: directorysizes kept in step");
    write_big(s / "w3" / "folder" / "blob", 10000);
    write_file(s / "w3" / "folder" / "x", "12345");
    CHECK(trash->trash(s / "w3" / "folder", &id, ec));
    std::string ds = read_file(home_trash / "directorysizes");
    CHECK_MSG(ds.rfind("10005 ", 0) == 0 && ds.find(" folder\n") != std::string::npos, ds);
    auto it = find_id(trash->list(), id);
    CHECK(it && it->is_directory && it->size == 10005);
    CHECK(trash->erase(id, ec));
    CHECK(read_file(home_trash / "directorysizes").find(" folder\n") == std::string::npos);

    section("freedesktop: symlinks are trashed as links");
    write_file(s / "lt" / "target.txt", "t");
    fs::create_symlink("target.txt", s / "lt" / "link", ec);
    CHECK(trash->trash(s / "lt" / "link", &id, ec));
    CHECK(fs::is_symlink(fs::symlink_status(home_trash / "files" / "link")) && read_file(s / "lt" / "target.txt") == "t");
    CHECK(trash->restore(id, vfs::RestoreConflict::Fail, nullptr, ec) && fs::is_symlink(fs::symlink_status(s / "lt" / "link")));

    section("freedesktop: refuses to trash the trash");
    CHECK(!trash->trash(home_trash, &id, ec) && path_exists(home_trash / "files"));
}

static void topdir_trash(const Scratch& s, const fs::path& home_trash) {
    fs::path other = other_volume_base(s.root());
    section("freedesktop: top-directory trash on another device");
    if (other.empty()) {
        note("no second device; skipped");
        return;
    }
    Scratch top("trash-top", other);
    const std::string uid = std::to_string(::getuid());
    vfs::FreedesktopTrashConfig cfg;
    cfg.home_trash = home_trash;
    cfg.search_mounts = false;
    cfg.extra_topdirs = {top.root()};
    cfg.topdir_of = [&](const fs::path&) { return top.root(); };
    auto trash = vfs::make_freedesktop_trash(cfg);
    std::error_code ec;
    std::string id;

    fs::path f = top / "sub" / "file.txt";
    write_file(f, "on another device");
    CHECK_MSG(trash->trash(f, &id, ec), ec.message());
    fs::path tdir = top / (".Trash-" + uid);
    CHECK(read_file(tdir / "files" / "file.txt") == "on another device");
    CHECK_MSG(info_of(tdir, "file.txt").find("Path=sub/file.txt\n") != std::string::npos, info_of(tdir, "file.txt"));
    struct stat st{};
    CHECK(::stat(tdir.c_str(), &st) == 0 && (st.st_mode & 0777) == 0700);
    auto it = find_id(trash->list(), id);
    CHECK(it && it->original_path == f);
    CHECK(trash->restore(id, vfs::RestoreConflict::Fail, nullptr, ec) && read_file(f) == "on another device");

    section("freedesktop: shared $topdir/.Trash/$uid only when sticky");
    Scratch top2("trash-top2", other);
    cfg.extra_topdirs = {top2.root()};
    cfg.topdir_of = [&](const fs::path&) { return top2.root(); };
    auto t2 = vfs::make_freedesktop_trash(cfg);
    fs::create_directories(top2 / ".Trash");
    ::chmod((top2 / ".Trash").c_str(), 0777); // not sticky: must not be used
    write_file(top2 / "g.txt", "g");
    CHECK(t2->trash(top2 / "g.txt", &id, ec));
    CHECK(path_exists(top2 / (".Trash-" + uid) / "files" / "g.txt") && !path_exists(top2 / ".Trash" / uid));
    ::chmod((top2 / ".Trash").c_str(), 01777);
    write_file(top2 / "h.txt", "h");
    CHECK(t2->trash(top2 / "h.txt", &id, ec));
    CHECK(path_exists(top2 / ".Trash" / uid / "files" / "h.txt"));
    CHECK(t2->restore(id, vfs::RestoreConflict::Fail, nullptr, ec) && read_file(top2 / "h.txt") == "h");

    section("freedesktop: no usable trash on the device -> refused, nothing deleted");
    Scratch top3("trash-top3", other);
    cfg.topdir_of = [&](const fs::path&) { return top3.root(); };
    // A read-only top directory: no trash can be created there, but w/ stays writable.
    const fs::path keep = top3 / "w" / "keep.txt";
    write_file(keep, "keep");
    ::chmod(top3.root().c_str(), 0555);
    auto t3 = vfs::make_freedesktop_trash(cfg);
    bool ok = t3->trash(keep, &id, ec);
    if (!is_root_user()) {
        CHECK(!ok && ec == vfs::Errc::no_trash_available && read_file(keep) == "keep");
    }

    section("freedesktop: opt-in home-trash fallback across devices (verified move)");
    cfg.allow_home_trash_across_devices = true;
    auto t4 = vfs::make_freedesktop_trash(cfg);
    if (!is_root_user()) {
        // Source that cannot be unlinked: the move must fail with the file intact and no
        // residue in the home trash.
        ::chmod((top3 / "w").c_str(), 0555);
        ok = t4->trash(keep, &id, ec);
        ::chmod((top3 / "w").c_str(), 0755);
        CHECK_MSG(!ok && read_file(keep) == "keep", ec.message());
        CHECK(!path_exists(home_trash / "files" / "keep.txt") && !path_exists(home_trash / "info" / "keep.txt.trashinfo"));

        ok = t4->trash(keep, &id, ec);
        CHECK_MSG(ok && !path_exists(keep) && read_file(home_trash / "files" / "keep.txt") == "keep", ec.message());
        it = find_id(t4->list(), id);
        CHECK(it && it->original_path == keep);
        CHECK(t4->restore(id, vfs::RestoreConflict::Fail, nullptr, ec) && read_file(keep) == "keep");
    }
    ::chmod(top3.root().c_str(), 0755);
}

static void trash_cli_oracle(const Scratch& s, const fs::path& xdg) {
    section("trash-cli oracle (XDG_DATA_HOME in scratch)");
    std::string have = sh("command -v trash-list || ls $HOME/.local/bin/trash-list 2>/dev/null");
    if (have.empty()) {
        note("trash-cli not installed; skipped");
        return;
    }
    std::string env = "PATH=$HOME/.local/bin:$PATH XDG_DATA_HOME=" + quote(xdg) + " ";
    auto trash = vfs::make_freedesktop_trash(); // default home trash = $XDG_DATA_HOME/Trash
    std::error_code ec;
    std::string id;
    fs::path f = s / "cli" / "odd name ü & %.txt";
    write_file(f, "odd");
    CHECK(trash->trash(f, &id, ec));
    CHECK(path_exists(xdg / "Trash" / "files" / "odd name ü & %.txt"));
    std::string listing = sh(env + "trash-list 2>&1");
    CHECK_MSG(listing.find(f.native()) != std::string::npos, listing);
    // trash-cli restores an item brovfs trashed.
    sh("cd " + quote(s / "cli") + " && echo 0 | " + env + "trash-restore 2>&1");
    CHECK(read_file(f) == "odd");
    // brovfs lists and restores an item trashed by trash-cli.
    write_file(s / "cli" / "by_cli.txt", "cli");
    sh(env + "trash-put " + quote(s / "cli" / "by_cli.txt") + " 2>&1");
    CHECK(!path_exists(s / "cli" / "by_cli.txt"));
    std::string cid;
    for (auto& item : trash->list()) {
        if (item.original_path == s / "cli" / "by_cli.txt") cid = item.id;
    }
    CHECK(!cid.empty());
    CHECK(!cid.empty() && trash->restore(cid, vfs::RestoreConflict::Fail, nullptr, ec) && read_file(s / "cli" / "by_cli.txt") == "cli");
}

#ifdef __APPLE__
static int run(const std::string& cmd) { return std::system(cmd.c_str()); }

// Finder's put-back records, end to end on a disk image this test creates: an item in the
// image's .Trashes/<uid> with a .DS_Store written by an independent library (fixture) is
// listed with Finder's original path and restored there. No Full Disk Access needed: the
// volume is ours.
static void macos_finder_records(const Scratch& s) {
    section("macOS: items Finder trashed are listed and restored from Finder's put-back records");
    std::string vol = "brovfsT" + std::to_string(::getpid());
    fs::path img = s / "finder.dmg";
    fs::path mnt = fs::path("/Volumes") / vol;
    if (run("hdiutil create -quiet -size 16m -fs APFS -volname " + vol + " '" + img.native() + "'") != 0 ||
        run("hdiutil attach -quiet -nobrowse '" + img.native() + "'") != 0 || !path_exists(mnt)) {
        note("could not create / attach a disk image; skipped");
        return;
    }
    fs::path tdir = mnt / ".Trashes" / std::to_string(::getuid());
    std::error_code ec;
    fs::create_directories(tdir, ec);
    fs::copy_file(fs::path(BROVFS_FIXTURES) / "trash.DS_Store", tdir / ".DS_Store", ec);
    write_file(tdir / "file000.txt", "zero");
    write_file(tdir / "file003.txt", "three");
    write_file(tdir / "no-putback.txt", "?");
    vfs::MacTrashConfig cfg;
    cfg.journal = s / "finder-journal";
    auto trash = vfs::make_macos_trash(cfg);
    auto items = trash->list();
    auto get = [&](const char* leaf) {
        std::optional<vfs::TrashItem> r;
        for (auto& i : items) {
            if (i.stored_path == tdir / leaf) r = i;
        }
        return r;
    };
    auto f0 = get("file000.txt"), f3 = get("file003.txt"), fn = get("no-putback.txt");
    CHECK(f0 && f0->finder_put_back && f0->original_path == mnt / "Users/j/Desktop/dir0/file000.txt");
    CHECK(f3 && f3->finder_put_back && f3->original_path == mnt / "Users/j/Desktop/dir3/orig003.txt" &&
          f3->name == "orig003.txt");
    CHECK(fn && !fn->finder_put_back && fn->original_path.empty());
    fs::path to;
    CHECK_MSG(f3 && trash->restore(f3->id, vfs::RestoreConflict::Fail, &to, ec), ec.message());
    CHECK(to == mnt / "Users/j/Desktop/dir3/orig003.txt" && read_file(to) == "three");
    CHECK(fn && !trash->restore(fn->id, vfs::RestoreConflict::Fail, nullptr, ec) && ec == vfs::Errc::trash_info_invalid);
    run("hdiutil detach -quiet -force '" + mnt.native() + "'");
}

// Asking Finder to trash needs Automation consent, which a test (often over ssh) cannot give,
// and even with consent Finder can fail the event (a CI runner's Finder does). Require then
// fails without touching the item, with operation_not_permitted when consent is what is
// missing; IfPermitted falls back to NSFileManager either way.
static void macos_finder_mode(vfs::Trash& plain, const Scratch& s, const std::string& tag, const fs::path& journal) {
    section("macOS: trashing through Finder only with the user's Automation consent");
    vfs::MacTrashConfig req;
    req.journal = journal;
    req.search_volumes = false;
    req.finder = vfs::FinderTrash::Require;
    auto finder = vfs::make_macos_trash(req);
    fs::path f = s / (tag + "_finder.txt");
    write_file(f, "f");
    std::string id;
    std::error_code ec;
    bool ok = finder->trash(f, &id, ec);
    if (ok) {
        note("Finder automation is permitted here: trashed through Finder");
        CHECK(!path_exists(f) && path_exists(fs::path(id)));
        CHECK_MSG(finder->restore(id, vfs::RestoreConflict::Fail, nullptr, ec) && read_file(f) == "f", ec.message());
    } else {
        const int consent = vfs::detail::finder_permission(false);
        note("Finder did not trash it (consent check: " + std::to_string(consent) + "): " + ec.message());
        CHECK(read_file(f) == "f");
        if (consent != 0) CHECK(ec == std::errc::operation_not_permitted);
        char buf[8];
        CHECK(::getxattr(f.c_str(), "com.bro.vfs.putback", buf, sizeof(buf), 0, XATTR_NOFOLLOW) < 0);
    }
    req.finder = vfs::FinderTrash::IfPermitted;
    auto maybe = vfs::make_macos_trash(req);
    CHECK_MSG(maybe->trash(f, &id, ec), ec.message());
    CHECK(!path_exists(f) && plain.restore(id, vfs::RestoreConflict::Fail, nullptr, ec) && read_file(f) == "f");
}

// The real macOS Trash, touching only items this test created (all under its scratch dir).
// The journal is persistent across runs (next to the scratch dirs, not inside one) and gets
// each item's predicted trash name before the move, so the leftovers of a run that died at any
// point are found and erased by the next run even without Full Disk Access.
static void macos_trash(const Scratch& s) {
    vfs::MacTrashConfig cfg;
    cfg.journal = fs::absolute(scratch_base()) / "macos-trash-test-journal";
    cfg.search_volumes = false;
    auto trash = vfs::make_macos_trash(cfg);
    cleanup_own_items(*trash, s); // a crashed earlier run
    std::string tag = "brovfstest" + std::to_string(::getpid());

    section("macOS: an item trashed by a run that died is found and erased by the next one");
    {
        // A child process trashes an item and exits without any cleanup, like a crash.
        fs::path f = s / (tag + "_orphan.txt");
        write_file(f, "orphan");
        pid_t pid = 0;
        std::string a0 = g_argv0, a1 = "--orphan", a2 = f.native(), a3 = cfg.journal.native();
        char* args[] = {a0.data(), a1.data(), a2.data(), a3.data(), nullptr};
        int status = -1;
        if (::posix_spawn(&pid, g_argv0, nullptr, nullptr, args, environ) == 0) ::waitpid(pid, &status, 0);
        CHECK(status == 0 && !path_exists(f));
        CHECK(cleanup_own_items(*trash, s) >= 1);
        bool still = false;
        for (auto& item : trash->list()) still |= item.original_path == f;
        CHECK(!still);
    }

    common_checks(*trash, s, tag);
    macos_finder_mode(*trash, s, tag, cfg.journal);

    section("macOS: the persistent journal records each trashed item");
    {
        fs::path f = s / (tag + "_pre.txt");
        write_file(f, "p");
        std::string id;
        std::error_code ec;
        CHECK(trash->trash(f, &id, ec));
        std::string j = read_file(cfg.journal);
        CHECK(j.find(id) != std::string::npos);
        CHECK(trash->restore(id, vfs::RestoreConflict::Fail, nullptr, ec));
    }

    section("macOS: restore data travels with the item and is removed on restore");
    fs::path f = s / (tag + "_x.txt");
    write_file(f, "x");
    std::string id;
    std::error_code ec;
    CHECK_MSG(trash->trash(f, &id, ec), ec.message());
    char buf[4096];
    ssize_t n = ::getxattr(id.c_str(), "com.bro.vfs.putback", buf, sizeof(buf), 0, XATTR_NOFOLLOW);
    CHECK(n > 0 && std::string(buf, static_cast<size_t>(n)) == f.native());
    CHECK(read_file(cfg.journal).find(id) != std::string::npos);
    CHECK(trash->restore(id, vfs::RestoreConflict::Fail, nullptr, ec) && read_file(f) == "x");
    CHECK(::getxattr(f.c_str(), "com.bro.vfs.putback", buf, sizeof(buf), 0, XATTR_NOFOLLOW) < 0);
    // The journal drops entries that are no longer in the trash.
    (void)trash->list();
    CHECK(read_file(cfg.journal).find(id) == std::string::npos);

    section("macOS: symlinks are trashed as links; the trash itself is refused");
    fs::create_symlink("target.txt", s / (tag + "_link"), ec);
    write_file(s / "target.txt", "t");
    CHECK_MSG(trash->trash(s / (tag + "_link"), &id, ec), ec.message());
    CHECK(fs::is_symlink(fs::symlink_status(fs::path(id))) && read_file(s / "target.txt") == "t");
    CHECK(trash->restore(id, vfs::RestoreConflict::Fail, nullptr, ec) && fs::is_symlink(fs::symlink_status(s / (tag + "_link"))));
    CHECK(!trash->trash(fs::path(id).parent_path(), &id, ec));

    cleanup_own_items(*trash, s);
    for (auto& item : trash->list()) CHECK_MSG(!within(item.original_path, s.root()), u8(item.original_path));
}
#endif

int main(int argc, char** argv) {
#ifdef __APPLE__
    g_argv0 = argv[0];
    if (argc == 4 && std::string(argv[1]) == "--orphan") {
        // Child of the "run that died" check: trash one item, exit without cleanup.
        vfs::MacTrashConfig cfg;
        cfg.journal = argv[3];
        cfg.search_volumes = false;
        std::string id;
        std::error_code ec;
        bool ok = vfs::make_macos_trash(cfg)->trash(argv[2], &id, ec);
        ::_exit(ok ? 0 : 1);
    }
#else
    (void)argc;
    (void)argv;
#endif
    Scratch s("trash");
#ifdef __APPLE__
    macos_trash(s); // before XDG_DATA_HOME is redirected; touches only this run's items
    macos_finder_records(s);
    CHECK(vfs::system_trash() != nullptr);
#endif
    fs::path xdg = s / "xdg";
    ::setenv("XDG_DATA_HOME", xdg.c_str(), 1); // nothing in this process may reach the real trash
    fs::path home_trash = xdg / "Trash";
    vfs::FreedesktopTrashConfig cfg;
    cfg.home_trash = home_trash;
    cfg.search_mounts = false;
    auto trash = vfs::make_freedesktop_trash(cfg);
    common_checks(*trash, s, "fdtest");
    freedesktop_specific(s, home_trash);
    topdir_trash(s, home_trash);
    trash_cli_oracle(s, xdg);
    section("empty() on the scratch trash");
    auto r = trash->empty();
    CHECK_MSG(r.ok() && trash->list().empty(), describe(r));
    return finish("test_trash");
}

#endif
