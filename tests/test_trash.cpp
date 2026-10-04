#include "brovfs/trash.h"
#include "brovfs/trash_freedesktop.h"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#ifdef _WIN32
#include <crtdbg.h>
#include <cstdlib>
#endif

namespace fs = std::filesystem;

namespace {

void make_file(const fs::path& p, const std::string& text) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p);
    out << text;
}

std::string get_text(const fs::path& p) {
    std::ifstream in(p);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

} // namespace

int main() {
#ifdef _WIN32
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
    std::cout << "[test_trash] Initializing test directories..." << std::endl;
    fs::path scratch = fs::current_path() / "test_scratch_trash";
    std::error_code ec;
    fs::remove_all(scratch, ec);
    fs::create_directories(scratch, ec);

    fs::path trash_dir = scratch / "DesktopTrash";
    auto provider = std::make_shared<bro::vfs::FreeDesktopTrash>(trash_dir.generic_string());

    fs::path orig_file = scratch / "workspace" / "important_document.txt";
    make_file(orig_file, "Very important confidential notes.");

    std::cout << "[test_trash] Testing FreeDesktopTrash::trash_path..." << std::endl;
    std::string trash_id;
    bool trash_ok = provider->trash_path(orig_file.generic_string(), &trash_id);
    assert(trash_ok);
    assert(!trash_id.empty());
    assert(!fs::exists(orig_file)); // Original file was removed
    assert(fs::exists(fs::path(provider->get_files_dir()) / trash_id));
    assert(fs::exists(fs::path(provider->get_info_dir()) / (trash_id + ".trashinfo")));

    std::cout << "[test_trash] Testing FreeDesktopTrash::list_trash..." << std::endl;
    auto items = provider->list_trash();
    assert(items.size() == 1);
    assert(items[0].id == trash_id);
    assert(items[0].size > 0);
    assert(items[0].deletion_time_ms > 0);

    std::cout << "[test_trash] Testing collision resolution when trashing duplicate filename..." << std::endl;
    make_file(orig_file, "Second version of important document.");
    std::string trash_id2;
    assert(provider->trash_path(orig_file.generic_string(), &trash_id2));
    assert(trash_id2 != trash_id); // Unique ID assigned
    items = provider->list_trash();
    assert(items.size() == 2);

    std::cout << "[test_trash] Testing FreeDesktopTrash::restore_item..." << std::endl;
    // Restore the first item
    assert(provider->restore_item(trash_id));
    assert(fs::exists(orig_file));
    assert(get_text(orig_file) == "Very important confidential notes.");
    assert(!fs::exists(fs::path(provider->get_info_dir()) / (trash_id + ".trashinfo")));
    assert(!fs::exists(fs::path(provider->get_files_dir()) / trash_id));

    std::cout << "[test_trash] Testing trashing and restoring a directory..." << std::endl;
    fs::path test_dir = scratch / "workspace" / "nested_dir";
    make_file(test_dir / "child1.txt", "Child 1 content");
    make_file(test_dir / "sub" / "child2.txt", "Child 2 content");

    std::string dir_trash_id;
    assert(provider->trash_path(test_dir.generic_string(), &dir_trash_id));
    assert(!fs::exists(test_dir));

    assert(provider->restore_item(dir_trash_id));
    assert(fs::exists(test_dir / "child1.txt"));
    assert(fs::exists(test_dir / "sub" / "child2.txt"));
    assert(get_text(test_dir / "sub" / "child2.txt") == "Child 2 content");

    std::cout << "[test_trash] Testing FreeDesktopTrash::empty_trash..." << std::endl;
    assert(provider->empty_trash());
    items = provider->list_trash();
    assert(items.empty());

    std::cout << "[test_trash] Testing global trash API hooks..." << std::endl;
    bro::vfs::set_default_trash_provider(provider);
    make_file(orig_file, "Global hook test file");
    std::string global_id;
    assert(bro::vfs::trash(orig_file.generic_string(), &global_id));
    assert(bro::vfs::list_trash().size() == 1);
    assert(bro::vfs::restore_trash(global_id));
    assert(fs::exists(orig_file));

    fs::remove_all(scratch, ec);
    std::cout << "[test_trash] All trash tests passed successfully!" << std::endl;
    return 0;
}
