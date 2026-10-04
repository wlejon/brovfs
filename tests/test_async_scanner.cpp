#include "brovfs/scanner.h"
#include <algorithm>
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

void write_file(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p);
    out << content;
}

} // namespace

int main() {
#ifdef _WIN32
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
    std::cout << "[test_async_scanner] Setting up test environment..." << std::endl;
    fs::path test_root = fs::current_path() / "test_scratch_scanner";
    std::error_code ec;
    fs::remove_all(test_root, ec);
    fs::create_directories(test_root, ec);

    write_file(test_root / "file_a.txt", "Hello A");
    write_file(test_root / "file_b.log", "Log message B");
    write_file(test_root / ".dotfile", "Hidden settings");
    write_file(test_root / "sub_folder" / "child1.txt", "Child 1");
    write_file(test_root / "sub_folder" / "child2.txt", "Child 2");
    write_file(test_root / "sub_folder" / "deep_folder" / "deepest.txt", "Deepest content");

    std::cout << "[test_async_scanner] Testing top-level non-recursive scan..." << std::endl;
    bro::vfs::ScanOptions opt_top;
    opt_top.recursive = false;
    opt_top.include_hidden = true;
    auto top_entries = bro::vfs::scan_directory(test_root.generic_string(), opt_top);
    assert(top_entries.size() == 4); // file_a, file_b, .dotfile, sub_folder

    std::cout << "[test_async_scanner] Testing hidden files exclusion..." << std::endl;
    bro::vfs::ScanOptions opt_no_hidden;
    opt_no_hidden.recursive = false;
    opt_no_hidden.include_hidden = false;
    auto no_hidden_entries = bro::vfs::scan_directory(test_root.generic_string(), opt_no_hidden);
    assert(no_hidden_entries.size() == 3);
    for (const auto& e : no_hidden_entries) {
        assert(e.name != ".dotfile");
    }

    std::cout << "[test_async_scanner] Testing full recursive scan..." << std::endl;
    bro::vfs::ScanOptions opt_rec;
    opt_rec.recursive = true;
    opt_rec.include_hidden = true;
    auto rec_entries = bro::vfs::scan_directory(test_root.generic_string(), opt_rec);
    // Root level: file_a, file_b, .dotfile, sub_folder (4)
    // sub_folder level: child1, child2, deep_folder (3)
    // deep_folder level: deepest.txt (1)
    // Total = 8 entries
    assert(rec_entries.size() == 8);

    std::cout << "[test_async_scanner] Testing max_depth restriction..." << std::endl;
    bro::vfs::ScanOptions opt_depth;
    opt_depth.recursive = true;
    opt_depth.max_depth = 1;
    auto depth_entries = bro::vfs::scan_directory(test_root.generic_string(), opt_depth);
    // Root level: 4. Depth 1 (inside sub_folder): child1, child2, deep_folder (3).
    // deep_folder's children should NOT be traversed! Total = 7.
    assert(depth_entries.size() == 7);
    for (const auto& e : depth_entries) {
        assert(e.name != "deepest.txt");
    }

    std::cout << "[test_async_scanner] Testing directory sorting..." << std::endl;
    bro::vfs::ScanOptions opt_sort;
    opt_sort.recursive = false;
    opt_sort.sort_directories_first = true;
    auto sort_entries = bro::vfs::scan_directory(test_root.generic_string(), opt_sort);
    assert(!sort_entries.empty());
    assert(sort_entries[0].is_directory); // sub_folder must be first
    assert(sort_entries[0].name == "sub_folder");

    std::cout << "[test_async_scanner] Testing streaming batch callback with early abort..." << std::endl;
    size_t batch_count = 0;
    bro::vfs::ScanOptions opt_stream;
    opt_stream.recursive = true;
    opt_stream.batch_size = 2;
    bool aborted = !bro::vfs::scan_directory_stream(
        test_root.generic_string(),
        [&batch_count](std::vector<bro::vfs::FileEntry>&& batch) -> bool {
            (void)batch;
            batch_count++;
            // Abort after first batch
            return false;
        },
        opt_stream
    );
    assert(aborted);
    assert(batch_count == 1);

    std::cout << "[test_async_scanner] Testing asynchronous scan handle..." << std::endl;
    auto async_handle = bro::vfs::scan_directory_async(test_root.generic_string(), nullptr, opt_rec);
    assert(async_handle != nullptr);
    async_handle->wait();
    assert(!async_handle->is_running());
    auto async_results = async_handle->get_results();
    assert(async_results.size() == 8);

    std::cout << "[test_async_scanner] Testing asynchronous cancellation..." << std::endl;
    auto cancel_handle = bro::vfs::scan_directory_async(test_root.generic_string(), nullptr, opt_rec);
    cancel_handle->cancel();
    cancel_handle->wait();
    assert(!cancel_handle->is_running());

    fs::remove_all(test_root, ec);
    std::cout << "[test_async_scanner] All scanner tests passed successfully!" << std::endl;
    return 0;
}
