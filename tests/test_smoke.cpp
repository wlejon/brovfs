#include "brovfs/vfs.h"
#include <cassert>
#include <iostream>

#ifdef _WIN32
#include <crtdbg.h>
#include <cstdlib>
#endif

int main() {
#ifdef _WIN32
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
    std::cout << "[test_smoke] Checking version..." << std::endl;
    assert(bro::vfs::version_major() == 0);
    assert(bro::vfs::version_minor() == 1);
    assert(bro::vfs::version_patch() == 0);
    assert(bro::vfs::version_string() == "0.1.0");

    std::cout << "[test_smoke] Checking type conversions..." << std::endl;
    assert(bro::vfs::file_type_to_string(bro::vfs::FileType::Regular) == "regular");
    assert(bro::vfs::file_type_to_string(bro::vfs::FileType::Directory) == "directory");
    assert(bro::vfs::file_type_to_string(bro::vfs::FileType::Symlink) == "symlink");

    assert(bro::vfs::op_status_to_string(bro::vfs::OpStatus::Pending) == "pending");
    assert(bro::vfs::op_status_to_string(bro::vfs::OpStatus::Running) == "running");
    assert(bro::vfs::op_status_to_string(bro::vfs::OpStatus::Completed) == "completed");

    std::cout << "[test_smoke] Checking path helpers..." << std::endl;
    std::string joined = bro::vfs::join_path("folder", "file.txt");
    assert(joined.find("file.txt") != std::string::npos);

    assert(bro::vfs::get_file_name("path/to/archive.tar.gz") == "archive.tar.gz");
    assert(bro::vfs::get_file_extension("archive.tar.gz") == ".gz");
    assert(bro::vfs::get_stem("archive.tar.gz") == "archive.tar");

    std::cout << "[test_smoke] Checking CancellationToken..." << std::endl;
    bro::vfs::CancellationToken token;
    assert(!token.is_cancelled());
    token.cancel();
    assert(token.is_cancelled());
    token.reset();
    assert(!token.is_cancelled());

    std::cout << "[test_smoke] Smoke tests passed!" << std::endl;
    return 0;
}
