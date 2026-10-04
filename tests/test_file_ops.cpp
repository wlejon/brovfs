#include "brovfs/file_ops.h"
#include "brovfs/reflink.h"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#ifdef _WIN32
#include <crtdbg.h>
#include <cstdlib>
#endif

namespace fs = std::filesystem;

namespace {

void create_file(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out << content;
}

std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

} // namespace

int main() {
#ifdef _WIN32
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
    std::cout << "[test_file_ops] Setting up scratch directory..." << std::endl;
    fs::path scratch = fs::current_path() / "test_scratch_file_ops";
    std::error_code ec;
    fs::remove_all(scratch, ec);
    fs::create_directories(scratch, ec);

    fs::path src_file = scratch / "source.txt";
    fs::path dst_file = scratch / "dest.txt";
    create_file(src_file, "The quick brown fox jumps over the lazy dog.");

    std::cout << "[test_file_ops] Testing copy_file..." << std::endl;
    bool progress_called = false;
    bro::vfs::FileOpOptions opt;
    bool copy_ok = bro::vfs::copy_file(
        src_file.generic_string(),
        dst_file.generic_string(),
        opt,
        [&progress_called](const bro::vfs::ProgressInfo& info) -> bool {
            progress_called = true;
            assert(info.bytes_processed > 0);
            return true;
        }
    );
    assert(copy_ok);
    assert(progress_called);
    assert(fs::exists(dst_file));
    assert(read_file(dst_file) == "The quick brown fox jumps over the lazy dog.");

    std::cout << "[test_file_ops] Testing conflict resolution: Overwrite..." << std::endl;
    create_file(src_file, "New updated contents");
    opt.conflict_resolution = bro::vfs::ConflictResolution::Overwrite;
    assert(bro::vfs::copy_file(src_file.generic_string(), dst_file.generic_string(), opt));
    assert(read_file(dst_file) == "New updated contents");

    std::cout << "[test_file_ops] Testing conflict resolution: Skip..." << std::endl;
    create_file(src_file, "Ignored contents");
    opt.conflict_resolution = bro::vfs::ConflictResolution::Skip;
    assert(bro::vfs::copy_file(src_file.generic_string(), dst_file.generic_string(), opt));
    assert(read_file(dst_file) == "New updated contents"); // Should not have changed!

    std::cout << "[test_file_ops] Testing conflict resolution: AutoRename..." << std::endl;
    opt.conflict_resolution = bro::vfs::ConflictResolution::AutoRename;
    create_file(src_file, "Auto-renamed file contents");
    assert(bro::vfs::copy_file(src_file.generic_string(), dst_file.generic_string(), opt));
    fs::path renamed_file = scratch / "dest (1).txt";
    assert(fs::exists(renamed_file));
    assert(read_file(renamed_file) == "Auto-renamed file contents");

    std::cout << "[test_file_ops] Testing recursive copy_directory..." << std::endl;
    fs::path src_dir = scratch / "source_tree";
    fs::path dst_dir = scratch / "copied_tree";
    create_file(src_dir / "doc.txt", "Document text");
    create_file(src_dir / "sub" / "data.bin", "Binary data 12345");

    opt.conflict_resolution = bro::vfs::ConflictResolution::Overwrite;
    uint64_t total_dir_bytes = 0;
    bool dir_copy_ok = bro::vfs::copy_directory(
        src_dir.generic_string(),
        dst_dir.generic_string(),
        opt,
        [&total_dir_bytes](const bro::vfs::ProgressInfo& info) -> bool {
            total_dir_bytes = info.bytes_processed;
            return true;
        }
    );
    assert(dir_copy_ok);
    assert(fs::exists(dst_dir / "doc.txt"));
    assert(fs::exists(dst_dir / "sub" / "data.bin"));
    assert(read_file(dst_dir / "sub" / "data.bin") == "Binary data 12345");
    assert(total_dir_bytes > 0);

    std::cout << "[test_file_ops] Testing move_path..." << std::endl;
    fs::path move_target = scratch / "moved_tree";
    assert(bro::vfs::move_path(dst_dir.generic_string(), move_target.generic_string()));
    assert(!fs::exists(dst_dir));
    assert(fs::exists(move_target / "doc.txt"));

    std::cout << "[test_file_ops] Testing delete_path..." << std::endl;
    assert(bro::vfs::delete_path(move_target.generic_string()));
    assert(!fs::exists(move_target));

    std::cout << "[test_file_ops] Testing reflink clone_file..." << std::endl;
    fs::path clone_src = scratch / "clone_source.txt";
    fs::path clone_dst = scratch / "clone_dest.txt";
    create_file(clone_src, "Reflink or fallback clone data");
    auto reflink_res = bro::vfs::clone_file(clone_src.generic_string(), clone_dst.generic_string(), true);
    assert(reflink_res.success);
    assert(fs::exists(clone_dst));
    assert(read_file(clone_dst) == "Reflink or fallback clone data");

    std::cout << "[test_file_ops] Testing FileOpsWorker job queue..." << std::endl;
    {
        bro::vfs::FileOpsWorker worker;

        fs::path worker_src = scratch / "worker_src.txt";
        fs::path worker_dst = scratch / "worker_dst.txt";
        create_file(worker_src, "Worker payload text");

        bool copy_completed = false;
        uint64_t job_copy = worker.submit_copy(
            worker_src.generic_string(),
            worker_dst.generic_string(),
            {},
            nullptr,
            [&copy_completed](bool success, const std::string& err) {
                (void)err;
                assert(success);
                copy_completed = true;
            }
        );
        worker.wait_job(job_copy);
        assert(copy_completed);
        assert(worker.get_status(job_copy) == bro::vfs::OpStatus::Completed);
        assert(read_file(worker_dst) == "Worker payload text");

        fs::path worker_moved = scratch / "worker_moved.txt";
        uint64_t job_move = worker.submit_move(
            worker_dst.generic_string(),
            worker_moved.generic_string()
        );
        worker.wait_job(job_move);
        assert(worker.get_status(job_move) == bro::vfs::OpStatus::Completed);
        assert(!fs::exists(worker_dst));
        assert(fs::exists(worker_moved));

        uint64_t job_del = worker.submit_delete(worker_moved.generic_string());
        worker.wait_job(job_del);
        assert(worker.get_status(job_del) == bro::vfs::OpStatus::Completed);
        assert(!fs::exists(worker_moved));
    }

    fs::remove_all(scratch, ec);
    std::cout << "[test_file_ops] All file operations tests passed!" << std::endl;
    return 0;
}
