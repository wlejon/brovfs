#include "brovfs/file_ops.h"
#include "brovfs/path.h"
#include "brovfs/types.h"

#include <string>

namespace bro::vfs {

std::string_view to_string(FileKind kind) noexcept {
    switch (kind) {
        case FileKind::Regular: return "regular";
        case FileKind::Directory: return "directory";
        case FileKind::Symlink: return "symlink";
        case FileKind::Junction: return "junction";
        case FileKind::Fifo: return "fifo";
        case FileKind::Socket: return "socket";
        case FileKind::CharDevice: return "char_device";
        case FileKind::BlockDevice: return "block_device";
        case FileKind::Unknown: break;
    }
    return "unknown";
}

std::string_view to_string(Outcome o) noexcept {
    switch (o) {
        case Outcome::Success: return "success";
        case Outcome::Partial: return "partial";
        case Outcome::Failed: return "failed";
        case Outcome::Cancelled: return "cancelled";
    }
    return "unknown";
}

std::string_view to_string(OpStatus status) noexcept {
    switch (status) {
        case OpStatus::Pending: return "pending";
        case OpStatus::Running: return "running";
        case OpStatus::Paused: return "paused";
        case OpStatus::Completed: return "completed";
        case OpStatus::Cancelled: return "cancelled";
        case OpStatus::Failed: return "failed";
    }
    return "unknown";
}

std::string_view to_string(CopyMethod m) noexcept {
    switch (m) {
        case CopyMethod::None: return "none";
        case CopyMethod::Reflink: return "reflink";
        case CopyMethod::KernelCopy: return "kernel_copy";
        case CopyMethod::Stream: return "stream";
    }
    return "unknown";
}

namespace {

class VfsCategory final : public std::error_category {
public:
    const char* name() const noexcept override { return "brovfs"; }
    std::string message(int ev) const override {
        switch (static_cast<Errc>(ev)) {
            case Errc::ok: return "success";
            case Errc::same_file: return "source and destination are the same file";
            case Errc::destination_inside_source: return "destination is inside the source directory";
            case Errc::conflict_unresolved: return "destination exists and no conflict decision was given";
            case Errc::type_mismatch: return "cannot replace a directory with a non-directory (or vice versa)";
            case Errc::source_changed: return "source changed during the operation; it was kept";
            case Errc::unsupported_file_type: return "file type cannot be copied (socket or device)";
            case Errc::incomplete_copy: return "copied size does not match the source";
            case Errc::not_found: return "not found";
            case Errc::no_trash_available: return "no trash is available for this location; nothing was deleted";
            case Errc::invalid_trash_id: return "invalid trash item id";
            case Errc::trash_info_invalid: return "trash metadata is missing or malformed";
            case Errc::restore_target_exists: return "something already exists at the restore location";
            case Errc::aborted: return "aborted by conflict decision";
            case Errc::cancelled: return "cancelled";
            case Errc::invalid_argument: return "invalid argument";
            case Errc::directory_not_empty_after_move: return "source directory gained entries during the move; it was kept";
            case Errc::not_reversible: return "cannot be undone: the data it replaced is gone";
            case Errc::target_changed: return "changed since the operation; left as it is";
        }
        return "unknown brovfs error";
    }
};

} // namespace

const std::error_category& vfs_category() noexcept {
    static const VfsCategory cat;
    return cat;
}

std::error_code make_error_code(Errc e) noexcept { return {static_cast<int>(e), vfs_category()}; }

std::string ItemError::message() const {
    std::string m = operation.empty() ? std::string("error") : operation;
    if (!source.empty()) m += " '" + path_to_utf8(source) + "'";
    if (!destination.empty()) m += " -> '" + path_to_utf8(destination) + "'";
    m += ": " + code.message();
    return m;
}

} // namespace bro::vfs
