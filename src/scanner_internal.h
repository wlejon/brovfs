#pragma once

#include "brovfs/scanner.h"

namespace bro::vfs::detail {

bool scan_directory_platform(
    const std::string& path,
    BatchCallback& callback,
    const ScanOptions& options,
    std::shared_ptr<CancellationToken> token,
    uint32_t current_depth);

} // namespace bro::vfs::detail
