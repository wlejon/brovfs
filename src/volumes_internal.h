#pragma once

#include "brovfs/volumes.h"
#include <vector>

namespace bro::vfs::detail {

std::vector<VolumeInfo> list_volumes_platform();

} // namespace bro::vfs::detail
