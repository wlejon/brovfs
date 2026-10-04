#pragma once

#include "brovfs/version.h"
#include "brovfs/types.h"
#include "brovfs/scanner.h"
#include "brovfs/file_ops.h"
#include "brovfs/reflink.h"
#include "brovfs/trash.h"
#include "brovfs/trash_freedesktop.h"
#include "brovfs/volumes.h"
#include "brovfs/mime.h"

namespace bro::vfs {

// Library initialization / teardown if needed (currently stateless)
inline void init() {}
inline void shutdown() {}

} // namespace bro::vfs
