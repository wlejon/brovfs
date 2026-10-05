#pragma once
// Bridge to Foundation for the macOS trash (trash_macos_ns.mm); the rest is trash_macos.cpp.
#ifdef __APPLE__

#include "brovfs/types.h"

namespace bro::vfs::detail {

// -[NSFileManager trashItemAtURL:resultingItemURL:error:] on `p` (a link is trashed as a link).
// On success `stored` is where the item now lives. A volume without a trash fails with
// Errc::no_trash_available and leaves the item untouched.
bool ns_trash_item(const fs::path& p, fs::path& stored, std::error_code& ec);

// The user's trash folder (NSTrashDirectory in the user domain), ~/.Trash as a fallback.
fs::path ns_home_trash();

} // namespace bro::vfs::detail

#endif
