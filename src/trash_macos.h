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

// The trash folder that would receive `p` (its volume's), empty if the volume has none.
fs::path ns_trash_for(const fs::path& p);

// May this process send Finder a "delete" Apple Event? 0 = yes; otherwise the OSStatus of
// AEDeterminePermissionToAutomateTarget (-1743 denied, -1744 would need the user's consent,
// -600 Finder not running). With `ask`, the system may show the consent prompt (blocking).
int finder_permission(bool ask);

// Asks Finder to move `p` to the trash (Finder records its own put-back data, so "Put Back"
// works in Finder). `stored` is where Finder put it, or empty if Finder did not say.
bool finder_trash_item(const fs::path& p, fs::path& stored, std::error_code& ec);

} // namespace bro::vfs::detail

#endif
