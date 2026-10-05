// Foundation side of the macOS trash: the only Objective-C in brovfs.
#ifdef __APPLE__

#import <Foundation/Foundation.h>

#include "src/trash_macos.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace bro::vfs::detail {

namespace {

std::error_code map_error(NSError* err) {
    if (!err) return std::make_error_code(std::errc::io_error);
    NSError* under = err.userInfo[NSUnderlyingErrorKey];
    if ([err.domain isEqualToString:NSCocoaErrorDomain]) {
        switch (err.code) {
            case NSFeatureUnsupportedError: return make_error_code(Errc::no_trash_available);
            case NSFileNoSuchFileError:
            case NSFileReadNoSuchFileError: return {ENOENT, std::system_category()};
            default: break;
        }
    }
    if (under && [under.domain isEqualToString:NSPOSIXErrorDomain]) {
        return {static_cast<int>(under.code), std::system_category()};
    }
    if ([err.domain isEqualToString:NSPOSIXErrorDomain]) return {static_cast<int>(err.code), std::system_category()};
    if ([err.domain isEqualToString:NSCocoaErrorDomain] &&
        (err.code == NSFileWriteNoPermissionError || err.code == NSFileReadNoPermissionError)) {
        return {EACCES, std::system_category()};
    }
    return std::make_error_code(std::errc::io_error);
}

} // namespace

bool ns_trash_item(const fs::path& p, fs::path& stored, std::error_code& ec) {
    @autoreleasepool {
        NSFileManager* fm = [NSFileManager defaultManager];
        NSString* s = [fm stringWithFileSystemRepresentation:p.c_str() length:std::strlen(p.c_str())];
        if (!s) {
            ec = make_error_code(Errc::invalid_argument);
            return false;
        }
        NSURL* url = [NSURL fileURLWithPath:s];
        NSURL* out = nil;
        NSError* err = nil;
        if (![fm trashItemAtURL:url resultingItemURL:&out error:&err]) {
            ec = map_error(err);
            return false;
        }
        if (!out) {
            // Moved, but the destination is unknown: report it rather than invent an id.
            ec = make_error_code(Errc::trash_info_invalid);
            return false;
        }
        stored = fs::path(out.path.fileSystemRepresentation);
        return true;
    }
}

fs::path ns_home_trash() {
    @autoreleasepool {
        NSURL* url = [[NSFileManager defaultManager] URLForDirectory:NSTrashDirectory
                                                            inDomain:NSUserDomainMask
                                                   appropriateForURL:nil
                                                              create:NO
                                                               error:nil];
        if (url) return fs::path(url.path.fileSystemRepresentation);
        const char* home = std::getenv("HOME");
        return fs::path(home ? home : "") / ".Trash";
    }
}

} // namespace bro::vfs::detail

#endif // __APPLE__
