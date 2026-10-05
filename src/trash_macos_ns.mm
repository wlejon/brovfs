// Foundation side of the macOS trash: the only Objective-C in brovfs.
#ifdef __APPLE__

#import <CoreServices/CoreServices.h>
#import <Foundation/Foundation.h>

#include "src/trash_macos.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <system_error>

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

fs::path ns_trash_for(const fs::path& p) {
    @autoreleasepool {
        NSFileManager* fm = [NSFileManager defaultManager];
        NSString* s = [fm stringWithFileSystemRepresentation:p.c_str() length:std::strlen(p.c_str())];
        if (!s) return {};
        NSURL* url = [fm URLForDirectory:NSTrashDirectory
                                inDomain:NSUserDomainMask
                       appropriateForURL:[NSURL fileURLWithPath:s]
                                  create:NO
                                   error:nil];
        return url ? fs::path(url.path.fileSystemRepresentation) : fs::path();
    }
}

namespace {
NSAppleEventDescriptor* finder_target() {
    return [NSAppleEventDescriptor descriptorWithBundleIdentifier:@"com.apple.finder"];
}

// Apple Event failures that have no errno equivalent keep their OSStatus, so a caller (and a
// test log) sees "Finder Apple Event failed: OSStatus -1728" rather than a bare EIO.
class OSStatusCategory final : public std::error_category {
public:
    const char* name() const noexcept override { return "brovfs.osstatus"; }
    std::string message(int code) const override {
        return "Finder Apple Event failed: OSStatus " + std::to_string(code);
    }
};

const std::error_category& osstatus_category() {
    static const OSStatusCategory cat;
    return cat;
}

// errAEEventNotPermitted (-1743): no Automation consent, whether the event was refused before
// it was sent or Finder refused it. procNotFound (-600): Finder is not running.
std::error_code map_ae_status(OSStatus st) {
    switch (st) {
        case errAEEventNotPermitted: return std::make_error_code(std::errc::operation_not_permitted);
        case procNotFound: return std::make_error_code(std::errc::no_such_process);
        case errAETimeout: return std::make_error_code(std::errc::timed_out);
        default: return {static_cast<int>(st), osstatus_category()};
    }
}
} // namespace

int finder_permission(bool ask) {
    @autoreleasepool {
        return static_cast<int>(
            AEDeterminePermissionToAutomateTarget(finder_target().aeDesc, kCoreEventClass, kAEDelete, ask ? true : false));
    }
}

bool finder_trash_item(const fs::path& p, fs::path& stored, std::error_code& ec) {
    @autoreleasepool {
        stored.clear();
        NSFileManager* fm = [NSFileManager defaultManager];
        NSString* s = [fm stringWithFileSystemRepresentation:p.c_str() length:std::strlen(p.c_str())];
        if (!s) {
            ec = make_error_code(Errc::invalid_argument);
            return false;
        }
        NSAppleEventDescriptor* target = finder_target();
        NSAppleEventDescriptor* del = [NSAppleEventDescriptor appleEventWithEventClass:kCoreEventClass
                                                                               eventID:kAEDelete
                                                                      targetDescriptor:target
                                                                              returnID:kAutoGenerateReturnID
                                                                         transactionID:kAnyTransactionID];
        [del setParamDescriptor:[NSAppleEventDescriptor descriptorWithFileURL:[NSURL fileURLWithPath:s]]
                     forKeyword:keyDirectObject];
        NSError* err = nil;
        NSAppleEventDescriptor* reply = [del sendEventWithOptions:NSAppleEventSendWaitForReply timeout:60 error:&err];
        if (!reply) {
            ec = err && [err.domain isEqualToString:NSOSStatusErrorDomain]
                     ? map_ae_status(static_cast<OSStatus>(err.code))
                     : map_error(err);
            return false;
        }
        NSAppleEventDescriptor* fail = [reply paramDescriptorForKeyword:keyErrorNumber];
        if (fail && fail.int32Value != 0) {
            ec = map_ae_status(static_cast<OSStatus>(fail.int32Value));
            return false;
        }
        // The reply names the trashed item as a Finder object; ask Finder for it as a file URL.
        NSAppleEventDescriptor* item = [reply paramDescriptorForKeyword:keyDirectObject];
        if (!item) return true;
        NSAppleEventDescriptor* get = [NSAppleEventDescriptor appleEventWithEventClass:kAECoreSuite
                                                                               eventID:kAEGetData
                                                                      targetDescriptor:target
                                                                              returnID:kAutoGenerateReturnID
                                                                         transactionID:kAnyTransactionID];
        [get setParamDescriptor:item forKeyword:keyDirectObject];
        [get setParamDescriptor:[NSAppleEventDescriptor descriptorWithTypeCode:typeFileURL] forKeyword:keyAERequestedType];
        NSAppleEventDescriptor* got = [get sendEventWithOptions:NSAppleEventSendWaitForReply timeout:30 error:nil];
        NSURL* url = [[got paramDescriptorForKeyword:keyDirectObject] fileURLValue];
        if (url.path) stored = fs::path(url.path.fileSystemRepresentation);
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
