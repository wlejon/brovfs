// macOS volume notification: DiskArbitration callbacks on a private dispatch queue. A disk
// appearing precedes its mount, so the volume-path change (the mount itself) is watched too;
// VolumeMonitor re-enumerates again shortly after each trigger regardless.
#ifdef __APPLE__

#include "src/volumes_internal.h"

#include <DiskArbitration/DiskArbitration.h>
#include <dispatch/dispatch.h>

namespace bro::vfs::detail {

namespace {

class DiskArbitrationNotifier final : public VolumeNotifier {
public:
    explicit DiskArbitrationNotifier(std::function<void()> trigger) : trigger_(std::move(trigger)) {}

    bool start(std::string& error) {
        session_ = DASessionCreate(kCFAllocatorDefault);
        if (!session_) {
            error = "DASessionCreate failed";
            return false;
        }
        queue_ = dispatch_queue_create("brovfs.volume-monitor", DISPATCH_QUEUE_SERIAL);
        DARegisterDiskAppearedCallback(session_, nullptr, &DiskArbitrationNotifier::appeared, this);
        DARegisterDiskDisappearedCallback(session_, nullptr, &DiskArbitrationNotifier::appeared, this);
        CFStringRef key = kDADiskDescriptionVolumePathKey;
        CFArrayRef keys = CFArrayCreate(kCFAllocatorDefault, reinterpret_cast<const void**>(&key), 1, &kCFTypeArrayCallBacks);
        DARegisterDiskDescriptionChangedCallback(session_, nullptr, keys, &DiskArbitrationNotifier::changed, this);
        CFRelease(keys);
        DASessionSetDispatchQueue(session_, queue_);
        return true;
    }

    ~DiskArbitrationNotifier() override {
        if (session_) {
            DASessionSetDispatchQueue(session_, nullptr);
            DAUnregisterCallback(session_, reinterpret_cast<void*>(&DiskArbitrationNotifier::appeared), this);
            DAUnregisterCallback(session_, reinterpret_cast<void*>(&DiskArbitrationNotifier::changed), this);
        }
        if (queue_) {
            dispatch_sync_f(queue_, nullptr, [](void*) {}); // a callback already running has finished
            dispatch_release(queue_);
        }
        if (session_) CFRelease(session_);
    }

private:
    static void appeared(DADiskRef, void* ctx) { static_cast<DiskArbitrationNotifier*>(ctx)->trigger_(); }
    static void changed(DADiskRef, CFArrayRef, void* ctx) { static_cast<DiskArbitrationNotifier*>(ctx)->trigger_(); }

    std::function<void()> trigger_;
    DASessionRef session_ = nullptr;
    dispatch_queue_t queue_ = nullptr;
};

} // namespace

std::unique_ptr<VolumeNotifier> start_volume_notifier(std::function<void()> trigger, std::string& error) {
    auto n = std::make_unique<DiskArbitrationNotifier>(std::move(trigger));
    if (!n->start(error)) return nullptr;
    return n;
}

} // namespace bro::vfs::detail

#endif // __APPLE__
