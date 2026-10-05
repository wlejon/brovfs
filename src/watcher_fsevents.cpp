// macOS watch backend: FSEvents with per-file events, one stream per root, all streams on one
// serial dispatch queue.
//
// FSEvents reports a path with the union of what happened to it since the last delivery
// (flags are coalesced), so the kind of each event is decided by looking at the path now:
// present -> Created (if it was created or renamed in) or Modified; absent -> Removed. Renames
// arrive as consecutive ItemRenamed events and are paired by file id (extended data, 10.13+).
//  * MustScanSubDirs (FSEvents itself gave up on detail below a path) -> Rescan(path).
//  * UserDropped / KernelDropped -> Rescan(root).
//  * RootChanged (kFSEventStreamCreateFlagWatchRoot) or Unmount with the root gone or replaced
//    -> RootRemoved.
//  * Non-recursive watches filter to the root's direct children (FSEvents is always recursive).
// FSEvents reports resolved paths (/private/var/...), mapped back to the caller's spelling.
#if defined(__APPLE__)

#include "src/watch_core.h"
#include "src/sys.h"

#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>

#include <cctype>
#include <map>
#include <memory>

namespace bro::vfs::detail {

namespace {

class FSEventsBackend;

struct Stream {
    FSEventsBackend* owner = nullptr;
    WatchId id = 0;
    fs::path root;      // caller's spelling
    std::string real;   // resolved, as FSEvents reports it
    WatchOptions options;
    FileId root_id;
    FSEventStreamRef ref = nullptr;
    bool dead = false;
    // FSEvents flags are sticky: a later event for a path can still carry ItemCreated. Paths
    // already reported present (with their inode) let a repeat be told apart from a creation.
    // Bounded; forgetting only turns a Modified back into a (harmless) repeated Created.
    std::map<std::string, int64_t> known;
};

struct Raw {
    std::string path;
    FSEventStreamEventFlags flags = 0;
    int64_t file_id = 0;
};

FileKind kind_of(FSEventStreamEventFlags f) {
    if (f & kFSEventStreamEventFlagItemIsSymlink) return FileKind::Symlink;
    if (f & kFSEventStreamEventFlagItemIsDir) return FileKind::Directory;
    if (f & kFSEventStreamEventFlagItemIsFile) return FileKind::Regular;
    return FileKind::Unknown;
}

bool prefix_ci(const std::string& s, const std::string& prefix) {
    if (s.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) != std::tolower(static_cast<unsigned char>(prefix[i]))) {
            return false;
        }
    }
    return true;
}

std::string cf_string(CFStringRef s) {
    if (!s) return {};
    CFIndex max = CFStringGetMaximumSizeOfFileSystemRepresentation(s);
    std::string out(static_cast<size_t>(max), '\0');
    if (!CFStringGetFileSystemRepresentation(s, out.data(), max)) return {};
    out.resize(std::strlen(out.c_str()));
    return out;
}

class FSEventsBackend final : public WatchBackend {
public:
    explicit FSEventsBackend(EventSink& sink) : sink_(sink) {
        queue_ = dispatch_queue_create("brovfs.fsevents", DISPATCH_QUEUE_SERIAL);
    }

    ~FSEventsBackend() override {
        std::vector<WatchId> ids;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& [id, s] : streams_) ids.push_back(id);
        }
        for (WatchId id : ids) remove(id);
        dispatch_release(queue_);
    }

    bool add(WatchId id, const fs::path& root, const fs::path& real, const WatchOptions& options,
             std::error_code& ec) override {
        auto s = std::make_unique<Stream>();
        s->owner = this;
        s->id = id;
        s->root = root;
        s->real = real.native();
        while (s->real.size() > 1 && s->real.back() == '/') s->real.pop_back();
        s->options = options;
        sys::Stat st;
        if (!sys::stat_follow(real, st, ec)) return false;
        s->root_id = st.id;

        CFStringRef path = CFStringCreateWithFileSystemRepresentation(nullptr, s->real.c_str());
        CFArrayRef paths = CFArrayCreate(nullptr, reinterpret_cast<const void**>(&path), 1, &kCFTypeArrayCallBacks);
        FSEventStreamContext ctx{};
        ctx.info = s.get();
        FSEventStreamCreateFlags flags = kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagWatchRoot |
                                         kFSEventStreamCreateFlagNoDefer | kFSEventStreamCreateFlagUseCFTypes |
                                         kFSEventStreamCreateFlagUseExtendedData;
        s->ref = FSEventStreamCreate(nullptr, &FSEventsBackend::callback, &ctx, paths, kFSEventStreamEventIdSinceNow,
                                     0.01, flags);
        CFRelease(paths);
        CFRelease(path);
        if (!s->ref) {
            ec = std::make_error_code(std::errc::io_error);
            return false;
        }
        FSEventStreamSetDispatchQueue(s->ref, queue_);
        if (!FSEventStreamStart(s->ref)) {
            FSEventStreamInvalidate(s->ref);
            FSEventStreamRelease(s->ref);
            ec = std::make_error_code(std::errc::io_error);
            return false;
        }
        // Make sure the stream is registered before add() returns: FSEventStreamFlushSync
        // delivers anything already queued and returns once fseventsd has caught up.
        FSEventStreamFlushSync(s->ref);
        std::lock_guard<std::mutex> lock(mutex_);
        streams_[id] = std::move(s);
        return true;
    }

    void remove(WatchId id) override {
        std::unique_ptr<Stream> s;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = streams_.find(id);
            if (it == streams_.end()) return;
            s = std::move(it->second);
            streams_.erase(it);
        }
        // Stop on the stream's own queue: once this returns no callback is running or pending.
        dispatch_sync_f(queue_, s.get(), [](void* p) {
            auto* st = static_cast<Stream*>(p);
            st->dead = true;
            FSEventStreamStop(st->ref);
            FSEventStreamInvalidate(st->ref);
            FSEventStreamRelease(st->ref);
            st->ref = nullptr;
        });
    }

private:
    static void callback(ConstFSEventStreamRef, void* info, size_t n, void* event_paths,
                         const FSEventStreamEventFlags flags[], const FSEventStreamEventId[]) {
        auto* s = static_cast<Stream*>(info);
        if (s->dead) return;
        stall_for_test();
        std::vector<Raw> raws;
        raws.reserve(n);
        auto arr = static_cast<CFArrayRef>(event_paths);
        for (size_t i = 0; i < n; ++i) {
            Raw r;
            r.flags = flags[i];
            auto item = CFArrayGetValueAtIndex(arr, static_cast<CFIndex>(i));
            if (CFGetTypeID(item) == CFDictionaryGetTypeID()) {
                auto dict = static_cast<CFDictionaryRef>(item);
                r.path = cf_string(static_cast<CFStringRef>(CFDictionaryGetValue(dict, kFSEventStreamEventExtendedDataPathKey)));
                auto num = static_cast<CFNumberRef>(CFDictionaryGetValue(dict, kFSEventStreamEventExtendedFileIDKey));
                if (num) CFNumberGetValue(num, kCFNumberSInt64Type, &r.file_id);
            } else {
                r.path = cf_string(static_cast<CFStringRef>(item));
            }
            raws.push_back(std::move(r));
        }
        s->owner->handle(*s, raws);
    }

    // Relative path inside the root, or false if the event is outside it (or is the root).
    static bool relative(const Stream& s, const std::string& p, fs::path& rel, bool& is_root) {
        is_root = false;
        std::string q = p;
        while (q.size() > 1 && q.back() == '/') q.pop_back();
        if (q.size() == s.real.size() && prefix_ci(q, s.real)) {
            is_root = true;
            return true;
        }
        if (!prefix_ci(q, s.real) || q.size() <= s.real.size() + 1 || (s.real != "/" && q[s.real.size()] != '/')) {
            return false;
        }
        rel = fs::path(q.substr(s.real == "/" ? 1 : s.real.size() + 1));
        return true;
    }

    void push(Stream& s, WatchEventKind kind, const fs::path& rel, FileKind fk, const fs::path* old = nullptr) {
        if (s.dead) return;
        WatchEvent ev;
        ev.kind = kind;
        ev.watch = s.id;
        ev.path = s.root / rel;
        if (old) ev.old_path = s.root / *old;
        ev.file_kind = fk;
        if (old) forget(s, *old);
        sink_.add(std::move(ev));
    }

    static void forget(Stream& s, const fs::path& rel) {
        const std::string key = rel.native();
        s.known.erase(key);
        const std::string sub = key + '/'; // a subtree is one contiguous range of the ordered map
        auto it = s.known.lower_bound(sub);
        while (it != s.known.end() && it->first.compare(0, sub.size(), sub) == 0) it = s.known.erase(it);
    }

    static void remember(Stream& s, const fs::path& rel, int64_t ino) {
        if (s.known.size() > 65536) s.known.clear();
        s.known[rel.native()] = ino;
    }

    void kill(Stream& s) {
        if (s.dead) return;
        WatchEvent ev;
        ev.kind = WatchEventKind::RootRemoved;
        ev.watch = s.id;
        ev.path = s.root;
        ev.file_kind = FileKind::Directory;
        sink_.add(std::move(ev));
        s.dead = true;
    }

    bool root_alive(const Stream& s) {
        sys::Stat st;
        std::error_code ec;
        return sys::stat_follow(fs::path(s.real), st, ec) && st.kind == FileKind::Directory && st.id == s.root_id;
    }

    struct Now {
        bool exists = false;
        int64_t ino = 0;
    };
    static Now look(const Stream& s, const fs::path& rel) {
        Now n;
        sys::Stat st;
        std::error_code ec;
        if (sys::lstat(fs::path(s.real) / rel, st, ec)) {
            n.exists = true;
            n.ino = static_cast<int64_t>(st.id.lo);
        }
        return n;
    }

    void handle(Stream& s, const std::vector<Raw>& raws) {
        using F = FSEventStreamEventFlags;
        constexpr F kItem = kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemRemoved |
                            kFSEventStreamEventFlagItemRenamed | kFSEventStreamEventFlagItemModified |
                            kFSEventStreamEventFlagItemInodeMetaMod | kFSEventStreamEventFlagItemChangeOwner |
                            kFSEventStreamEventFlagItemXattrMod | kFSEventStreamEventFlagItemFinderInfoMod;
        for (size_t i = 0; i < raws.size() && !s.dead; ++i) {
            const Raw& r = raws[i];
            if (r.flags & (kFSEventStreamEventFlagUserDropped | kFSEventStreamEventFlagKernelDropped)) {
                sink_.rescan(s.id, s.root, std::make_error_code(std::errc::no_buffer_space));
                continue;
            }
            if (r.flags & (kFSEventStreamEventFlagRootChanged | kFSEventStreamEventFlagUnmount)) {
                if (!root_alive(s)) kill(s);
                continue;
            }
            fs::path rel;
            bool is_root = false;
            if (!relative(s, r.path, rel, is_root)) continue;
            if (r.flags & kFSEventStreamEventFlagMustScanSubDirs) {
                sink_.rescan(s.id, is_root ? s.root : s.root / rel);
                continue;
            }
            if (is_root) {
                if ((r.flags & (kFSEventStreamEventFlagItemRemoved | kFSEventStreamEventFlagItemRenamed)) &&
                    !root_alive(s)) {
                    kill(s);
                }
                continue; // the root's own metadata changes are not reported
            }
            if (!(r.flags & kItem)) continue;
            if (!s.options.recursive && rel.has_parent_path() && !rel.parent_path().empty()) continue;
            const FileKind fk = kind_of(r.flags);
            const Now now = look(s, rel);
            const bool present = now.exists && (r.file_id == 0 || now.ino == r.file_id);

            if (r.flags & kFSEventStreamEventFlagItemRenamed) {
                // Pair with the next renamed event of the same file id: old name gone, new present.
                if (i + 1 < raws.size() && (raws[i + 1].flags & kFSEventStreamEventFlagItemRenamed) && r.file_id != 0 &&
                    raws[i + 1].file_id == r.file_id && !present) {
                    fs::path rel2;
                    bool root2 = false;
                    if (relative(s, raws[i + 1].path, rel2, root2) && !root2) {
                        Now now2 = look(s, rel2);
                        bool in_scope = s.options.recursive || !rel2.has_parent_path() || rel2.parent_path().empty();
                        if (now2.exists && now2.ino == r.file_id && in_scope) {
                            push(s, WatchEventKind::Renamed, rel2, kind_of(raws[i + 1].flags), &rel);
                            ++i;
                            continue;
                        }
                    }
                }
                if (present) {
                    remember(s, rel, now.ino);
                } else {
                    forget(s, rel);
                }
                push(s, present ? WatchEventKind::Created : WatchEventKind::Removed, rel, fk);
                continue;
            }
            if (!now.exists) {
                forget(s, rel);
                push(s, WatchEventKind::Removed, rel, fk);
                continue;
            }
            constexpr F kChange = kFSEventStreamEventFlagItemModified | kFSEventStreamEventFlagItemInodeMetaMod |
                                  kFSEventStreamEventFlagItemChangeOwner | kFSEventStreamEventFlagItemXattrMod |
                                  kFSEventStreamEventFlagItemFinderInfoMod;
            auto k = s.known.find(rel.native());
            const bool repeat = k != s.known.end() && k->second == now.ino;
            if ((r.flags & (kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemRemoved)) && !repeat) {
                remember(s, rel, now.ino);
                push(s, WatchEventKind::Created, rel, fk);
            } else if (r.flags & kChange) {
                remember(s, rel, now.ino);
                push(s, WatchEventKind::Modified, rel, fk);
            }
        }
    }

    EventSink& sink_;
    dispatch_queue_t queue_ = nullptr;
    std::mutex mutex_;
    std::map<WatchId, std::unique_ptr<Stream>> streams_;
};

} // namespace

std::unique_ptr<WatchBackend> make_watch_backend(EventSink& sink) { return std::make_unique<FSEventsBackend>(sink); }
std::string_view watch_backend_name() noexcept { return "FSEvents"; }

} // namespace bro::vfs::detail

#endif // __APPLE__
