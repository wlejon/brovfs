// Linux watch backend: inotify, one inotify instance per root (so watch descriptors of
// overlapping roots never collide), serviced by one thread that polls all of them.
//
//  * Recursive watches add a watch per directory. A directory that appears (created or moved
//    in) is watched first and listed second, recursively, so nothing created inside it is
//    missed; its Created event is pushed after its subtree is watched.
//  * IN_MOVED_FROM / IN_MOVED_TO are queued adjacently by the kernel and paired by cookie; a
//    FROM that ends a read waits briefly for its TO. A directory renamed inside the tree keeps
//    its watches (they follow the inode) and their paths are rewritten; one moved out has its
//    watches dropped; one moved in is watched as new.
//  * IN_Q_OVERFLOW re-synchronises the watch set with the tree and pushes Rescan(root).
//  * A watch that cannot be added (ENOSPC: fs.inotify.max_user_watches) is an Error event
//    naming that directory: changes beneath it are not seen.
//  * IN_DELETE_SELF / IN_MOVE_SELF / IN_UNMOUNT / IN_IGNORED on the root is RootRemoved.
#if defined(__linux__)

#include "src/watch_core.h"
#include "src/sys.h"

#include <cerrno>
#include <cstring>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <map>
#include <memory>

namespace bro::vfs::detail {

namespace {

constexpr uint32_t kMask = IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM |
                           IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF | IN_EXCL_UNLINK | IN_ONLYDIR | IN_DONT_FOLLOW;

std::error_code errno_ec(int e) { return {e, std::system_category()}; }

struct RawEvent {
    int wd;
    uint32_t mask;
    uint32_t cookie;
    std::string name;
};

struct Root {
    WatchId id = 0;
    fs::path root;   // caller's spelling
    fs::path real;   // resolved, used for every syscall
    WatchOptions options;
    int fd = -1;
    int root_wd = -1;
    bool dead = false;
    std::unordered_map<int, fs::path> wd_rel;          // wd -> path relative to the root ("" = root)
    std::map<fs::path::string_type, int> rel_wd;       // ordered: a subtree is a contiguous range

    fs::path abs(const fs::path& rel) const { return rel.empty() ? root : root / rel; }
    fs::path sys_path(const fs::path& rel) const { return rel.empty() ? real : real / rel; }
};

class InotifyBackend final : public WatchBackend {
public:
    explicit InotifyBackend(EventSink& sink) : sink_(sink) {
        wake_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        thread_ = std::thread([this] { run(); });
    }

    ~InotifyBackend() override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_ = true;
        }
        wake();
        thread_.join();
        for (auto& [id, r] : roots_) {
            if (r->fd >= 0) ::close(r->fd);
        }
        if (wake_ >= 0) ::close(wake_);
    }

    bool add(WatchId id, const fs::path& root, const fs::path& real, const WatchOptions& options,
             std::error_code& ec) override {
        auto r = std::make_unique<Root>();
        r->id = id;
        r->root = root;
        r->real = real;
        r->options = options;
        r->fd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (r->fd < 0) {
            ec = errno_ec(errno);
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        int wd = ::inotify_add_watch(r->fd, real.c_str(), kMask);
        if (wd < 0) {
            ec = errno_ec(errno);
            ::close(r->fd);
            return false;
        }
        r->root_wd = wd;
        map(*r, wd, fs::path());
        if (options.recursive) watch_children(*r, fs::path());
        roots_[id] = std::move(r);
        wake();
        return true;
    }

    void remove(WatchId id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = roots_.find(id);
        if (it == roots_.end()) return;
        if (it->second->fd >= 0) ::close(it->second->fd);
        roots_.erase(it);
        wake();
    }

private:
    void wake() {
        if (wake_ < 0) return;
        uint64_t one = 1;
        [[maybe_unused]] ssize_t n = ::write(wake_, &one, sizeof(one));
    }

    // ------------------------------------------------------------ watch table

    static void map(Root& r, int wd, const fs::path& rel) {
        auto old = r.wd_rel.find(wd);
        if (old != r.wd_rel.end()) {
            auto o = r.rel_wd.find(old->second.native());
            if (o != r.rel_wd.end() && o->second == wd) r.rel_wd.erase(o);
        }
        r.wd_rel[wd] = rel;
        r.rel_wd[rel.native()] = wd;
    }

    static void unmap_wd(Root& r, int wd) {
        auto it = r.wd_rel.find(wd);
        if (it == r.wd_rel.end()) return;
        auto o = r.rel_wd.find(it->second.native());
        if (o != r.rel_wd.end() && o->second == wd) r.rel_wd.erase(o);
        r.wd_rel.erase(it);
    }

    // Entries of rel_wd at or below `rel` (never the root: rel is non-empty).
    template <class F>
    static void for_subtree(Root& r, const fs::path& rel, F&& f) {
        std::vector<std::pair<fs::path, int>> hits;
        const auto& key = rel.native();
        for (auto it = r.rel_wd.lower_bound(key); it != r.rel_wd.end(); ++it) {
            fs::path p(it->first);
            if (!path_within(p, rel)) {
                if (it->first.compare(0, key.size(), key) != 0) break; // past every "rel..." key
                continue; // "rel-x" sorts between "rel" and "rel/..."
            }
            hits.emplace_back(std::move(p), it->second);
        }
        for (auto& [p, wd] : hits) f(p, wd);
    }

    void drop_subtree(Root& r, const fs::path& rel) {
        for_subtree(r, rel, [&](const fs::path&, int wd) {
            ::inotify_rm_watch(r.fd, wd);
            unmap_wd(r, wd);
        });
    }

    void rename_subtree(Root& r, const fs::path& from, const fs::path& to) {
        drop_subtree(r, to); // a directory replaced by the rename
        std::vector<std::pair<fs::path, int>> moved;
        for_subtree(r, from, [&](const fs::path& p, int wd) { moved.emplace_back(p, wd); });
        const size_t n = from.native().size();
        for (auto& [p, wd] : moved) {
            fs::path np = to;
            if (p.native().size() > n) np = fs::path(to.native() + p.native().substr(n));
            map(r, wd, np);
        }
    }

    // Watch `rel` (a directory) and, recursively, every directory below it. Watch first, list
    // second: anything created after the listing is reported by the new watch.
    void watch_tree(Root& r, const fs::path& rel) {
        int wd = ::inotify_add_watch(r.fd, r.sys_path(rel).c_str(), kMask);
        if (wd < 0) {
            int e = errno;
            if (e != ENOENT && e != ENOTDIR && e != ELOOP) push_error(r, rel, errno_ec(e));
            return;
        }
        map(r, wd, rel);
        watch_children(r, rel);
    }

    void watch_children(Root& r, const fs::path& rel) {
        std::vector<fs::path> subdirs;
        std::error_code ec;
        sys::list_dir(r.sys_path(rel), [&](sys::RawEntry&& e) {
            if (e.st.kind == FileKind::Directory) subdirs.push_back(rel.empty() ? e.name : rel / e.name);
            return true;
        }, ec);
        for (auto& d : subdirs) watch_tree(r, d);
    }

    // After an overflow: rebuild the table from the tree as it is now.
    void resync(Root& r) {
        std::unordered_map<int, fs::path> before;
        before.swap(r.wd_rel);
        r.rel_wd.clear();
        map(r, r.root_wd, fs::path());
        if (r.options.recursive) watch_children(r, fs::path());
        for (auto& [wd, rel] : before) {
            if (!r.wd_rel.count(wd)) ::inotify_rm_watch(r.fd, wd);
        }
    }

    // ------------------------------------------------------------ events

    void push(Root& r, WatchEventKind kind, const fs::path& rel, FileKind fk, const fs::path* old_rel = nullptr) {
        if (r.dead) return;
        WatchEvent ev;
        ev.kind = kind;
        ev.watch = r.id;
        ev.path = r.abs(rel);
        if (old_rel) ev.old_path = r.abs(*old_rel);
        ev.file_kind = fk;
        sink_.add(std::move(ev));
    }

    void push_error(Root& r, const fs::path& rel, std::error_code ec) {
        if (r.dead) return;
        WatchEvent ev;
        ev.kind = WatchEventKind::Error;
        ev.watch = r.id;
        ev.path = r.abs(rel);
        ev.file_kind = FileKind::Directory;
        ev.error = ec;
        sink_.add(std::move(ev));
    }

    void kill(Root& r) {
        if (r.dead) return;
        WatchEvent ev;
        ev.kind = WatchEventKind::RootRemoved;
        ev.watch = r.id;
        ev.path = r.root;
        ev.file_kind = FileKind::Directory;
        sink_.add(std::move(ev));
        r.dead = true;
        if (r.fd >= 0) ::close(r.fd);
        r.fd = -1;
        r.wd_rel.clear();
        r.rel_wd.clear();
    }

    FileKind kind_of(Root& r, const fs::path& rel, uint32_t mask) {
        if (mask & IN_ISDIR) return FileKind::Directory;
        sys::Stat st;
        std::error_code ec;
        if (sys::lstat(r.sys_path(rel), st, ec)) return st.kind;
        return FileKind::Unknown;
    }

    static bool read_events(int fd, std::vector<RawEvent>& out) {
        alignas(struct inotify_event) char buf[64 * 1024];
        bool any = false;
        for (;;) {
            ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                return any;
            }
            any = true;
            for (ssize_t off = 0; off < n;) {
                auto* e = reinterpret_cast<struct inotify_event*>(buf + off);
                RawEvent re{e->wd, e->mask, e->cookie, e->len ? std::string(e->name) : std::string()};
                out.push_back(std::move(re));
                off += static_cast<ssize_t>(sizeof(struct inotify_event) + e->len);
            }
        }
    }

    void process(Root& r) {
        std::vector<RawEvent> evs;
        read_events(r.fd, evs);
        // The TO of a rename is queued right after its FROM; if a read ended between them,
        // give the kernel a moment to deliver it.
        for (int tries = 0; !evs.empty() && (evs.back().mask & IN_MOVED_FROM) && tries < 3; ++tries) {
            struct pollfd p{r.fd, POLLIN, 0};
            if (::poll(&p, 1, 5) <= 0 || !read_events(r.fd, evs)) break;
        }
        for (size_t i = 0; i < evs.size() && !r.dead; ++i) {
            const RawEvent& e = evs[i];
            if (e.mask & IN_Q_OVERFLOW) {
                resync(r);
                sink_.rescan(r.id, r.root, std::make_error_code(std::errc::no_buffer_space));
                continue;
            }
            if (e.mask & IN_IGNORED) {
                if (e.wd == r.root_wd) {
                    kill(r);
                } else {
                    unmap_wd(r, e.wd);
                }
                continue;
            }
            auto it = r.wd_rel.find(e.wd);
            if (it == r.wd_rel.end()) continue; // a watch already dropped
            const fs::path dir_rel = it->second;
            if (e.wd == r.root_wd && (e.mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT))) {
                kill(r);
                continue;
            }
            if (e.mask & (IN_DELETE_SELF | IN_MOVE_SELF)) continue; // its parent reports it
            if (e.mask & IN_UNMOUNT) {
                sink_.rescan(r.id, r.abs(dir_rel)); // a mount under the tree went away
                continue;
            }
            const fs::path rel = e.name.empty() ? dir_rel : (dir_rel.empty() ? fs::path(e.name) : dir_rel / e.name);
            const bool is_dir = (e.mask & IN_ISDIR) != 0;
            const bool deep = r.options.recursive && is_dir;
            if (e.mask & IN_CREATE) {
                if (deep) watch_tree(r, rel);
                push(r, WatchEventKind::Created, rel, kind_of(r, rel, e.mask));
            } else if (e.mask & IN_DELETE) {
                push(r, WatchEventKind::Removed, rel, is_dir ? FileKind::Directory : FileKind::Unknown);
            } else if (e.mask & IN_MOVED_FROM) {
                const RawEvent* to = i + 1 < evs.size() ? &evs[i + 1] : nullptr;
                auto tit = to ? r.wd_rel.find(to->wd) : r.wd_rel.end();
                if (to && (to->mask & IN_MOVED_TO) && to->cookie == e.cookie && tit != r.wd_rel.end()) {
                    const fs::path to_rel = tit->second.empty() ? fs::path(to->name) : tit->second / to->name;
                    if (deep) rename_subtree(r, rel, to_rel);
                    push(r, WatchEventKind::Renamed, to_rel, kind_of(r, to_rel, to->mask), &rel);
                    ++i;
                } else {
                    if (deep) drop_subtree(r, rel); // moved out of the tree
                    push(r, WatchEventKind::Removed, rel, is_dir ? FileKind::Directory : FileKind::Unknown);
                }
            } else if (e.mask & IN_MOVED_TO) {
                if (deep) watch_tree(r, rel); // moved in from outside
                push(r, WatchEventKind::Created, rel, kind_of(r, rel, e.mask));
            } else if (e.mask & (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE)) {
                push(r, WatchEventKind::Modified, rel, is_dir ? FileKind::Directory : FileKind::Unknown);
            }
        }
    }

    void run() {
        for (;;) {
            std::vector<struct pollfd> pfds;
            std::vector<WatchId> ids;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stop_) return;
                pfds.push_back({wake_, POLLIN, 0});
                ids.push_back(0);
                for (auto& [id, r] : roots_) {
                    if (r->fd < 0) continue;
                    pfds.push_back({r->fd, POLLIN, 0});
                    ids.push_back(id);
                }
            }
            int n = ::poll(pfds.data(), pfds.size(), -1);
            if (n < 0) {
                if (errno == EINTR) continue;
                return;
            }
            if (pfds[0].revents) {
                uint64_t v;
                while (::read(wake_, &v, sizeof(v)) > 0) {
                }
            }
            if (n > (pfds[0].revents ? 1 : 0)) stall_for_test();
            std::lock_guard<std::mutex> lock(mutex_);
            if (stop_) return;
            for (size_t i = 1; i < pfds.size(); ++i) {
                if (!pfds[i].revents) continue;
                auto it = roots_.find(ids[i]);
                if (it == roots_.end() || it->second->fd != pfds[i].fd || it->second->dead) continue;
                process(*it->second);
            }
        }
    }

    EventSink& sink_;
    int wake_ = -1;
    std::mutex mutex_;
    std::map<WatchId, std::unique_ptr<Root>> roots_;
    bool stop_ = false;
    std::thread thread_;
};

} // namespace

std::unique_ptr<WatchBackend> make_watch_backend(EventSink& sink) { return std::make_unique<InotifyBackend>(sink); }
std::string_view watch_backend_name() noexcept { return "inotify"; }

} // namespace bro::vfs::detail

#endif // __linux__
