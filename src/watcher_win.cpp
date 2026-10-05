// Windows watch backend: ReadDirectoryChangesExW (extended information: attributes, so the
// kind of an entry is known) with ReadDirectoryChangesW as the fallback, on one I/O
// completion port serviced by one thread that issues every read itself (I/O issued by a
// thread is tied to it).
//
//  * A completed read is copied out and the next read is issued before parsing, so the gap
//    in which changes are only buffered by the kernel is as short as possible.
//  * Kernel buffer overflow (a successful completion with no data, or ERROR_NOTIFY_ENUM_DIR)
//    becomes a Rescan of the root.
//  * RENAMED_OLD_NAME / RENAMED_NEW_NAME arrive adjacently; an old name is held until the
//    next record (or briefly, if it ended a buffer) and becomes Removed if no new name follows.
//  * The root's own deletion or rename is not reported by a watch on the root, so the parent
//    directory is watched (names only, non-recursive) for the root's name; a removal or
//    rename of that name that leaves the root unreachable is RootRemoved.
#ifdef _WIN32

#include "src/watch_core.h"
#include "src/win_util.h"

#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <vector>

namespace bro::vfs::detail {

namespace {

using namespace win;

constexpr ULONG_PTR kWakeKey = 1;
constexpr DWORD kBufferBytes = 64 * 1024; // the network redirector's maximum
constexpr auto kRenameHold = std::chrono::milliseconds(30);

constexpr DWORD kFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES |
                          FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION |
                          FILE_NOTIFY_CHANGE_SECURITY;

struct Watch;

struct Request {
    OVERLAPPED ov{}; // first member: the OVERLAPPED* of a completion is the Request*
    Watch* owner = nullptr;
    bool is_parent = false;
    bool pending = false;
    Handle dir;
    std::vector<DWORD> buffer = std::vector<DWORD>(kBufferBytes / sizeof(DWORD));
};

struct Held {
    fs::path path;
    FileKind kind = FileKind::Unknown;
    std::chrono::steady_clock::time_point deadline;
    bool from_remove = false; // REMOVED waiting for an ADDED of the same file id
    int64_t file_id = 0;
};

struct Watch {
    WatchId id = 0;
    fs::path root;
    fs::path real;         // root with links resolved: where short names are looked up
    WatchOptions options;
    FileId root_id;
    bool extended = true;
    bool old_unresolved = false; // a RENAMED_OLD_NAME became a Rescan: its NEW_NAME is a Created
    bool dead = false;     // RootRemoved pushed or being removed: push nothing more
    std::wstring leaf;     // root's name in its parent
    Request main;
    Request parent;
    std::optional<Held> held;
    std::promise<void>* on_gone = nullptr; // removal waiting for outstanding reads
};

// Could `c` be an 8.3 short name ("LONGFI~1.TXT")? Short names are upper case, a base of at
// most 8 characters containing "~<digit>", and an extension of at most 3.
bool short_name_shape(std::wstring_view c) {
    size_t dot = c.rfind(L'.');
    std::wstring_view base = dot == std::wstring_view::npos ? c : c.substr(0, dot);
    std::wstring_view ext = dot == std::wstring_view::npos ? std::wstring_view() : c.substr(dot + 1);
    if (base.empty() || base.size() > 8 || ext.size() > 3 || (dot != std::wstring_view::npos && ext.empty())) return false;
    size_t t = base.find(L'~');
    if (t == std::wstring_view::npos || t + 1 >= base.size() || base[t + 1] < L'0' || base[t + 1] > L'9') return false;
    for (wchar_t ch : c) {
        if (ch >= L'a' && ch <= L'z') return false;
    }
    return true;
}

// The long spelling of `rel` (relative to the directory `real`): each component that looks
// like a short name is replaced by the name of the object it reaches. Returns false when such
// a component no longer resolves (the object is gone); `resolved_prefix` then holds the
// components before it, long-spelled.
bool long_relative(const fs::path& real, const std::wstring& rel, fs::path& out, fs::path& resolved_prefix) {
    out.clear();
    fs::path rp(rel);
    bool any = false;
    for (const auto& c : rp) {
        if (short_name_shape(c.native())) any = true;
    }
    if (!any) {
        out = rp;
        return true;
    }
    for (const auto& c : rp) {
        if (!short_name_shape(c.native())) {
            out /= c;
            continue;
        }
        std::wstring full = win_extended_path(real / out / c);
        DWORD need = GetLongPathNameW(full.c_str(), nullptr, 0);
        std::wstring buf(need, L'\0');
        DWORD got = need ? GetLongPathNameW(full.c_str(), buf.data(), need) : 0;
        if (got == 0 || got >= need) {
            resolved_prefix = out;
            return false;
        }
        buf.resize(got);
        out /= fs::path(buf).filename();
    }
    return true;
}

FileKind kind_of(DWORD attrs, DWORD tag) {
    bool link_dir = false;
    if (attrs == 0) return FileKind::Unknown;
    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) && tag == 0) {
        return (attrs & FILE_ATTRIBUTE_DIRECTORY) ? FileKind::Directory : FileKind::Unknown;
    }
    return kind_from(attrs, tag, link_dir);
}

class WinWatchBackend final : public WatchBackend {
public:
    explicit WinWatchBackend(EventSink& sink) : sink_(sink) {
        port_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
        thread_ = std::thread([this] { run(); });
    }

    ~WinWatchBackend() override {
        post([this] { stopping_ = true; });
        thread_.join();
        CloseHandle(port_);
    }

    bool add(WatchId id, const fs::path& root, const fs::path& real, const WatchOptions& options,
             std::error_code& ec) override {
        bool ok = false;
        post_wait([&] { ok = do_add(id, root, real, options, ec); });
        return ok;
    }

    void remove(WatchId id) override {
        std::promise<void> gone;
        auto fut = gone.get_future();
        bool waiting = false;
        post_wait([&] { waiting = begin_remove(id, &gone); });
        if (waiting) fut.wait();
    }

private:
    // ------------------------------------------------------------ command plumbing

    void post(std::function<void()> fn) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            commands_.push_back(std::move(fn));
        }
        PostQueuedCompletionStatus(port_, 0, kWakeKey, nullptr);
    }

    void post_wait(std::function<void()> fn) {
        std::promise<void> done;
        auto fut = done.get_future();
        post([&] {
            fn();
            done.set_value();
        });
        fut.wait();
    }

    void run_commands() {
        std::deque<std::function<void()>> cmds;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cmds.swap(commands_);
        }
        for (auto& c : cmds) c();
    }

    // ------------------------------------------------------------ watches

    bool issue(Request& r, std::error_code* ec = nullptr) {
        Watch& w = *r.owner;
        r.ov = OVERLAPPED{};
        BOOL ok;
        if (r.is_parent) {
            ok = ReadDirectoryChangesW(r.dir.get(), r.buffer.data(), kBufferBytes, FALSE,
                                       FILE_NOTIFY_CHANGE_DIR_NAME, nullptr, &r.ov, nullptr);
        } else if (w.extended) {
            ok = ReadDirectoryChangesExW(r.dir.get(), r.buffer.data(), kBufferBytes, w.options.recursive, kFilter,
                                         nullptr, &r.ov, nullptr, ReadDirectoryNotifyExtendedInformation);
            if (!ok) {
                DWORD e = GetLastError();
                if (e == ERROR_INVALID_PARAMETER || e == ERROR_INVALID_FUNCTION || e == ERROR_NOT_SUPPORTED) {
                    w.extended = false; // e.g. an SMB share or a file system without the Ex class
                    return issue(r, ec);
                }
                SetLastError(e);
            }
        } else {
            ok = ReadDirectoryChangesW(r.dir.get(), r.buffer.data(), kBufferBytes, w.options.recursive, kFilter,
                                       nullptr, &r.ov, nullptr);
        }
        if (!ok) {
            if (ec) *ec = last_error();
            return false;
        }
        r.pending = true;
        return true;
    }

    static Handle open_dir(const fs::path& p) {
        std::wstring w = win_extended_path(p);
        return Handle(CreateFileW(w.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr));
    }

    bool do_add(WatchId id, const fs::path& root, const fs::path& real, const WatchOptions& options,
                std::error_code& ec) {
        auto w = std::make_unique<Watch>();
        w->id = id;
        w->root = root;
        w->real = real;
        w->options = options;
        w->main.owner = w.get();
        w->parent.owner = w.get();
        w->parent.is_parent = true;
        w->main.dir = open_dir(real);
        if (!w->main.dir.ok()) {
            ec = last_error();
            return false;
        }
        sys::Stat st;
        if (!stat_handle(w->main.dir.get(), st, ec)) return false;
        w->root_id = st.id;
        if (!CreateIoCompletionPort(w->main.dir.get(), port_, 0, 0)) {
            ec = last_error();
            return false;
        }
        if (!issue(w->main, &ec)) return false;
        // The parent watch is best effort (a drive root has none).
        fs::path parent = real.parent_path();
        w->leaf = real.filename().wstring();
        if (!parent.empty() && parent != real && !w->leaf.empty()) {
            w->parent.dir = open_dir(parent);
            if (w->parent.dir.ok() && (!CreateIoCompletionPort(w->parent.dir.get(), port_, 0, 0) || !issue(w->parent))) {
                w->parent.dir.reset();
            }
        }
        watches_.push_back(std::move(w));
        return true;
    }

    bool begin_remove(WatchId id, std::promise<void>* gone) {
        for (auto& w : watches_) {
            if (w->id != id) continue;
            w->dead = true;
            w->held.reset();
            if (!cancel(*w)) {
                erase(w.get());
                return false;
            }
            w->on_gone = gone;
            return true;
        }
        return false;
    }

    // Cancels outstanding reads; returns true if completions are still to come.
    static bool cancel(Watch& w) {
        bool outstanding = false;
        for (Request* r : {&w.main, &w.parent}) {
            if (r->pending && r->dir.ok()) {
                CancelIoEx(r->dir.get(), &r->ov);
                outstanding = true;
            }
        }
        return outstanding;
    }

    void erase(Watch* w) {
        for (auto it = watches_.begin(); it != watches_.end(); ++it) {
            if (it->get() == w) {
                watches_.erase(it);
                return;
            }
        }
    }

    // ------------------------------------------------------------ events

    void push(Watch& w, WatchEventKind kind, fs::path path, FileKind fk = FileKind::Unknown, fs::path old = {}) {
        if (w.dead) return;
        WatchEvent ev;
        ev.kind = kind;
        ev.watch = w.id;
        ev.path = std::move(path);
        ev.old_path = std::move(old);
        ev.file_kind = fk;
        sink_.add(std::move(ev));
    }

    void release_held(Watch& w) {
        if (!w.held) return;
        Held h = std::move(*w.held);
        w.held.reset();
        push(w, WatchEventKind::Removed, std::move(h.path), h.kind); // renamed out of the watch
    }

    bool root_alive(Watch& w) {
        FILE_STANDARD_INFO si{};
        if (w.main.dir.ok() && GetFileInformationByHandleEx(w.main.dir.get(), FileStandardInfo, &si, sizeof(si)) &&
            si.DeletePending) {
            return false;
        }
        sys::Stat st;
        std::error_code ec;
        return sys::stat_follow(w.root, st, ec) && st.id == w.root_id;
    }

    void kill(Watch& w, std::error_code why) {
        if (w.dead) return;
        release_held(w);
        WatchEvent ev;
        ev.kind = WatchEventKind::RootRemoved;
        ev.watch = w.id;
        ev.path = w.root;
        ev.file_kind = FileKind::Directory;
        ev.error = why;
        sink_.add(std::move(ev));
        w.dead = true;
        cancel(w);
    }

    void parse_main(Watch& w, const std::vector<unsigned char>& data) {
        size_t off = 0;
        while (off + sizeof(DWORD) * 3 <= data.size()) {
            DWORD next = 0, action = 0, attrs = 0, tag = 0, name_len = 0;
            int64_t file_id = 0;
            const WCHAR* name = nullptr;
            if (w.extended) {
                const auto* r = reinterpret_cast<const FILE_NOTIFY_EXTENDED_INFORMATION*>(data.data() + off);
                next = r->NextEntryOffset;
                action = r->Action;
                attrs = r->FileAttributes;
                tag = r->ReparsePointTag;
                file_id = r->FileId.QuadPart;
                name_len = r->FileNameLength;
                name = r->FileName;
            } else {
                const auto* r = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(data.data() + off);
                next = r->NextEntryOffset;
                action = r->Action;
                name_len = r->FileNameLength;
                name = r->FileName;
            }
            if (reinterpret_cast<const unsigned char*>(name) + name_len > data.data() + data.size()) break;
            // Changes made through an 8.3 alias are reported under the short name; events always
            // carry long names. A short name that no longer resolves (deleted, or the old name
            // of a rename) cannot be translated: its directory is rescanned instead.
            fs::path rel, prefix;
            if (!long_relative(w.real, std::wstring(name, name_len / sizeof(WCHAR)), rel, prefix)) {
                release_held(w);
                sink_.rescan(w.id, prefix.empty() ? w.root : w.root / prefix);
                w.old_unresolved = action == FILE_ACTION_RENAMED_OLD_NAME;
                if (next == 0) break;
                off += next;
                continue;
            }
            if (w.old_unresolved) {
                w.old_unresolved = false;
                if (action == FILE_ACTION_RENAMED_NEW_NAME) action = FILE_ACTION_ADDED;
            }
            fs::path path = w.root / rel;
            FileKind fk = kind_of(attrs, tag);
            // A move to another directory of the tree is reported as REMOVED + ADDED; the
            // extended records carry the file id, which pairs them into a rename.
            const bool pairs_old = w.held && !w.held->from_remove && action == FILE_ACTION_RENAMED_NEW_NAME;
            const bool pairs_removed = w.held && w.held->from_remove && action == FILE_ACTION_ADDED &&
                                       file_id != 0 && w.held->file_id == file_id;
            if (pairs_old || pairs_removed) {
                fs::path old = std::move(w.held->path);
                w.held.reset();
                push(w, WatchEventKind::Renamed, std::move(path), fk, std::move(old));
            } else {
                release_held(w);
                auto hold = [&](bool from_remove) {
                    w.held = Held{std::move(path), fk, std::chrono::steady_clock::now() + kRenameHold, from_remove,
                                  file_id};
                };
                switch (action) {
                    case FILE_ACTION_ADDED:
                    case FILE_ACTION_RENAMED_NEW_NAME: // renamed into the watch
                        push(w, WatchEventKind::Created, std::move(path), fk);
                        break;
                    case FILE_ACTION_REMOVED:
                        if (file_id != 0) {
                            hold(true);
                        } else {
                            push(w, WatchEventKind::Removed, std::move(path), fk);
                        }
                        break;
                    case FILE_ACTION_MODIFIED: push(w, WatchEventKind::Modified, std::move(path), fk); break;
                    case FILE_ACTION_RENAMED_OLD_NAME: hold(false); break;
                    default: break;
                }
            }
            if (next == 0) break;
            off += next;
        }
    }

    void parse_parent(Watch& w, const std::vector<unsigned char>& data) {
        size_t off = 0;
        bool suspicious = false;
        while (off + sizeof(FILE_NOTIFY_INFORMATION) <= data.size()) {
            const auto* r = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(data.data() + off);
            std::wstring_view name(r->FileName, r->FileNameLength / sizeof(WCHAR));
            if ((r->Action == FILE_ACTION_REMOVED || r->Action == FILE_ACTION_RENAMED_OLD_NAME) &&
                CompareStringOrdinal(name.data(), static_cast<int>(name.size()), w.leaf.c_str(),
                                     static_cast<int>(w.leaf.size()), TRUE) == CSTR_EQUAL) {
                suspicious = true;
            }
            if (r->NextEntryOffset == 0) break;
            off += r->NextEntryOffset;
        }
        if (suspicious && !root_alive(w)) kill(w, {});
    }

    void complete(Request& r, bool ok, DWORD bytes, DWORD err) {
        r.pending = false;
        Watch& w = *r.owner;
        if (w.dead) {
            if (!w.main.pending && !w.parent.pending) {
                if (w.on_gone) w.on_gone->set_value();
                erase(&w); // `r` and `w` are gone after this
            } else {
                cancel(w);
            }
            return;
        }
        if (r.is_parent) {
            if (!ok) {
                r.dir.reset(); // the parent went away; the main watch decides about the root
                return;
            }
            std::vector<unsigned char> data(reinterpret_cast<unsigned char*>(r.buffer.data()),
                                            reinterpret_cast<unsigned char*>(r.buffer.data()) + bytes);
            if (!issue(r)) r.dir.reset();
            if (bytes == 0) {
                if (!root_alive(w)) kill(w, {});
            } else {
                parse_parent(w, data);
            }
            return;
        }
        if (!ok && err != ERROR_NOTIFY_ENUM_DIR) {
            std::error_code why = win_error(err);
            if (!root_alive(w)) {
                kill(w, {});
            } else {
                kill(w, why); // the read cannot continue: the watch is dead either way
            }
            return;
        }
        std::vector<unsigned char> data;
        if (ok && bytes > 0) {
            data.assign(reinterpret_cast<unsigned char*>(r.buffer.data()),
                        reinterpret_cast<unsigned char*>(r.buffer.data()) + bytes);
        }
        std::error_code ec;
        if (!issue(r, &ec)) {
            if (!data.empty()) parse_main(w, data);
            kill(w, root_alive(w) ? ec : std::error_code());
            return;
        }
        if (data.empty()) {
            // Overflow: the kernel dropped records. Pending events are subsumed by the rescan.
            w.held.reset();
            sink_.rescan(w.id, w.root, std::make_error_code(std::errc::no_buffer_space));
            return;
        }
        parse_main(w, data);
    }

    void run() {
        for (;;) {
            auto now = std::chrono::steady_clock::now();
            DWORD timeout = INFINITE;
            for (auto& w : watches_) {
                if (!w->held) continue;
                if (w->held->deadline <= now) {
                    release_held(*w);
                } else {
                    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(w->held->deadline - now).count();
                    timeout = std::min<DWORD>(timeout, static_cast<DWORD>(ms + 1));
                }
            }
            if (stopping_) {
                bool any = false;
                for (auto& w : watches_) {
                    w->dead = true;
                    if (cancel(*w)) any = true;
                }
                if (!any) return;
                timeout = INFINITE;
            }
            DWORD bytes = 0;
            ULONG_PTR key = 0;
            OVERLAPPED* ov = nullptr;
            BOOL ok = GetQueuedCompletionStatus(port_, &bytes, &key, &ov, timeout);
            DWORD err = ok ? 0 : GetLastError();
            if (!ov) {
                if (ok && key == kWakeKey) run_commands();
                continue; // timeout
            }
            auto* r = reinterpret_cast<Request*>(ov);
            if (!r->is_parent && !stopping_) stall_for_test();
            complete(*r, ok != FALSE, bytes, err);
            if (stopping_) {
                for (size_t i = watches_.size(); i-- > 0;) {
                    Watch& w = *watches_[i];
                    if (!w.main.pending && !w.parent.pending) {
                        if (w.on_gone) w.on_gone->set_value();
                        watches_.erase(watches_.begin() + static_cast<std::ptrdiff_t>(i));
                    }
                }
            }
        }
    }

    EventSink& sink_;
    HANDLE port_ = nullptr;
    std::thread thread_;
    std::mutex mutex_;
    std::deque<std::function<void()>> commands_;
    std::vector<std::unique_ptr<Watch>> watches_; // owned by the backend thread
    bool stopping_ = false;
};

} // namespace

std::unique_ptr<WatchBackend> make_watch_backend(EventSink& sink) { return std::make_unique<WinWatchBackend>(sink); }
std::string_view watch_backend_name() noexcept { return "ReadDirectoryChangesW"; }

} // namespace bro::vfs::detail

#endif // _WIN32
