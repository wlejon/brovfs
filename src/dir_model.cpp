// DirectoryModel driver: one thread owns the view; it scans, applies watcher events and
// commands, and pushes the resulting updates. Readers (snapshot / find) take the mutex.
#include "brovfs/dir_model.h"

#include "brovfs/path.h"
#include "brovfs/watcher.h"
#include "src/dir_model_view.h"

#include <condition_variable>
#include <deque>
#include <future>
#include <mutex>
#include <thread>

namespace bro::vfs {

std::string_view to_string(ModelState s) noexcept {
    switch (s) {
        case ModelState::Loading: return "loading";
        case ModelState::Ready: return "ready";
        case ModelState::Gone: return "gone";
        case ModelState::Failed: return "failed";
    }
    return "?";
}

void apply_update(std::vector<ModelItem>& list, const ModelUpdate& u) {
    if (u.reset) list = u.items;
    for (const auto& op : u.ops) {
        switch (op.kind) {
            case ModelOp::Remove:
                if (op.index < list.size()) list.erase(list.begin() + static_cast<std::ptrdiff_t>(op.index));
                break;
            case ModelOp::Insert:
                if (op.index <= list.size()) list.insert(list.begin() + static_cast<std::ptrdiff_t>(op.index), op.item);
                break;
            case ModelOp::Update:
                if (op.index < list.size()) list[op.index] = op.item;
                break;
        }
    }
}

struct DirectoryModel::Impl {
    using Command = std::function<void()>;

    fs::path dir;
    ModelOptions opt;
    std::shared_ptr<ModelQueue> out;

    mutable std::mutex mutex;          // guards view, generation, state, error
    detail::ModelView view;
    uint64_t generation = 0;
    ModelState state = ModelState::Loading;
    std::error_code error;

    std::mutex cmd_mutex;
    std::condition_variable cv;
    std::deque<Command> commands;
    bool stopping = false;
    bool woken = false;

    std::shared_ptr<WatchEventQueue> events = std::make_shared<WatchEventQueue>();
    std::unique_ptr<DirectoryWatcher> watcher; // destroyed before the members above
    std::error_code watch_error;
    std::chrono::steady_clock::time_point last_change = std::chrono::steady_clock::now();
    std::vector<std::pair<std::promise<void>, std::chrono::steady_clock::time_point>> settlers;
    std::thread thread;

    Impl(fs::path d, ModelOptions o, std::shared_ptr<ModelQueue> q)
        : dir(strip_trailing_separators(d)), opt(std::move(o)), out(std::move(q)),
          view(opt.sort, opt.show_hidden, opt.filter) {
        thread = std::thread([this] { run(); });
    }

    ~Impl() {
        post(nullptr);
        thread.join();
        events->set_wake(nullptr);
        watcher.reset();
    }

    void wake() {
        {
            std::lock_guard<std::mutex> lock(cmd_mutex);
            woken = true;
        }
        cv.notify_all();
    }

    // A null command stops the thread.
    void post(Command c) {
        {
            std::lock_guard<std::mutex> lock(cmd_mutex);
            if (c) {
                commands.push_back(std::move(c));
            } else {
                stopping = true;
            }
        }
        cv.notify_all();
    }

    // Commits staged changes and pushes an update if anything changed (or `force`).
    void publish(std::vector<ScanError> errors = {}, bool force = false, bool reset = false) {
        ModelUpdate u;
        {
            std::lock_guard<std::mutex> lock(mutex);
            bool changed = view.commit(u.ops);
            if (reset) {
                u.ops.clear();
                u.reset = true;
                u.items = view.visible_items();
            }
            if (!changed && !force && !reset && errors.empty()) return;
            u.generation = ++generation;
            u.state = state;
            u.error = error;
            u.errors = std::move(errors);
        }
        last_change = std::chrono::steady_clock::now();
        out->push(std::move(u));
    }

    void set_state(ModelState s, std::error_code ec = {}) {
        std::lock_guard<std::mutex> lock(mutex);
        state = s;
        error = ec;
    }

    // Lists the directory; streams batches into the view when `stream`, else reconciles.
    bool load(bool stream) {
        ScanOptions so;
        so.recursive = false;
        so.include_hidden = true;
        so.batch_size = opt.batch_size;
        std::vector<FileEntry> all;
        std::vector<ScanError> errors;
        bool root_failed = false;
        std::error_code root_error;
        scan_directory_stream(
            dir,
            [&](ScanBatch&& b) {
                for (auto& e : b.errors) {
                    if (e.path == dir) {
                        root_failed = true;
                        root_error = e.code;
                    } else {
                        errors.push_back(std::move(e));
                    }
                }
                if (stream) {
                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        for (auto& e : b.entries) view.put(std::move(e));
                    }
                    publish();
                } else {
                    for (auto& e : b.entries) all.push_back(std::move(e));
                }
                return !stop_requested();
            },
            so);
        if (root_failed) {
            set_state(ModelState::Failed, root_error);
            {
                std::lock_guard<std::mutex> lock(mutex);
                view.clear();
            }
            publish(std::move(errors), true, true);
            return false;
        }
        if (!stream) {
            std::lock_guard<std::mutex> lock(mutex);
            view.reconcile(std::move(all));
        }
        set_state(ModelState::Ready);
        publish(std::move(errors), stream);
        return true;
    }

    bool stop_requested() {
        std::lock_guard<std::mutex> lock(cmd_mutex);
        return stopping;
    }

    void stat_into_view(const fs::path& p) {
        FileEntry e;
        std::error_code ec;
        const std::string name = path_to_utf8(leaf_name(p));
        std::lock_guard<std::mutex> lock(mutex);
        if (stat_entry(p, e, ec)) {
            view.put(std::move(e));
        } else {
            view.erase(name);
        }
    }

    void apply(const WatchEvent& ev, bool& rescan, std::vector<ScanError>& errors) {
        auto in_dir = [&](const fs::path& p) { return !p.empty() && p.parent_path() == dir; };
        switch (ev.kind) {
            case WatchEventKind::Created:
            case WatchEventKind::Removed:
            case WatchEventKind::Modified:
                if (in_dir(ev.path)) stat_into_view(ev.path);
                break;
            case WatchEventKind::Renamed: {
                FileEntry e;
                std::error_code ec;
                const bool to_exists = in_dir(ev.path) && stat_entry(ev.path, e, ec);
                std::lock_guard<std::mutex> lock(mutex);
                const ModelItem* old = in_dir(ev.old_path) ? view.find_name(path_to_utf8(leaf_name(ev.old_path))) : nullptr;
                const std::string old_name = old ? old->entry.name : std::string();
                const bool same = old && to_exists && old->entry.id == e.id;
                if (same) {
                    view.rename(old_name, std::move(e));
                } else {
                    if (old) view.erase(old_name);
                    if (to_exists) view.put(std::move(e));
                }
                break;
            }
            case WatchEventKind::Rescan: rescan = true; break;
            case WatchEventKind::RootRemoved: {
                set_state(ModelState::Gone, ev.error);
                std::lock_guard<std::mutex> lock(mutex);
                view.clear();
                break;
            }
            case WatchEventKind::Error: errors.push_back({ev.path, ev.error}); break;
        }
    }

    void run() {
        publish({}, true, true); // generation 1: empty, loading
        if (opt.watch) {
            watcher = std::make_unique<DirectoryWatcher>(events);
            events->set_wake([this] { wake(); });
            WatchOptions wo;
            wo.recursive = false;
            wo.latency = opt.latency;
            if (watcher->add(dir, wo, watch_error) == 0) watcher.reset();
        }
        // Watch first, list second: nothing created after the listing is missed.
        if (load(true) && watch_error) publish({{dir, watch_error}}); // listed, but not live
        for (;;) {
            std::deque<Command> cmds;
            {
                std::unique_lock<std::mutex> lock(cmd_mutex);
                cv.wait_for(lock, std::chrono::milliseconds(50), [&] { return stopping || woken || !commands.empty(); });
                if (stopping) break;
                woken = false;
                cmds.swap(commands);
            }
            auto evs = events->drain();
            if (!evs.empty()) last_change = std::chrono::steady_clock::now();
            bool rescan = false;
            std::vector<ScanError> errors;
            const bool live = state_now() == ModelState::Ready;
            for (auto& ev : evs) {
                if (live) apply(ev, rescan, errors);
            }
            if (state_now() == ModelState::Gone && live) {
                watcher.reset();
                publish(std::move(errors), true, true);
            } else {
                if (rescan) {
                    load(false);
                } else {
                    publish(std::move(errors));
                }
            }
            for (auto& c : cmds) c();
            // A settle completes after a quiet period that began no earlier than its request:
            // changes made just before it are still on their way through the watcher.
            const auto now = std::chrono::steady_clock::now();
            for (auto it = settlers.begin(); it != settlers.end();) {
                if (now - std::max(last_change, it->second) >= quiet()) {
                    it->first.set_value();
                    it = settlers.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (auto& p : settlers) p.first.set_value();
    }

    std::chrono::milliseconds quiet() const { return opt.latency + std::chrono::milliseconds(150); }

    ModelState state_now() const {
        std::lock_guard<std::mutex> lock(mutex);
        return state;
    }
};

DirectoryModel::DirectoryModel(fs::path directory, ModelOptions options, std::shared_ptr<ModelQueue> queue)
    : queue_(queue ? std::move(queue) : std::make_shared<ModelQueue>()) {
    impl_ = std::make_unique<Impl>(std::move(directory), std::move(options), queue_);
}

DirectoryModel::~DirectoryModel() = default;

const fs::path& DirectoryModel::directory() const noexcept { return impl_->dir; }

ModelSnapshot DirectoryModel::snapshot() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    ModelSnapshot s;
    s.generation = impl_->generation;
    s.state = impl_->state;
    s.error = impl_->error;
    s.items = impl_->view.visible_items();
    return s;
}

std::optional<ModelItem> DirectoryModel::find(ItemKey key) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    const ModelItem* m = impl_->view.find(key);
    return m ? std::optional<ModelItem>(*m) : std::nullopt;
}

void DirectoryModel::set_sort(SortSpec sort) {
    Impl* im = impl_.get();
    im->post([im, sort] {
        {
            std::lock_guard<std::mutex> lock(im->mutex);
            std::vector<ModelOp> ignored;
            im->view.commit(ignored); // nothing is staged between commands; keep it that way
            im->view.set_sort(sort);
        }
        im->publish({}, true, true);
    });
}

void DirectoryModel::set_filter(EntryFilter filter, bool show_hidden) {
    Impl* im = impl_.get();
    im->post([im, f = std::move(filter), show_hidden]() mutable {
        {
            std::lock_guard<std::mutex> lock(im->mutex);
            im->view.set_filter(std::move(f), show_hidden);
        }
        im->publish();
    });
}

void DirectoryModel::refresh() {
    Impl* im = impl_.get();
    im->post([im] {
        if (im->state_now() == ModelState::Ready || im->state_now() == ModelState::Failed) im->load(false);
    });
}

bool DirectoryModel::settle(std::chrono::milliseconds timeout) {
    std::promise<void> p;
    auto f = p.get_future();
    Impl* im = impl_.get();
    const auto at = std::chrono::steady_clock::now();
    im->post([im, at, pr = std::make_shared<std::promise<void>>(std::move(p))]() mutable {
        im->settlers.emplace_back(std::move(*pr), at);
    });
    return f.wait_for(timeout) == std::future_status::ready;
}

} // namespace bro::vfs
