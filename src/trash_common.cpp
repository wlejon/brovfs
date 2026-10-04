#include "brovfs/trash.h"

#include "src/engine.h"

#include <mutex>

namespace bro::vfs {

OpResult trash_paths(Trash& trash, const std::vector<fs::path>& paths,
                     const std::function<bool(const ProgressInfo&)>& on_progress,
                     std::shared_ptr<CancellationToken> token) {
    OpResult r;
    ProgressCallback cb = on_progress;
    detail::Progress prog(&cb, token.get());
    prog.phase(Phase::Trashing);
    prog.add_totals(0, paths.size());
    for (const auto& p : paths) {
        if (!prog.begin_item(p)) break;
        std::string id;
        std::error_code ec;
        if (trash.trash(p, &id, ec)) {
            r.trash_ids.push_back(id);
            ++r.files_done;
        } else {
            r.trash_ids.push_back(std::string());
            r.errors.push_back({p, {}, ec, "trash"});
        }
        prog.end_item();
    }
    while (r.trash_ids.size() < paths.size()) r.trash_ids.push_back(std::string());
    detail::finish_result(r, prog.stopped());
    return r;
}

std::shared_ptr<Trash> system_trash() {
    static std::mutex m;
    static std::shared_ptr<Trash> instance;
    std::lock_guard<std::mutex> lock(m);
    if (!instance) {
#ifdef _WIN32
        instance = make_recycle_bin();
#else
        instance = make_freedesktop_trash();
#endif
    }
    return instance;
}

} // namespace bro::vfs
