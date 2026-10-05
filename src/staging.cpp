// Recognising and cleaning staging files left behind by a crash (see file_ops.h).
#include "brovfs/file_ops.h"
#include "brovfs/path.h"

#include "src/engine.h"
#include "src/walk.h"

namespace bro::vfs {

bool is_staging_name(std::string_view n) noexcept {
    constexpr std::string_view prefix = ".brovfs-", suffix = ".tmp";
    if (n.size() != prefix.size() + 16 + suffix.size()) return false;
    if (n.substr(0, prefix.size()) != prefix || n.substr(n.size() - suffix.size()) != suffix) return false;
    for (char c : n.substr(prefix.size(), 16)) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

std::vector<StagingLeftover> find_staging_leftovers(const fs::path& dir, bool recursive, std::chrono::seconds min_age,
                                                    std::vector<ItemError>* errors) {
    std::vector<StagingLeftover> out;
    const int64_t cutoff_ms = sys::now_unix_ms() - static_cast<int64_t>(min_age.count()) * 1000;
    detail::WalkOptions wo;
    wo.max_depth = recursive ? 0 : 1;
    detail::walk(
        strip_trailing_separators(dir), wo, nullptr,
        [&](const detail::WalkNode& n) {
            if (n.stat_error || !is_staging_name(n.name)) return true;
            if (n.st.kind == FileKind::Directory) {
                // Only a junction caught between its mkdir and its reparse data: an empty one.
                bool empty = true;
                std::error_code lec;
                if (!sys::list_dir(n.path, [&](sys::RawEntry&&) { return empty = false; }, lec) || !empty) {
                    return true;
                }
            }
            int64_t changed = (n.st.ctime_ns ? n.st.ctime_ns : n.st.mtime_ns) / 1000000;
            if (changed > cutoff_ms) return true; // possibly an operation still writing it
            StagingLeftover l;
            l.path = n.path;
            l.kind = n.st.kind;
            l.size = n.st.size;
            l.changed_ms = changed;
            l.id = n.st.id;
            out.push_back(std::move(l));
            return true;
        },
        [&](const fs::path& p, const std::error_code& ec) {
            if (errors) errors->push_back({p, {}, ec, "scan"});
        });
    return out;
}

OpResult clean_staging_leftovers(const fs::path& dir, bool recursive, std::chrono::seconds min_age) {
    OpResult r;
    for (auto& l : find_staging_leftovers(dir, recursive, min_age, &r.errors)) {
        std::error_code ec;
        bool ok = l.kind == FileKind::Directory ? sys::remove_dir(l.path, ec, &l.id)
                                                : sys::remove_nondir(l.path, ec, &l.id);
        if (ok) {
            if (l.kind == FileKind::Regular) {
                ++r.files_done;
                r.bytes_done += l.size;
            } else {
                ++r.links_done;
            }
        } else {
            r.errors.push_back({l.path, {}, ec, "delete"});
        }
    }
    detail::finish_result(r, false);
    return r;
}

} // namespace bro::vfs
