#include "brovfs/file_ops.h"
#include "brovfs/path.h"

#include "src/engine.h"

namespace bro::vfs {

namespace {

std::vector<detail::TransferPair> into(const std::vector<fs::path>& sources, const fs::path& dest_dir) {
    std::vector<detail::TransferPair> pairs;
    pairs.reserve(sources.size());
    for (const auto& s : sources) pairs.push_back({s, dest_dir / leaf_name(s)});
    return pairs;
}

OpResult transfer(detail::TransferMode mode, const std::vector<detail::TransferPair>& pairs,
                  const FileOpOptions& options, const ProgressCallback& on_progress,
                  const std::shared_ptr<CancellationToken>& token) {
    detail::Progress progress(&on_progress, token.get());
    return detail::run_transfer(mode, pairs, options, progress);
}

} // namespace

OpResult copy_into(const std::vector<fs::path>& sources, const fs::path& dest_dir, const FileOpOptions& options,
                   ProgressCallback on_progress, std::shared_ptr<CancellationToken> token) {
    return transfer(detail::TransferMode::Copy, into(sources, dest_dir), options, on_progress, token);
}

OpResult copy_to(const fs::path& src, const fs::path& dst, const FileOpOptions& options, ProgressCallback on_progress,
                 std::shared_ptr<CancellationToken> token) {
    return transfer(detail::TransferMode::Copy, {{src, dst}}, options, on_progress, token);
}

OpResult move_into(const std::vector<fs::path>& sources, const fs::path& dest_dir, const FileOpOptions& options,
                   ProgressCallback on_progress, std::shared_ptr<CancellationToken> token) {
    return transfer(detail::TransferMode::Move, into(sources, dest_dir), options, on_progress, token);
}

OpResult move_to(const fs::path& src, const fs::path& dst, const FileOpOptions& options, ProgressCallback on_progress,
                 std::shared_ptr<CancellationToken> token) {
    return transfer(detail::TransferMode::Move, {{src, dst}}, options, on_progress, token);
}

OpResult remove(const std::vector<fs::path>& paths, ProgressCallback on_progress,
                std::shared_ptr<CancellationToken> token) {
    detail::Progress progress(&on_progress, token.get());
    return detail::run_remove(paths, progress);
}

fs::path unique_sibling_name(const fs::path& path) {
    sys::Stat st;
    std::error_code ec;
    bool is_dir = sys::lstat(path, st, ec) && st.kind == FileKind::Directory;
    return detail::unique_sibling(strip_trailing_separators(path), is_dir);
}

CloneResult clone_file(const fs::path& src, const fs::path& dst, bool allow_fallback) {
    CloneResult r;
    sys::Stat st;
    if (!sys::lstat(src, st, r.error)) return r;
    if (st.kind != FileKind::Regular) {
        r.error = make_error_code(Errc::unsupported_file_type);
        return r;
    }
    sys::Stat ds;
    std::error_code dec;
    if (sys::lstat(dst, ds, dec)) {
        // Covers dst == src under any spelling: never truncate an existing file.
        r.error = ds.id == st.id ? make_error_code(Errc::same_file) : std::make_error_code(std::errc::file_exists);
        return r;
    }
    fs::path parent = dst.parent_path();
    fs::path tmp = sys::temp_sibling(parent.empty() ? fs::path(".") : parent);
    sys::DataCopyHooks hooks;
    hooks.require_reflink = !allow_fallback;
    uint64_t bytes = 0;
    CopyMethod m = sys::copy_file_data(src, st, tmp, hooks, bytes, r.error);
    if (m == CopyMethod::None) return r;
    if (!sys::rename_noreplace(tmp, dst, r.error)) {
        std::error_code rec;
        sys::remove_nondir(tmp, rec);
        return r;
    }
    r.method = m;
    return r;
}

bool reflink_supported(const fs::path& directory) { return sys::reflink_supported(directory); }

} // namespace bro::vfs
