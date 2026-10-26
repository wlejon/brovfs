// The helpers bro.vfs's natives use to ask the host's access gate
// (embed/embed_access.h; what each native asks is in api.h, "Access").

#include "host_vfs_internal.h"
#include "brovfs/path.h"
#include "embed/embed_access.h"

namespace brovfs::api {

namespace {

std::string absoluteUtf8(const std::filesystem::path& p) {
    std::error_code ec;
    std::filesystem::path abs = std::filesystem::absolute(p, ec);
    if (ec) abs = p;
    return bro::vfs::path_to_utf8(abs.lexically_normal());
}

} // namespace

bool pathGateActive() {
    return ev::accessGateActive();
}

PathRefusal checkPath(const std::filesystem::path& p, PathAccess access) {
    if (!ev::accessGateActive()) return {};
    PathRefusal r;
    r.path = absoluteUtf8(p);
    r.message = ev::checkAccess(access == PathAccess::Write ? ev::AccessKind::Write : ev::AccessKind::Read, r.path);
    return r;
}

PathRefusal checkPaths(const std::vector<std::filesystem::path>& paths, PathAccess access) {
    if (!ev::accessGateActive()) return {};
    for (const auto& p : paths) {
        PathRefusal r = checkPath(p, access);
        if (r) return r;
    }
    return {};
}

Value newAccessError(const PathRefusal& refusal) {
    return ev::newAccessError(refusal.message, "EACCES", refusal.path);
}

Value throwAccessError(const PathRefusal& refusal) {
    return ev::throwAccessError(refusal.message, "EACCES", refusal.path);
}

uint64_t holdPath(const std::filesystem::path& p, std::function<void(const std::string& refusal)> revoke) {
    if (!ev::accessGateActive()) return 0;
    return ev::holdAccess(ev::AccessKind::Read, absoluteUtf8(p), std::move(revoke));
}

void releaseHeldPath(uint64_t& id) {
    if (id == 0) return;
    ev::releaseAccess(id);
    id = 0;
}

Value newRevokedError(const std::string& refusal, const std::filesystem::path& p) {
    return ev::newAccessError(refusal, "EACCES", absoluteUtf8(p));
}

Value rejectWithAccessError(Value promise, const PathRefusal& refusal) {
    ev::Persistent p(promise);
    ev::Persistent err(ev::newAccessError(refusal.message, "EACCES", refusal.path));
    ev::rejectPromise(p.get(), err.get());
    return p.get();
}

} // namespace brovfs::api
