// The process-wide path gate (api.h, "Path gate") and the helpers bro.vfs's
// natives use to ask it.
//
// The gate is set before realms run, but every realm's thread reads it, and a
// host that revokes a grant (or a test) may replace it while they do. So it
// lives behind a shared_ptr swapped under a mutex: a check copies the pointer
// under the lock and calls the gate outside it, so a gate that blocks to ask the
// user holds no lock, and a replaced gate stays alive until the calls already in
// it return. The flag spares the common case, no gate at all, the lock.

#include "host_vfs_internal.h"
#include "brovfs/path.h"

#include <atomic>
#include <mutex>

namespace brovfs::api {

namespace {

std::mutex g_gate_mu;
std::shared_ptr<const PathGate> g_gate;
std::atomic<bool> g_gate_active{false};

std::shared_ptr<const PathGate> currentGate() {
    if (!g_gate_active.load(std::memory_order_acquire)) return nullptr;
    std::lock_guard lock(g_gate_mu);
    return g_gate;
}

std::string absoluteUtf8(const std::filesystem::path& p) {
    std::error_code ec;
    std::filesystem::path abs = std::filesystem::absolute(p, ec);
    if (ec) abs = p;
    return bro::vfs::path_to_utf8(abs.lexically_normal());
}

} // namespace

void setPathGate(PathGate gate) {
    const bool any = static_cast<bool>(gate);
    auto next = any ? std::make_shared<const PathGate>(std::move(gate)) : nullptr;
    std::lock_guard lock(g_gate_mu);
    g_gate = std::move(next);
    g_gate_active.store(any, std::memory_order_release);
}

bool pathGateActive() {
    return g_gate_active.load(std::memory_order_acquire);
}

PathRefusal checkPath(const std::filesystem::path& p, PathAccess access) {
    auto gate = currentGate();
    if (!gate) return {};
    PathRefusal r;
    r.path = absoluteUtf8(p);
    r.message = (*gate)(r.path, access);
    return r;
}

PathRefusal checkPaths(const std::vector<std::filesystem::path>& paths, PathAccess access) {
    if (!pathGateActive()) return {};
    for (const auto& p : paths) {
        PathRefusal r = checkPath(p, access);
        if (r) return r;
    }
    return {};
}

Value newAccessError(const PathRefusal& refusal) {
    ev::Persistent err(makeError(refusal.message));
    if (ev::isObject(err.get())) {
        // Each value is made in a statement of its own: built inside the call,
        // it could move the receiver after err.get() was read.
        ev::Persistent code(ev::fromUtf8("EACCES"));
        err.set(ev::setProperty(err.get(), "code", code.get()));
        ev::Persistent path(ev::fromUtf8(refusal.path));
        err.set(ev::setProperty(err.get(), "path", path.get()));
    }
    return err.get();
}

Value throwAccessError(const PathRefusal& refusal) {
    return ev::throwValue(newAccessError(refusal));
}

Value rejectWithAccessError(Value promise, const PathRefusal& refusal) {
    ev::Persistent p(promise);
    ev::Persistent err(newAccessError(refusal));
    ev::rejectPromise(p.get(), err.get());
    return p.get();
}

} // namespace brovfs::api
