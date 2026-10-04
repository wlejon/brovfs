#include "brovfs/trash.h"
#include "brovfs/trash_freedesktop.h"

#include <mutex>

namespace bro::vfs {

#ifdef _WIN32
std::shared_ptr<ITrashProvider> create_windows_recycle_bin();
#endif

namespace {

std::mutex g_trash_mutex;
std::shared_ptr<ITrashProvider> g_default_trash_provider;

std::shared_ptr<ITrashProvider> get_or_create_default_provider() {
    std::lock_guard<std::mutex> lock(g_trash_mutex);
    if (!g_default_trash_provider) {
#ifdef _WIN32
        g_default_trash_provider = create_windows_recycle_bin();
#else
        g_default_trash_provider = std::make_shared<FreeDesktopTrash>();
#endif
    }
    return g_default_trash_provider;
}

} // namespace

void set_default_trash_provider(std::shared_ptr<ITrashProvider> provider) {
    std::lock_guard<std::mutex> lock(g_trash_mutex);
    g_default_trash_provider = std::move(provider);
}

std::shared_ptr<ITrashProvider> get_default_trash_provider() {
    return get_or_create_default_provider();
}

bool trash(const std::string& path, std::string* out_id) {
    auto provider = get_or_create_default_provider();
    if (provider) {
        return provider->trash_path(path, out_id);
    }
    return false;
}

std::vector<TrashItem> list_trash() {
    auto provider = get_or_create_default_provider();
    if (provider) {
        return provider->list_trash();
    }
    return {};
}

bool restore_trash(const std::string& id) {
    auto provider = get_or_create_default_provider();
    if (provider) {
        return provider->restore_item(id);
    }
    return false;
}

bool delete_from_trash(const std::string& id) {
    auto provider = get_or_create_default_provider();
    if (provider) {
        return provider->delete_item(id);
    }
    return false;
}

bool empty_trash() {
    auto provider = get_or_create_default_provider();
    if (provider) {
        return provider->empty_trash();
    }
    return false;
}

} // namespace bro::vfs
