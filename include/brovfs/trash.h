#pragma once

#include "brovfs/types.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace bro::vfs {

struct TrashItem {
    std::string id;               // Unique filename identifier in trash
    std::string original_path;    // Absolute path of the file before trashing
    std::string current_path;     // Path inside the trash store
    int64_t deletion_time_ms = 0; // Unix epoch ms
    uint64_t size = 0;            // File or directory size
    bool is_directory = false;
};

class ITrashProvider {
public:
    virtual ~ITrashProvider() = default;

    virtual bool trash_path(const std::string& path, std::string* out_id = nullptr) = 0;
    [[nodiscard]] virtual std::vector<TrashItem> list_trash() = 0;
    virtual bool restore_item(const std::string& id) = 0;
    virtual bool delete_item(const std::string& id) = 0;
    virtual bool empty_trash() = 0;
};

// Global default provider access and configuration
void set_default_trash_provider(std::shared_ptr<ITrashProvider> provider);
[[nodiscard]] std::shared_ptr<ITrashProvider> get_default_trash_provider();

// High-level convenience functions using default trash provider
bool trash(const std::string& path, std::string* out_id = nullptr);
[[nodiscard]] std::vector<TrashItem> list_trash();
bool restore_trash(const std::string& id);
bool delete_from_trash(const std::string& id);
bool empty_trash();

} // namespace bro::vfs
