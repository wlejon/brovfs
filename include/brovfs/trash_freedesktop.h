#pragma once

#include "brovfs/trash.h"
#include <string>

namespace bro::vfs {

// FreeDesktop.org Trash Specification implementation
// Standard layout:
//   $XDG_DATA_HOME/Trash/files/
//   $XDG_DATA_HOME/Trash/info/<name>.trashinfo
class FreeDesktopTrash : public ITrashProvider {
public:
    // If trash_dir is empty, defaults to $XDG_DATA_HOME/Trash or ~/.local/share/Trash
    explicit FreeDesktopTrash(std::string trash_dir = "");

    bool trash_path(const std::string& path, std::string* out_id = nullptr) override;
    [[nodiscard]] std::vector<TrashItem> list_trash() override;
    bool restore_item(const std::string& id) override;
    bool delete_item(const std::string& id) override;
    bool empty_trash() override;

    [[nodiscard]] const std::string& get_trash_dir() const noexcept { return trash_dir_; }
    [[nodiscard]] std::string get_files_dir() const;
    [[nodiscard]] std::string get_info_dir() const;

private:
    std::string trash_dir_;

    void ensure_directories_exist();
    std::string allocate_trash_id(const std::string& original_filename);
};

} // namespace bro::vfs
