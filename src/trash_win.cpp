#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>

#include "brovfs/trash.h"
#include "brovfs/types.h"
#include <filesystem>
#include <string>
#include <vector>

namespace bro::vfs {

namespace fs = std::filesystem;

namespace {

std::wstring to_wide_double_null(const std::string& path) {
    fs::path p(path);
    std::wstring w = p.lexically_normal().wstring();
    // Replace forward slashes with Windows backslashes
    for (auto& c : w) {
        if (c == L'/') c = L'\\';
    }
    w.push_back(L'\0'); // Double null terminate
    return w;
}

} // namespace

class WindowsRecycleBin : public ITrashProvider {
public:
    bool trash_path(const std::string& path, std::string* out_id) override {
        fs::path p(path);
        std::error_code ec;
        if (!fs::exists(p, ec)) {
            return false;
        }

        std::wstring wpath = to_wide_double_null(fs::absolute(p, ec).string());

        SHFILEOPSTRUCTW file_op{};
        file_op.wFunc = FO_DELETE;
        file_op.pFrom = wpath.c_str();
        file_op.pTo = nullptr;
        file_op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;

        int ret = SHFileOperationW(&file_op);
        if (ret == 0 && !file_op.fAnyOperationsAborted) {
            if (out_id) {
                *out_id = p.filename().string();
            }
            return true;
        }
        return false;
    }

    std::vector<TrashItem> list_trash() override {
        // Windows Recycle Bin item enumeration is typically done via COM IShellFolder2.
        // For a lightweight portable engine without COM apartment requirements,
        // we return an empty list or documented empty state.
        return {};
    }

    bool restore_item(const std::string& id) override {
        (void)id;
        return false;
    }

    bool delete_item(const std::string& id) override {
        (void)id;
        return false;
    }

    bool empty_trash() override {
        HRESULT hr = SHEmptyRecycleBinW(nullptr, nullptr, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);
        return SUCCEEDED(hr);
    }
};

std::shared_ptr<ITrashProvider> create_windows_recycle_bin() {
    return std::make_shared<WindowsRecycleBin>();
}

} // namespace bro::vfs

#endif // _WIN32
