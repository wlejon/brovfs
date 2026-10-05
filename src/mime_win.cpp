// Windows type database: an extension's "Content Type" through AssocQueryString (which honours
// per-user overrides), and HKCR\MIME\Database\Content Type\<type>\Extension for the reverse.
// The built-in table answers whatever the registry does not.
#include "src/mime_db.h"

#include "brovfs/path.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlwapi.h>

#include <algorithm>

namespace bro::vfs::detail {

namespace {

std::string registry_content_type(std::string_view ext_with_dot) {
    std::wstring ext = wide_from_utf8(ext_with_dot);
    wchar_t buf[256];
    DWORD n = static_cast<DWORD>(std::size(buf));
    HRESULT hr = AssocQueryStringW(ASSOCF_INIT_IGNOREUNKNOWN, ASSOCSTR_CONTENTTYPE, ext.c_str(), nullptr, buf, &n);
    if (FAILED(hr) || n <= 1) return {};
    return utf8_from_wide(std::wstring_view(buf, n - 1));
}

std::string registry_extension_for(std::string_view mime) {
    std::wstring key = L"MIME\\Database\\Content Type\\" + wide_from_utf8(mime);
    wchar_t buf[256];
    DWORD bytes = sizeof(buf);
    LSTATUS st = RegGetValueW(HKEY_CLASSES_ROOT, key.c_str(), L"Extension", RRF_RT_REG_SZ, nullptr, buf, &bytes);
    if (st != ERROR_SUCCESS || bytes < sizeof(wchar_t)) return {};
    std::string ext = utf8_from_wide(std::wstring_view(buf, bytes / sizeof(wchar_t) - 1));
    if (!ext.empty() && ext.front() == '.') ext.erase(0, 1);
    return ascii_lower(ext);
}

class WinDatabase : public TableDatabase {
public:
    WinDatabase() : TableDatabase("Windows registry", nullptr) {}

    std::vector<std::string> types_for_name(std::string_view file_name) const override {
        std::vector<std::string> out;
        size_t dot = file_name.rfind('.');
        if (dot != std::string_view::npos && dot > 0 && dot + 1 < file_name.size()) {
            std::string ct = registry_content_type(file_name.substr(dot));
            if (!ct.empty()) out.push_back(canonical(ct));
        }
        for (auto& m : TableDatabase::types_for_name(file_name)) {
            if (std::find(out.begin(), out.end(), m) == out.end()) out.push_back(std::move(m));
        }
        return out;
    }

    std::vector<std::string> extensions_for_type(std::string_view mime) const override {
        std::vector<std::string> out;
        for (const std::string& spelling : {canonical(mime), ascii_lower(mime)}) {
            std::string ext = registry_extension_for(spelling);
            if (!ext.empty() && std::find(out.begin(), out.end(), ext) == out.end()) out.push_back(ext);
        }
        for (auto& e : TableDatabase::extensions_for_type(mime)) {
            if (std::find(out.begin(), out.end(), e) == out.end()) out.push_back(std::move(e));
        }
        return out;
    }
};

} // namespace

std::unique_ptr<MimeDatabase> make_platform_database() {
    return std::make_unique<WinDatabase>();
}

} // namespace bro::vfs::detail
