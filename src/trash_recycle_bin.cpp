// Windows Recycle Bin.
//  * trash(): IFileOperation with FOFX_RECYCLEONDELETE on a private STA thread. A progress
//    sink vetoes any item the shell would delete permanently (PreDeleteItem without
//    TSF_DELETE_RECYCLE_IF_POSSIBLE: too large, no bin on the volume, ...), and network /
//    UNC paths are refused up front, so trash() never turns into a permanent delete.
//  * list/restore/erase read <volume>\$Recycle.Bin\<user SID>\$I* records (v1 and v2) and
//    act on the matching $R payload directly. Restore is a no-replace rename back to the
//    original path; ids are validated to be $R entries of this user's bins.
#ifdef _WIN32

#include "brovfs/trash.h"

#include "src/engine.h"
#include "src/win_util.h"

#include <objbase.h>
#include <sddl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>

#include <cstring>
#include <fstream>
#include <thread>

namespace bro::vfs {

namespace {

using namespace win;

std::wstring user_sid() {
    static const std::wstring sid = [] {
        std::wstring out;
        HANDLE tok = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return out;
        DWORD len = 0;
        GetTokenInformation(tok, TokenUser, nullptr, 0, &len);
        std::vector<unsigned char> buf(len);
        if (len && GetTokenInformation(tok, TokenUser, buf.data(), len, &len)) {
            LPWSTR s = nullptr;
            if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &s)) {
                out = s;
                LocalFree(s);
            }
        }
        CloseHandle(tok);
        return out;
    }();
    return sid;
}

fs::path bin_dir(wchar_t drive) {
    return fs::path(std::wstring(1, static_cast<wchar_t>(towupper(drive))) + L":\\$Recycle.Bin\\" + user_sid());
}

// One spelling per item, whatever case the shell reported ($RECYCLE.BIN vs $Recycle.Bin).
std::string canonical_id(const fs::path& stored) {
    return utf8_from_wide((bin_dir(stored.native()[0]) / stored.filename()).native());
}

bool iequals(const std::wstring& a, const std::wstring& b) {
    return CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(), static_cast<int>(b.size()), TRUE) ==
           CSTR_EQUAL;
}

struct InfoRecord {
    std::wstring original;
    uint64_t size = 0;
    int64_t deleted_ft = 0;
};

bool read_info(const fs::path& file, InfoRecord& rec, std::error_code& ec) {
    Handle h(CreateFileW(win_extended_path(file).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                         OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!h.ok()) {
        ec = last_error();
        return false;
    }
    std::vector<unsigned char> buf(64 * 1024 + 64);
    DWORD got = 0;
    if (!ReadFile(h.get(), buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr)) {
        ec = last_error();
        return false;
    }
    buf.resize(got);
    auto rd64 = [&](size_t off) {
        uint64_t v = 0;
        std::memcpy(&v, buf.data() + off, 8);
        return v;
    };
    if (buf.size() < 24) {
        ec = make_error_code(Errc::trash_info_invalid);
        return false;
    }
    uint64_t version = rd64(0);
    rec.size = rd64(8);
    rec.deleted_ft = static_cast<int64_t>(rd64(16));
    const wchar_t* name = nullptr;
    size_t chars = 0;
    if (version == 1 && buf.size() >= 24 + 520) {
        name = reinterpret_cast<const wchar_t*>(buf.data() + 24);
        chars = 260;
    } else if (version == 2 && buf.size() >= 28) {
        uint32_t n = 0;
        std::memcpy(&n, buf.data() + 24, 4);
        if (buf.size() < 28 + static_cast<size_t>(n) * 2) {
            ec = make_error_code(Errc::trash_info_invalid);
            return false;
        }
        name = reinterpret_cast<const wchar_t*>(buf.data() + 28);
        chars = n;
    } else {
        ec = make_error_code(Errc::trash_info_invalid);
        return false;
    }
    rec.original.assign(name, chars);
    while (!rec.original.empty() && rec.original.back() == L'\0') rec.original.pop_back();
    if (rec.original.empty()) {
        ec = make_error_code(Errc::trash_info_invalid);
        return false;
    }
    return true;
}

class DeleteSink final : public IFileOperationProgressSink {
public:
    bool would_nuke = false;
    HRESULT delete_hr = S_OK;
    bool post_called = false;
    std::wstring recycled_path;

    // IUnknown (stack object: reference counting is a formality)
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == __uuidof(IFileOperationProgressSink)) {
            *ppv = static_cast<IFileOperationProgressSink*>(this);
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return 2; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }

    HRESULT STDMETHODCALLTYPE PreDeleteItem(DWORD flags, IShellItem*) override {
        if (!(flags & TSF_DELETE_RECYCLE_IF_POSSIBLE)) {
            would_nuke = true;
            return E_ABORT; // cancels this and every pending operation
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PostDeleteItem(DWORD, IShellItem*, HRESULT hr, IShellItem* created) override {
        post_called = true;
        delete_hr = hr;
        if (created) {
            LPWSTR p = nullptr;
            if (SUCCEEDED(created->GetDisplayName(SIGDN_FILESYSPATH, &p)) && p) {
                recycled_path = p;
                CoTaskMemFree(p);
            }
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE StartOperations() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE FinishOperations(HRESULT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE PreRenameItem(DWORD, IShellItem*, LPCWSTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE PostRenameItem(DWORD, IShellItem*, LPCWSTR, HRESULT, IShellItem*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE PreMoveItem(DWORD, IShellItem*, IShellItem*, LPCWSTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE PostMoveItem(DWORD, IShellItem*, IShellItem*, LPCWSTR, HRESULT, IShellItem*) override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PreCopyItem(DWORD, IShellItem*, IShellItem*, LPCWSTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE PostCopyItem(DWORD, IShellItem*, IShellItem*, LPCWSTR, HRESULT, IShellItem*) override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE PreNewItem(DWORD, IShellItem*, LPCWSTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE PostNewItem(DWORD, IShellItem*, LPCWSTR, LPCWSTR, DWORD, HRESULT, IShellItem*) override {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE UpdateProgress(UINT, UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ResetTimer() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE PauseTimer() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ResumeTimer() override { return S_OK; }
};

struct ShellResult {
    HRESULT hr = S_OK;
    BOOL aborted = FALSE;
    DeleteSink sink;
};

// Runs the shell delete on a dedicated STA thread so the caller's COM apartment is untouched.
void shell_recycle(const std::wstring& path, ShellResult& out) {
    std::thread t([&] {
        HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        IFileOperation* op = nullptr;
        IShellItem* item = nullptr;
        out.hr = CoCreateInstance(__uuidof(FileOperation), nullptr, CLSCTX_ALL, IID_PPV_ARGS(&op));
        if (SUCCEEDED(out.hr)) {
            out.hr = op->SetOperationFlags(FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT | FOF_ALLOWUNDO |
                                           FOFX_RECYCLEONDELETE | FOFX_EARLYFAILURE);
        }
        if (SUCCEEDED(out.hr)) out.hr = SHCreateItemFromParsingName(path.c_str(), nullptr, IID_PPV_ARGS(&item));
        if (SUCCEEDED(out.hr)) out.hr = op->DeleteItem(item, &out.sink);
        if (SUCCEEDED(out.hr)) out.hr = op->PerformOperations();
        if (op) op->GetAnyOperationsAborted(&out.aborted);
        if (item) item->Release();
        if (op) op->Release();
        if (SUCCEEDED(init)) CoUninitialize();
    });
    t.join();
}

class RecycleBin final : public Trash {
public:
    bool trash(const fs::path& in, std::string* out_id, std::error_code& ec) override {
        std::error_code aec;
        fs::path p = strip_trailing_separators(fs::absolute(in, aec).lexically_normal());
        if (aec || leaf_name(p).empty()) {
            ec = make_error_code(Errc::invalid_argument);
            return false;
        }
        sys::Stat st;
        if (!sys::lstat(p, st, ec)) return false;
        const std::wstring& w = p.native();
        if (w.size() < 3 || w[1] != L':') { // UNC / device paths: no Recycle Bin
            ec = make_error_code(Errc::no_trash_available);
            return false;
        }
        std::wstring root = w.substr(0, 2) + L"\\";
        UINT type = GetDriveTypeW(root.c_str());
        if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) {
            ec = make_error_code(Errc::no_trash_available);
            return false;
        }
        ShellResult r;
        shell_recycle(w, r);
        sys::Stat after;
        std::error_code aec2;
        bool still_there = sys::lstat(p, after, aec2) && after.id == st.id;
        if (r.sink.would_nuke) {
            ec = make_error_code(Errc::no_trash_available);
            return false;
        }
        if (FAILED(r.hr) || (r.sink.post_called && FAILED(r.sink.delete_hr)) || r.aborted || still_there) {
            ec = FAILED(r.sink.delete_hr) ? hresult_error(r.sink.delete_hr)
                 : FAILED(r.hr)          ? hresult_error(r.hr)
                                         : make_error_code(Errc::cancelled);
            return false;
        }
        std::wstring recycled = r.sink.recycled_path;
        if (recycled.empty()) recycled = find_recycled(p, ec);
        if (recycled.empty()) {
            // The item left its place but the bin record could not be identified.
            if (!ec) ec = make_error_code(Errc::trash_info_invalid);
            return false;
        }
        if (out_id) *out_id = canonical_id(fs::path(recycled));
        return true;
    }

    std::vector<TrashItem> list(std::vector<ItemError>* errors) override {
        std::vector<TrashItem> items;
        DWORD drives = GetLogicalDrives();
        for (int i = 0; i < 26; ++i) {
            if (!(drives & (1u << i))) continue;
            wchar_t letter = static_cast<wchar_t>(L'A' + i);
            std::wstring root = std::wstring(1, letter) + L":\\";
            UINT type = GetDriveTypeW(root.c_str());
            if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) continue;
            fs::path bin = bin_dir(letter);
            std::error_code ec;
            bool ok = sys::list_dir(bin, [&](sys::RawEntry&& e) {
                const std::wstring& n = e.name.native();
                if (n.size() < 3 || !(n[0] == L'$' && (n[1] == L'I' || n[1] == L'i'))) return true;
                TrashItem item;
                std::error_code iec;
                if (fill_item(bin, bin / (L"$R" + n.substr(2)), item, iec)) {
                    items.push_back(std::move(item));
                } else if (errors && !sys::is_not_found(iec)) {
                    errors->push_back({bin / e.name, {}, iec, "read recycle record"});
                }
                return true;
            }, ec);
            if (!ok && errors && !sys::is_not_found(ec)) errors->push_back({bin, {}, ec, "list recycle bin"});
        }
        return items;
    }

    bool restore(const std::string& id, RestoreConflict on_conflict, fs::path* restored_to,
                 std::error_code& ec) override {
        fs::path stored, info;
        if (!validate(id, stored, info, ec)) return false;
        TrashItem item;
        if (!fill_item(stored.parent_path(), stored, item, ec)) return false;
        fs::path target = item.original_path;
        if (sys::exists_nofollow(target)) {
            if (on_conflict == RestoreConflict::Fail) {
                ec = make_error_code(Errc::restore_target_exists);
                return false;
            }
            target = detail::unique_sibling(target, item.is_directory);
        }
        if (!sys::make_dirs(target.parent_path(), ec)) return false;
        if (!sys::rename_noreplace(stored, target, ec)) {
            if (sys::is_exists_error(ec)) {
                ec = make_error_code(Errc::restore_target_exists);
                return false;
            }
            if (!sys::is_cross_device(ec)) return false; // original was under a mounted folder
            ec.clear();
            FileOpOptions opt;
            detail::Progress prog(nullptr, nullptr);
            OpResult r = detail::run_transfer(detail::TransferMode::Move, {{stored, target}}, opt, prog);
            if (!r.ok()) {
                ec = r.errors.empty() ? make_error_code(Errc::cancelled) : r.errors.front().code;
                return false;
            }
        }
        std::error_code iec;
        sys::remove_nondir(info, iec);
        notify(stored.parent_path(), target);
        if (restored_to) *restored_to = target;
        return true;
    }

    bool erase(const std::string& id, std::error_code& ec) override {
        fs::path stored, info;
        if (!validate(id, stored, info, ec)) return false;
        if (sys::exists_nofollow(stored)) {
            detail::Progress prog(nullptr, nullptr);
            OpResult r = detail::run_remove({stored}, prog);
            if (!r.ok()) {
                ec = r.errors.empty() ? make_error_code(Errc::cancelled) : r.errors.front().code;
                return false;
            }
        }
        if (!sys::remove_nondir(info, ec)) return false;
        notify(stored.parent_path(), fs::path());
        return true;
    }

    OpResult empty() override {
        OpResult r;
        for (const auto& item : list(&r.errors)) {
            std::error_code ec;
            if (erase(item.id, ec)) {
                ++r.files_done;
            } else {
                r.errors.push_back({item.stored_path, {}, ec, "erase"});
            }
        }
        detail::finish_result(r, false);
        return r;
    }

private:
    static void notify(const fs::path& bin, const fs::path& restored) {
        SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, bin.c_str(), nullptr);
        if (!restored.empty()) {
            SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATHW | SHCNF_FLUSHNOWAIT, restored.parent_path().c_str(), nullptr);
        }
    }

    // An id is the full path of a $R entry directly inside this user's bin on its volume.
    static bool validate(const std::string& id, fs::path& stored, fs::path& info, std::error_code& ec) {
        stored = path_from_utf8(id);
        const std::wstring& w = stored.native();
        bool ok = w.size() > 3 && w[1] == L':' && stored == stored.lexically_normal();
        if (ok) {
            std::wstring leaf = stored.filename().native();
            ok = leaf.size() > 2 && leaf[0] == L'$' && (leaf[1] == L'R' || leaf[1] == L'r') &&
                 iequals(stored.parent_path().native(), bin_dir(w[0]).native());
            if (ok) info = stored.parent_path() / (L"$I" + leaf.substr(2));
        }
        if (!ok) ec = make_error_code(Errc::invalid_trash_id);
        return ok;
    }

    static bool fill_item(const fs::path& bin, const fs::path& stored, TrashItem& item, std::error_code& ec) {
        fs::path info = bin / (L"$I" + stored.filename().native().substr(2));
        InfoRecord rec;
        if (!read_info(info, rec, ec)) return false;
        sys::Stat st;
        if (!sys::lstat(stored, st, ec)) return false;
        item.id = canonical_id(stored);
        item.original_path = fs::path(rec.original);
        item.stored_path = stored;
        item.name = utf8_from_wide(leaf_name(item.original_path).native());
        item.deletion_time_ms = filetime_to_unix_ns(rec.deleted_ft) / 1000000;
        item.size = rec.size;
        item.is_directory = st.kind == FileKind::Directory;
        return true;
    }

    // Fallback when the shell did not hand back the new item: newest record for this path.
    std::wstring find_recycled(const fs::path& original, std::error_code& ec) {
        fs::path bin = bin_dir(original.native()[0]);
        std::wstring best;
        int64_t best_time = -1;
        sys::list_dir(bin, [&](sys::RawEntry&& e) {
            const std::wstring& n = e.name.native();
            if (n.size() < 3 || n[0] != L'$' || (n[1] != L'I' && n[1] != L'i')) return true;
            InfoRecord rec;
            std::error_code iec;
            if (read_info(bin / e.name, rec, iec) && iequals(rec.original, original.native()) &&
                rec.deleted_ft > best_time) {
                best_time = rec.deleted_ft;
                best = (bin / (L"$R" + n.substr(2))).native();
            }
            return true;
        }, ec);
        return best;
    }
};

} // namespace

std::shared_ptr<Trash> make_recycle_bin() { return std::make_shared<RecycleBin>(); }

} // namespace bro::vfs

#endif // _WIN32
