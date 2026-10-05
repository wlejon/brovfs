// Windows volume notification: WM_DEVICECHANGE is broadcast to top-level windows (not to
// message-only ones), so the notifier owns a hidden top-level window on its own thread.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "src/volumes_internal.h"

#include <future>
#include <thread>

namespace bro::vfs::detail {

namespace {

constexpr wchar_t kClassName[] = L"brovfs.VolumeNotifier";

class DeviceChangeNotifier final : public VolumeNotifier {
public:
    explicit DeviceChangeNotifier(std::function<void()> trigger) : trigger_(std::move(trigger)) {}

    bool start(std::string& error) {
        std::promise<DWORD> started;
        auto ready = started.get_future();
        thread_ = std::thread([this, &started] { run(started); });
        DWORD err = ready.get();
        if (err != 0) {
            thread_.join();
            error = "hidden window for WM_DEVICECHANGE: error " + std::to_string(err);
            return false;
        }
        return true;
    }

    ~DeviceChangeNotifier() override {
        if (thread_.joinable()) {
            PostMessageW(hwnd_, WM_CLOSE, 0, 0);
            thread_.join();
        }
    }

private:
    static LRESULT CALLBACK proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        if (msg == WM_NCCREATE) {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        }
        auto* self = reinterpret_cast<DeviceChangeNotifier*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        switch (msg) {
            case WM_DEVICECHANGE:
                // DBT_DEVICEARRIVAL / DBT_DEVICEREMOVECOMPLETE for volumes, DBT_DEVNODES_CHANGED
                // for hardware: any of them may change the drive set.
                if (self) self->trigger_();
                return TRUE;
            case WM_CLOSE: DestroyWindow(hwnd); return 0;
            case WM_DESTROY: PostQuitMessage(0); return 0;
            default: break;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }

    void run(std::promise<DWORD>& started) {
        HINSTANCE inst = GetModuleHandleW(nullptr);
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = &DeviceChangeNotifier::proc;
        wc.hInstance = inst;
        wc.lpszClassName = kClassName;
        if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            started.set_value(GetLastError());
            return;
        }
        // Top-level (no parent, never shown): broadcasts reach it, the user never sees it.
        hwnd_ = CreateWindowExW(WS_EX_TOOLWINDOW, kClassName, L"", WS_POPUP, 0, 0, 0, 0, nullptr, nullptr, inst, this);
        if (!hwnd_) {
            started.set_value(GetLastError() ? GetLastError() : 1);
            return;
        }
        started.set_value(0);
        MSG m;
        while (GetMessageW(&m, nullptr, 0, 0) > 0) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }

    std::function<void()> trigger_;
    HWND hwnd_ = nullptr;
    std::thread thread_;
};

} // namespace

std::unique_ptr<VolumeNotifier> start_volume_notifier(std::function<void()> trigger, std::string& error) {
    auto n = std::make_unique<DeviceChangeNotifier>(std::move(trigger));
    if (!n->start(error)) return nullptr;
    return n;
}

} // namespace bro::vfs::detail

#endif // _WIN32
