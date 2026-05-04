#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <shellapi.h>
#include <cstring>
#include <mutex>

namespace marrow {

namespace {

static NOTIFYICONDATAA g_nid{};
static std::mutex      g_nid_mutex;
static std::once_flag  g_init_flag;
static bool            g_icon_ok = false;

static LRESULT CALLBACK msg_wnd_proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    return DefWindowProcA(h, m, w, l);
}

static void init_tray_icon() {
    // Register a throwaway window class for the message-only window.
    WNDCLASSEXA wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = msg_wnd_proc;
    wc.hInstance     = GetModuleHandleA(nullptr);
    wc.lpszClassName = "marrow-toast-wnd";
    RegisterClassExA(&wc); // ignore failure if already registered

    HWND hwnd = CreateWindowExA(
        0, "marrow-toast-wnd", "marrow-agent",
        0, 0, 0, 0, 0,
        HWND_MESSAGE, nullptr, GetModuleHandleA(nullptr), nullptr);
    if (!hwnd) return;

    g_nid.cbSize           = sizeof(g_nid);
    g_nid.hWnd             = hwnd;
    g_nid.uID              = 1;
    g_nid.uFlags           = NIF_ICON | NIF_TIP;
    g_nid.hIcon            = LoadIconA(nullptr,
                                 reinterpret_cast<LPCSTR>(IDI_INFORMATION));
    strncpy_s(g_nid.szTip, sizeof(g_nid.szTip), "marrow", _TRUNCATE);

    BOOL ok = Shell_NotifyIconA(NIM_ADD, &g_nid);
    if (!ok && GetLastError() == ERROR_TIMEOUT) {
        Sleep(500);
        ok = Shell_NotifyIconA(NIM_ADD, &g_nid);
    }
    g_icon_ok = (ok == TRUE);
}

static duk_ret_t js_toast(duk_context* ctx) {
    const char* title = duk_is_null_or_undefined(ctx, 0)
                        ? ""
                        : duk_safe_to_string(ctx, 0);
    const char* body  = duk_safe_to_string(ctx, 1);

    std::call_once(g_init_flag, init_tray_icon);

    std::lock_guard<std::mutex> lk(g_nid_mutex);
    if (!g_icon_ok) {
        duk_push_false(ctx);
        return 1;
    }

    g_nid.uFlags     = NIF_INFO;
    g_nid.dwInfoFlags = NIIF_INFO;

    strncpy_s(g_nid.szInfoTitle, sizeof(g_nid.szInfoTitle),
              title ? title : "", _TRUNCATE);
    strncpy_s(g_nid.szInfo,      sizeof(g_nid.szInfo),
              body  ? body  : "", _TRUNCATE);

    BOOL ok = Shell_NotifyIconA(NIM_MODIFY, &g_nid);
    if (!ok && GetLastError() == ERROR_TIMEOUT) {
        Sleep(500);
        ok = Shell_NotifyIconA(NIM_MODIFY, &g_nid);
    }

    duk_push_boolean(ctx, ok ? 1 : 0);
    return 1;
}

} // anonymous namespace

void register_toast_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_toast, 2);
    duk_put_prop_string(ctx, ns_idx, "toast");
}

} // namespace marrow
