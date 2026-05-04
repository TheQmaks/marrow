#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <vector>
#include <string>
#include <cstdio>
#include <cstring>

namespace marrow {
namespace {

struct WinInfo { HWND hwnd; DWORD pid; std::string title; RECT rect; bool visible; };

BOOL CALLBACK enum_proc(HWND hwnd, LPARAM lparam) {
    auto* out = reinterpret_cast<std::vector<WinInfo>*>(lparam);
    DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId()) return TRUE;
    if (!IsWindow(hwnd)) return TRUE;
    char buf[256] = {};
    GetWindowTextA(hwnd, buf, sizeof(buf) - 1);
    RECT r{}; GetWindowRect(hwnd, &r);
    bool visible = IsWindowVisible(hwnd) != 0;
    out->push_back({hwnd, pid, std::string(buf), r, visible});
    return TRUE;
}

void push_win_obj(duk_context* c, const WinInfo& w) {
    duk_idx_t o = duk_push_object(c);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)w.hwnd);
    duk_push_string(c, buf); duk_put_prop_string(c, o, "hwnd");
    duk_push_string(c, w.title.c_str()); duk_put_prop_string(c, o, "title");
    duk_push_int(c, w.rect.left); duk_put_prop_string(c, o, "x");
    duk_push_int(c, w.rect.top); duk_put_prop_string(c, o, "y");
    duk_push_int(c, w.rect.right - w.rect.left); duk_put_prop_string(c, o, "w");
    duk_push_int(c, w.rect.bottom - w.rect.top); duk_put_prop_string(c, o, "h");
    duk_push_boolean(c, w.visible); duk_put_prop_string(c, o, "visible");
}

duk_ret_t js_windows(duk_context* c) {
    std::vector<WinInfo> wins;
    EnumWindows(enum_proc, reinterpret_cast<LPARAM>(&wins));
    duk_idx_t arr = duk_push_array(c);
    duk_uarridx_t i = 0;
    for (auto& w : wins) {
        push_win_obj(c, w);
        duk_put_prop_index(c, arr, i++);
    }
    return 1;
}

bool icontains(const std::string& s, const std::string& sub) {
    if (sub.empty()) return true;
    if (s.size() < sub.size()) return false;
    auto lower = [](char ch) { return char(::tolower((unsigned char)ch)); };
    for (size_t k = 0; k + sub.size() <= s.size(); ++k) {
        bool match = true;
        for (size_t j = 0; j < sub.size(); ++j) {
            if (lower(s[k + j]) != lower(sub[j])) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

duk_ret_t js_findWindow(duk_context* c) {
    const char* needle = duk_require_string(c, 0);
    std::vector<WinInfo> wins;
    EnumWindows(enum_proc, reinterpret_cast<LPARAM>(&wins));
    for (auto& w : wins) {
        if (icontains(w.title, needle)) { push_win_obj(c, w); return 1; }
    }
    duk_push_null(c);
    return 1;
}

duk_ret_t js_activeWindow(duk_context* c) {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) { duk_push_null(c); return 1; }
    DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
    char buf[256] = {}; GetWindowTextA(hwnd, buf, sizeof(buf) - 1);
    RECT r{}; GetWindowRect(hwnd, &r);
    WinInfo w{hwnd, pid, buf, r, IsWindowVisible(hwnd) != 0};
    push_win_obj(c, w);
    duk_push_boolean(c, pid == GetCurrentProcessId());
    duk_put_prop_string(c, -2, "ours");
    return 1;
}

duk_ret_t js_setForeground(duk_context* c) {
    const char* hex = duk_require_string(c, 0);
    HWND hwnd = (HWND)strtoull(hex, nullptr, 0);
    if (!hwnd) { duk_push_false(c); return 1; }
    BOOL ok1 = SetForegroundWindow(hwnd);
    BOOL ok2 = BringWindowToTop(hwnd);
    duk_push_boolean(c, ok1 || ok2);
    return 1;
}

} // anon

void register_window_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_windows, 0);
    duk_put_prop_string(ctx, ns_idx, "windows");
    duk_push_c_function(ctx, js_findWindow, 1);
    duk_put_prop_string(ctx, ns_idx, "findWindow");
    duk_push_c_function(ctx, js_activeWindow, 0);
    duk_put_prop_string(ctx, ns_idx, "activeWindow");
    duk_push_c_function(ctx, js_setForeground, 1);
    duk_put_prop_string(ctx, ns_idx, "setForeground");
}

} // namespace marrow
