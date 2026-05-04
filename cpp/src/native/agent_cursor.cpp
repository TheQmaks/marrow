#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <chrono>
#include <thread>

namespace marrow {
namespace {

void send_click(int button) {
    DWORD down, up;
    switch (button) {
        case 1: down = MOUSEEVENTF_LEFTDOWN;   up = MOUSEEVENTF_LEFTUP;   break;
        case 2: down = MOUSEEVENTF_RIGHTDOWN;  up = MOUSEEVENTF_RIGHTUP;  break;
        case 4: down = MOUSEEVENTF_MIDDLEDOWN; up = MOUSEEVENTF_MIDDLEUP; break;
        default: return;
    }
    INPUT in[2] = {};
    in[0].type = INPUT_MOUSE; in[0].mi.dwFlags = down;
    in[1].type = INPUT_MOUSE; in[1].mi.dwFlags = up;
    SendInput(2, in, sizeof(INPUT));
}

duk_ret_t js_setCursor(duk_context* ctx) {
    int x = duk_require_int(ctx, 0);
    int y = duk_require_int(ctx, 1);
    duk_push_boolean(ctx, SetCursorPos(x, y));
    return 1;
}

duk_ret_t js_click(duk_context* ctx) {
    int btn = duk_require_int(ctx, 0);
    send_click(btn);
    duk_push_true(ctx);
    return 1;
}

duk_ret_t js_clickAt(duk_context* ctx) {
    int x   = duk_require_int(ctx, 0);
    int y   = duk_require_int(ctx, 1);
    int btn = duk_require_int(ctx, 2);
    SetCursorPos(x, y);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    send_click(btn);
    duk_push_true(ctx);
    return 1;
}

duk_ret_t js_scroll(duk_context* ctx) {
    int amount = duk_require_int(ctx, 0);
    INPUT in = {};
    in.type = INPUT_MOUSE;
    in.mi.dwFlags    = MOUSEEVENTF_WHEEL;
    in.mi.mouseData  = static_cast<DWORD>(amount);
    SendInput(1, &in, sizeof(INPUT));
    duk_push_true(ctx);
    return 1;
}

duk_ret_t js_drag(duk_context* ctx) {
    int fx  = duk_require_int(ctx, 0);
    int fy  = duk_require_int(ctx, 1);
    int tx  = duk_require_int(ctx, 2);
    int ty  = duk_require_int(ctx, 3);
    int btn = duk_require_int(ctx, 4);

    DWORD down, up;
    switch (btn) {
        case 1: down = MOUSEEVENTF_LEFTDOWN;   up = MOUSEEVENTF_LEFTUP;   break;
        case 2: down = MOUSEEVENTF_RIGHTDOWN;  up = MOUSEEVENTF_RIGHTUP;  break;
        case 4: down = MOUSEEVENTF_MIDDLEDOWN; up = MOUSEEVENTF_MIDDLEUP; break;
        default: duk_push_false(ctx); return 1;
    }

    SetCursorPos(fx, fy);

    INPUT in = {};
    in.type = INPUT_MOUSE;
    in.mi.dwFlags = down;
    SendInput(1, &in, sizeof(INPUT));

    constexpr int steps = 30;
    for (int i = 1; i <= steps; ++i) {
        int cx = fx + (tx - fx) * i / steps;
        int cy = fy + (ty - fy) * i / steps;
        SetCursorPos(cx, cy);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    in.mi.dwFlags = up;
    SendInput(1, &in, sizeof(INPUT));

    duk_push_true(ctx);
    return 1;
}

} // namespace

void register_cursor_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_setCursor, 2); duk_put_prop_string(ctx, ns_idx, "setCursor");
    duk_push_c_function(ctx, js_click,     1); duk_put_prop_string(ctx, ns_idx, "click");
    duk_push_c_function(ctx, js_clickAt,   3); duk_put_prop_string(ctx, ns_idx, "clickAt");
    duk_push_c_function(ctx, js_scroll,    1); duk_put_prop_string(ctx, ns_idx, "scroll");
    duk_push_c_function(ctx, js_drag,      5); duk_put_prop_string(ctx, ns_idx, "drag");
}

} // namespace marrow
