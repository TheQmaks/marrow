#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace marrow {

struct MouseEntry {
    int button;
    bool was_down{false};
    std::atomic<uint64_t> presses{0};
    std::atomic<uint64_t> drained{0};
};

struct MouseState {
    std::mutex mu;
    std::vector<std::unique_ptr<MouseEntry>> entries;
    std::atomic<bool> thread_running{false};
};

static MouseState g_mouse;

static void mouse_poll_loop() {
    g_mouse.thread_running.store(true);
    while (g_mouse.thread_running.load()) {
        {
            std::lock_guard<std::mutex> g(g_mouse.mu);
            for (auto& e : g_mouse.entries) {
                bool now_down = (GetAsyncKeyState(e->button) & 0x8000) != 0;
                if (now_down && !e->was_down) {
                    e->presses.fetch_add(1, std::memory_order_relaxed);
                }
                e->was_down = now_down;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
}

static duk_ret_t js_registerMouse(duk_context* ctx) {
    int button = duk_require_int(ctx, 0);
    {
        std::lock_guard<std::mutex> g(g_mouse.mu);
        for (auto& e : g_mouse.entries) {
            if (e->button == button) { duk_push_true(ctx); return 1; }
        }
        auto entry = std::make_unique<MouseEntry>();
        entry->button = button;
        g_mouse.entries.push_back(std::move(entry));
    }
    if (!g_mouse.thread_running.load()) {
        std::thread(mouse_poll_loop).detach();
    }
    duk_push_true(ctx);
    return 1;
}

static duk_ret_t js_drainMouse(duk_context* ctx) {
    duk_idx_t arr = duk_push_array(ctx);
    duk_uarridx_t idx = 0;
    std::lock_guard<std::mutex> g(g_mouse.mu);
    for (auto& e : g_mouse.entries) {
        uint64_t total  = e->presses.load(std::memory_order_relaxed);
        uint64_t prev   = e->drained.load(std::memory_order_relaxed);
        uint64_t delta  = total - prev;
        if (delta == 0) continue;
        e->drained.store(total, std::memory_order_relaxed);
        duk_push_object(ctx);
        duk_push_int(ctx, e->button);
        duk_put_prop_string(ctx, -2, "button");
        duk_push_number(ctx, static_cast<double>(delta));
        duk_put_prop_string(ctx, -2, "delta");
        duk_push_number(ctx, static_cast<double>(total));
        duk_put_prop_string(ctx, -2, "total");
        duk_put_prop_index(ctx, arr, idx++);
    }
    return 1;
}

static duk_ret_t js_mousePos(duk_context* ctx) {
    POINT pt{};
    GetCursorPos(&pt);
    duk_push_object(ctx);
    duk_push_int(ctx, pt.x);
    duk_put_prop_string(ctx, -2, "x");
    duk_push_int(ctx, pt.y);
    duk_put_prop_string(ctx, -2, "y");
    return 1;
}

void register_mouse_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);

    duk_push_c_function(ctx, js_registerMouse, 1);
    duk_put_prop_string(ctx, ns_idx, "_registerMouse");

    duk_push_c_function(ctx, js_drainMouse, 0);
    duk_put_prop_string(ctx, ns_idx, "_drainMouse");

    duk_push_c_function(ctx, js_mousePos, 0);
    duk_put_prop_string(ctx, ns_idx, "_mousePos");
}

} // namespace marrow
