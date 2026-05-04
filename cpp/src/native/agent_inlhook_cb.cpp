#include "agent_modules.hpp"
#include "duktape.h"
#include <cstdio>
#include <mutex>
#include <unordered_map>

namespace marrow {
namespace {

struct DrainState { uint64_t last_drained{0}; };
static std::mutex g_drain_mu;
static std::unordered_map<int, DrainState> g_drains;
static std::unordered_map<int, DrainState> g_drains_leave;

duk_ret_t js_onNativeDrain(duk_context* c) {
    int hook_id = duk_require_int(c, 0);
    int max_n = duk_get_int_default(c, 1, 16);
    if (max_n <= 0 || max_n > 64) max_n = 16;
    duk_idx_t arr = duk_push_array(c);

    // Get current head
    duk_get_global_string(c, "Marrow");
    duk_get_prop_string(c, -1, "_inlineHookHead");
    duk_push_int(c, hook_id);
    duk_pcall(c, 1);
    if (!duk_is_number(c, -1)) {
        duk_pop_2(c);  // result + Marrow
        return 1;
    }
    uint64_t head = (uint64_t)duk_get_number(c, -1);
    duk_pop(c);  // result

    // Determine drain window
    uint64_t last;
    {
        std::lock_guard<std::mutex> g(g_drain_mu);
        last = g_drains[hook_id].last_drained;
        g_drains[hook_id].last_drained = head;
    }
    if (head <= last) { duk_pop(c); return 1; }  // pop Marrow

    uint64_t start = last;
    if (head - start > (uint64_t)max_n) start = head - (uint64_t)max_n;

    // Pull each snapshot
    duk_get_prop_string(c, -1, "_inlineHookSnap");
    duk_uarridx_t out_i = 0;
    for (uint64_t s = start; s < head; ++s) {
        duk_dup(c, -1);  // dup _inlineHookSnap function
        duk_push_int(c, hook_id);
        duk_push_number(c, (double)s);
        duk_pcall(c, 2);
        if (duk_is_object(c, -1)) {
            duk_put_prop_index(c, arr, out_i++);
        } else {
            duk_pop(c);
        }
    }
    duk_pop_2(c);  // _inlineHookSnap + Marrow
    return 1;
}

// Mirror of js_onNativeDrain for the leave ring. Returns array of
// {rax, ts} for each new leave event since the previous call.
duk_ret_t js_onNativeDrainLeave(duk_context* c) {
    int hook_id = duk_require_int(c, 0);
    int max_n = duk_get_int_default(c, 1, 16);
    if (max_n <= 0 || max_n > 64) max_n = 16;
    duk_idx_t arr = duk_push_array(c);

    duk_get_global_string(c, "Marrow");
    duk_get_prop_string(c, -1, "_inlineHookLeaveHead");
    duk_push_int(c, hook_id);
    duk_pcall(c, 1);
    if (!duk_is_number(c, -1)) { duk_pop_2(c); return 1; }
    uint64_t head = (uint64_t)duk_get_number(c, -1);
    duk_pop(c);

    uint64_t last;
    {
        std::lock_guard<std::mutex> g(g_drain_mu);
        last = g_drains_leave[hook_id].last_drained;
        g_drains_leave[hook_id].last_drained = head;
    }
    if (head <= last) { duk_pop(c); return 1; }

    uint64_t start = last;
    if (head - start > (uint64_t)max_n) start = head - (uint64_t)max_n;

    duk_get_prop_string(c, -1, "_inlineHookLeaveSnap");
    duk_uarridx_t out_i = 0;
    for (uint64_t s = start; s < head; ++s) {
        duk_dup(c, -1);
        duk_push_int(c, hook_id);
        duk_push_number(c, (double)s);
        duk_pcall(c, 2);
        if (duk_is_object(c, -1)) {
            duk_put_prop_index(c, arr, out_i++);
        } else {
            duk_pop(c);
        }
    }
    duk_pop_2(c);
    return 1;
}

} // anon

void register_inlhook_cb_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_onNativeDrain, 2);
    duk_put_prop_string(ctx, ns_idx, "_onNativeDrain");
    duk_push_c_function(ctx, js_onNativeDrainLeave, 2);
    duk_put_prop_string(ctx, ns_idx, "_onNativeDrainLeave");
}

} // namespace marrow
