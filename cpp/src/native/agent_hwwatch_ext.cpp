#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>

namespace marrow {

// Forward decls — these live in agent_watch.cpp
extern uint32_t agent_watch_addr(VMMeta* vm, uint64_t addr, int length, int slot);
extern bool     agent_unwatch(VMMeta* vm, uint32_t cookie);

namespace {

duk_ret_t js_watchAll(duk_context* c) {
    auto* vm = current_vm(c);
    duk_idx_t arr = duk_push_array(c);
    if (!vm || !duk_is_array(c, 0)) return 1;
    duk_size_t n = duk_get_length(c, 0);
    if (n > 4) n = 4;
    for (duk_size_t i = 0; i < n; ++i) {
        duk_get_prop_index(c, 0, (duk_uarridx_t)i);
        if (!duk_is_object(c, -1)) {
            duk_pop(c);
            duk_push_int(c, -1);
            duk_put_prop_index(c, arr, (duk_uarridx_t)i);
            continue;
        }
        duk_get_prop_string(c, -1, "addr");
        const char* hex = duk_get_string_default(c, -1, "0x0");
        uint64_t addr = strtoull(hex, nullptr, 0);
        duk_pop(c);
        duk_get_prop_string(c, -1, "length");
        int len = duk_get_int_default(c, -1, 4);
        duk_pop(c);
        duk_pop(c);  // entry obj

        uint32_t cookie = agent_watch_addr(vm, addr, len, (int)i);
        duk_push_uint(c, cookie);
        duk_put_prop_index(c, arr, (duk_uarridx_t)i);
    }
    return 1;
}

duk_ret_t js_unwatchAll(duk_context* c) {
    auto* vm = current_vm(c);
    duk_idx_t result = duk_push_array(c);
    if (!vm || !duk_is_array(c, 0)) return 1;
    duk_size_t n = duk_get_length(c, 0);
    for (duk_size_t i = 0; i < n; ++i) {
        duk_get_prop_index(c, 0, (duk_uarridx_t)i);
        uint32_t cookie = (uint32_t)duk_get_uint_default(c, -1, 0);
        duk_pop(c);
        bool ok = agent_unwatch(vm, cookie);
        duk_push_boolean(c, ok);
        duk_put_prop_index(c, result, (duk_uarridx_t)i);
    }
    return 1;
}

} // anon

void register_hwwatch_ext_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_watchAll, 1);
    duk_put_prop_string(ctx, ns_idx, "_watchAll");
    duk_push_c_function(ctx, js_unwatchAll, 1);
    duk_put_prop_string(ctx, ns_idx, "_unwatchAll");
}

} // namespace marrow
