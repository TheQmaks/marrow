#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>

namespace marrow {
namespace {

duk_ret_t js_readMem(duk_context* c) {
    const char* addr_hex = duk_require_string(c, 0);
    int n = duk_require_int(c, 1);
    if (n <= 0 || n > 4096) { duk_push_null(c); return 1; }
    uint64_t addr = strtoull(addr_hex, nullptr, 0);
    if (!addr) { duk_push_null(c); return 1; }
    auto* vm = current_vm(c);
    if (!vm) { duk_push_null(c); return 1; }

    duk_idx_t arr = duk_push_array(c);
    try {
        auto bytes = vm->reader()->read(addr, (size_t)n);
        for (size_t i = 0; i < bytes.size(); ++i) {
            duk_push_int(c, bytes[i]);
            duk_put_prop_index(c, arr, (duk_uarridx_t)i);
        }
    } catch (...) {}
    return 1;
}

duk_ret_t js_opstackRead(duk_context* c) {
    const char* cookie_str = duk_require_string(c, 0);
    int count = duk_require_int(c, 1);
    if (count <= 0 || count > 256) { duk_push_null(c); return 1; }

    // Retrieve rsp from _lastStack(cookie)[0] via the global stash hook ring
    duk_push_global_object(c);
    duk_get_prop_string(c, -1, "Marrow");
    duk_get_prop_string(c, -1, "_lastStack");
    duk_push_string(c, cookie_str);
    if (duk_pcall(c, 1) != 0 || !duk_is_array(c, -1)) {
        duk_pop_3(c);
        duk_push_null(c);
        return 1;
    }
    // stack[0] is rsp; operand args start at rsp+8
    duk_get_prop_index(c, -1, 0);
    const char* rsp_hex = duk_to_string(c, -1);
    uint64_t rsp = strtoull(rsp_hex, nullptr, 0);
    duk_pop(c);   // rsp string
    duk_pop_3(c); // array, Marrow, global

    if (!rsp) { duk_push_null(c); return 1; }

    auto* vm = current_vm(c);
    if (!vm) { duk_push_null(c); return 1; }

    uint64_t base = rsp + 8;
    size_t byte_count = (size_t)count * 8;
    duk_idx_t arr = duk_push_array(c);
    try {
        auto bytes = vm->reader()->read(base, byte_count);
        for (int i = 0; i < count; ++i) {
            uint64_t qword = 0;
            for (int b = 0; b < 8; ++b)
                qword |= (uint64_t)bytes[(size_t)(i * 8 + b)] << (b * 8);
            char buf[19];
            snprintf(buf, sizeof(buf), "0x%016llx", (unsigned long long)qword);
            duk_push_string(c, buf);
            duk_put_prop_index(c, arr, (duk_uarridx_t)i);
        }
    } catch (...) {}
    return 1;
}

} // anon

void register_opstack_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_readMem, 2);
    duk_put_prop_string(ctx, ns_idx, "_readMem");
    duk_push_c_function(ctx, js_opstackRead, 2);
    duk_put_prop_string(ctx, ns_idx, "_opstackRead");
}

} // namespace marrow
