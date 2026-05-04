#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>

namespace marrow {
namespace {

bool looks_like_method(VMMeta* vm, uint64_t maybe) {
    if (maybe < 0x10000 || (maybe & 7)) return false;
    auto* mt = vm->type("Method");
    if (!mt) return false;
    auto* cm_field = mt->field("_constMethod");
    if (!cm_field) return false;
    try {
        uint64_t cm = vm->reader()->read_u64(maybe + cm_field->offset);
        return cm != 0 && (cm & 7) == 0;
    } catch (...) { return false; }
}

duk_ret_t js_backtrace(duk_context* c) {
    uint64_t cookie = duk_require_uint(c, 0);
    int max_frames = duk_get_int_default(c, 1, 16);
    if (max_frames > 64) max_frames = 64;
    auto* vm = current_vm(c);
    duk_idx_t arr = duk_push_array(c);
    if (!vm) return 1;

    // Get RBP from _lastRegs(cookie)
    duk_get_global_string(c, "Marrow");
    duk_get_prop_string(c, -1, "_lastRegs");
    duk_push_uint(c, (duk_uint_t)cookie);
    if (duk_pcall(c, 1) != 0) {
        duk_pop_2(c);  // err + Marrow
        return 1;
    }
    if (!duk_is_array(c, -1)) { duk_pop_2(c); return 1; }
    duk_get_prop_index(c, -1, 5);  // regs[5] = rbp
    const char* rbp_hex = duk_get_string_default(c, -1, "0x0");
    uint64_t rbp = strtoull(rbp_hex, nullptr, 0);
    duk_pop(c);  // rbp string
    duk_pop_2(c);  // regs array + Marrow
    if (!rbp) return 1;

    // Walk frames
    duk_uarridx_t i = 0;
    for (int n = 0; n < max_frames && rbp; ++n) {
        uint64_t prev_rbp = 0, ret_pc = 0, maybe_method = 0;
        try {
            prev_rbp     = vm->reader()->read_u64(rbp + 0);
            ret_pc       = vm->reader()->read_u64(rbp + 8);
            maybe_method = vm->reader()->read_u64(rbp - 24);
        } catch (...) { break; }

        const char* kind = looks_like_method(vm, maybe_method) ? "interp" : "compiled-or-native";

        duk_idx_t o = duk_push_object(c);
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)rbp);
        duk_push_string(c, buf); duk_put_prop_string(c, o, "rbp");
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ret_pc);
        duk_push_string(c, buf); duk_put_prop_string(c, o, "retPc");
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)maybe_method);
        duk_push_string(c, buf); duk_put_prop_string(c, o, "methodPtr");
        duk_push_string(c, kind); duk_put_prop_string(c, o, "kind");
        duk_put_prop_index(c, arr, i++);

        if (prev_rbp <= rbp || prev_rbp - rbp > (1 << 20)) break;
        rbp = prev_rbp;
    }
    return 1;
}

} // anon

void register_backtrace_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_backtrace, 2);
    duk_put_prop_string(ctx, ns_idx, "_backtrace");
}

} // namespace marrow
