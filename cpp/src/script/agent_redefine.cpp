#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace marrow {
namespace {

duk_ret_t js_redefine(duk_context* c) {
    uint64_t method = duk_require_uint(c, 0);
    uint64_t method_hi = duk_require_uint(c, 1);
    method |= (method_hi << 32);
    if (!duk_is_array(c, 2)) { duk_push_false(c); return 1; }
    duk_size_t bclen = duk_get_length(c, 2);
    auto* vm = current_vm(c);
    if (!vm) { duk_push_false(c); return 1; }

    auto* mt = vm->type("Method");
    auto* cmt = vm->type("ConstMethod");
    if (!mt || !cmt) { duk_push_false(c); return 1; }

    try {
        uint64_t cm = vm->reader()->read_u64(method + mt->field("_constMethod")->offset);
        uint16_t code_size = vm->reader()->read_u16(cm + cmt->field("_code_size")->offset);
        if ((duk_size_t)code_size < bclen) { duk_push_false(c); return 1; }

        std::vector<uint8_t> bc(code_size, 0x00);  // nop pad
        for (duk_size_t i = 0; i < bclen; ++i) {
            duk_get_prop_index(c, 2, (duk_uarridx_t)i);
            bc[i] = (uint8_t)duk_get_int_default(c, -1, 0);
            duk_pop(c);
        }
        uint64_t code_base = cm + cmt->size;
        vm->reader()->write(code_base, bc.data(), bc.size());
        // Null _code so JIT'd version is invalidated
        uint64_t zero = 0;
        vm->reader()->write(method + mt->field("_code")->offset, &zero, 8);
        duk_push_true(c);
        return 1;
    } catch (...) {
        duk_push_false(c);
        return 1;
    }
}

} // anon

void register_redefine_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_redefine, 3);
    duk_put_prop_string(ctx, ns_idx, "_redefineMethod");
}

} // namespace marrow
