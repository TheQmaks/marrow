#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "duktape.h"

namespace marrow {

// Marrow._dumpBytecode(method_lo, method_hi) -> Array<int> | null
static duk_ret_t js_dumpBytecode(duk_context* ctx) {
    uint64_t method    = duk_require_uint(ctx, 0);
    uint64_t method_hi = duk_require_uint(ctx, 1);
    method |= (method_hi << 32);

    auto* vm = current_vm(ctx);
    if (!vm) { duk_push_null(ctx); return 1; }

    auto* mt  = vm->type("Method");
    auto* cmt = vm->type("ConstMethod");
    if (!mt || !cmt ||
        !mt->field("_constMethod") ||
        !cmt->field("_code_size")) {
        duk_push_null(ctx);
        return 1;
    }

    uint64_t cm        = vm->reader()->read_u64(method + mt->field("_constMethod")->offset);
    uint16_t code_size = vm->reader()->read_u16(cm + cmt->field("_code_size")->offset);

    // 0-byte methods (native/abstract) and unreasonably large sizes are
    // both returned as null so callers can distinguish "no bytecode" from
    // an empty array.  65535 is the JVM spec maximum for a single method.
    if (code_size == 0 || code_size > 65535) {
        duk_push_null(ctx);
        return 1;
    }

    uint64_t code_base = cm + cmt->size;
    auto bytes = vm->reader()->read(code_base, code_size);

    duk_push_array(ctx);
    for (duk_uarridx_t i = 0; i < static_cast<duk_uarridx_t>(bytes.size()); ++i) {
        duk_push_uint(ctx, bytes[i]);
        duk_put_prop_index(ctx, -2, i);
    }
    return 1;
}

void register_bytecode_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_dumpBytecode, 2);
    duk_put_prop_string(ctx, ns_idx, "_dumpBytecode");
}

} // namespace marrow
