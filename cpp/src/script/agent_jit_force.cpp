// agent_jit_force.cpp — JIT force-compile JS binding.
// Bumps Method::_method_counters->_invocation_counter._counter past the
// compile threshold so HotSpot triggers JIT on the next interpreter dispatch.
#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "duktape.h"

namespace marrow {

// js_forceCompile(method_lo, method_hi) -> bool
// Reads Method::_method_counters, then writes a huge count into
// MethodCounters::_invocation_counter._counter (upper bits; low 3 = state).
static duk_ret_t js_forceCompile(duk_context* ctx) {
    uint32_t lo = static_cast<uint32_t>(duk_to_uint32(ctx, 0));
    uint32_t hi = static_cast<uint32_t>(duk_to_uint32(ctx, 1));
    uint64_t method = (static_cast<uint64_t>(hi) << 32) | lo;

    VMMeta* vm = current_vm(ctx);
    if (!vm) {
        duk_push_false(ctx);
        return 1;
    }

    try {
        const TypeInfo* mt = vm->type("Method");
        if (!mt) { duk_push_false(ctx); return 1; }

        const FieldInfo* mc_fld = mt->field("_method_counters");
        if (!mc_fld) { duk_push_false(ctx); return 1; }

        uint64_t mc = vm->reader()->read_u64(method + mc_fld->offset);
        if (!mc) {
            // MethodCounters not yet allocated — cannot bump out-of-process.
            duk_push_false(ctx);
            return 1;
        }

        const TypeInfo* mct = vm->type("MethodCounters");
        if (!mct) { duk_push_false(ctx); return 1; }

        const FieldInfo* ic_fld = mct->field("_invocation_counter");
        if (!ic_fld) { duk_push_false(ctx); return 1; }

        const TypeInfo* ict = vm->type("InvocationCounter");
        if (!ict) { duk_push_false(ctx); return 1; }

        const FieldInfo* cnt_fld = ict->field("_counter");
        if (!cnt_fld) { duk_push_false(ctx); return 1; }

        // HotSpot InvocationCounter: low 3 bits = state, upper bits = count.
        // Write a large count that exceeds any CompileThreshold.
        uint32_t huge = 100000u << 3;
        uint64_t target = mc + ic_fld->offset + cnt_fld->offset;
        vm->reader()->write(target, &huge, sizeof(huge));

        duk_push_true(ctx);
        return 1;
    } catch (...) {
        duk_push_false(ctx);
        return 1;
    }
}

void register_jit_force_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_forceCompile, 2);
    duk_put_prop_string(ctx, ns_idx, "_forceCompile");
}

} // namespace marrow
