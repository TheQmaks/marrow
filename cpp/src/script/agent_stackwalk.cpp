#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>

namespace marrow {
namespace {

bool looks_like_method(VMMeta* vm, uint64_t maybe_method) {
    if (maybe_method < 0x10000 || (maybe_method & 7)) return false;
    auto* mt = vm->type("Method");
    if (!mt) return false;
    auto* cm_field = mt->field("_constMethod");
    if (!cm_field) return false;
    try {
        uint64_t cm = vm->reader()->read_u64(maybe_method + cm_field->offset);
        return cm != 0 && (cm & 7) == 0;
    } catch (...) { return false; }
}

duk_ret_t js_stackWalk(duk_context* c) {
    const char* tha_hex = duk_require_string(c, 0);
    int max_frames = duk_get_int_default(c, 1, 32);
    if (max_frames <= 0)  max_frames = 32;
    if (max_frames > 256) max_frames = 256;

    uint64_t thread = strtoull(tha_hex, nullptr, 0);
    auto* vm = current_vm(c);
    duk_idx_t arr = duk_push_array(c);
    if (!vm || !thread) return 1;

    auto* jt = vm->type("JavaThread");
    if (!jt) return 1;
    auto* anchor_f = jt->field("_anchor");
    if (!anchor_f) return 1;
    uint64_t anchor_base = thread + anchor_f->offset;

    auto* anchor_t = vm->type("JavaFrameAnchor");
    if (!anchor_t) return 1;
    auto* fp_f = anchor_t->field("_last_Java_fp");
    if (!fp_f) return 1;

    uint64_t rbp = 0;
    try {
        rbp = vm->reader()->read_u64(anchor_base + fp_f->offset);
    } catch (...) { return 1; }
    if (!rbp) return 1;

    duk_uarridx_t i = 0;
    for (int n = 0; n < max_frames && rbp; ++n) {
        uint64_t prev_rbp = 0, ret_pc = 0, maybe_method = 0;
        try {
            prev_rbp    = vm->reader()->read_u64(rbp + 0);
            ret_pc      = vm->reader()->read_u64(rbp + 8);
            maybe_method = vm->reader()->read_u64(rbp - 24);  // interpreter_frame_method_offset=-3 slots
        } catch (...) { break; }

        const char* kind = looks_like_method(vm, maybe_method)
                           ? "interp" : "compiled-or-native";

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

        // Sanity: saved RBP must advance forward, and not by more than 1 MB.
        if (prev_rbp <= rbp || prev_rbp - rbp > (1u << 20)) break;
        rbp = prev_rbp;
    }
    return 1;
}

} // anon

void register_stackwalk_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_stackWalk, 2);
    duk_put_prop_string(ctx, ns_idx, "_stackWalk");
}

} // namespace marrow
