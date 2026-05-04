#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "walker.hpp"
#include "method_walker.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace marrow {
namespace {

duk_ret_t js_codeCache(duk_context* c) {
    int max_n = duk_get_int_default(c, 0, 256);
    auto* vm = current_vm(c);
    duk_idx_t arr = duk_push_array(c);
    if (!vm) return 1;

    auto* mt = vm->type("Method");
    auto* cbt = vm->type("CodeBlob");
    if (!mt || !cbt) return 1;
    auto* code_f = mt->field("_code");
    auto* size_f = cbt->field("_size");
    if (!code_f || !size_f) return 1;

    ClassWalker cw(vm);
    std::vector<KlassSnapshot> klasses;
    try { klasses = cw.list(); } catch (...) { return 1; }

    duk_uarridx_t out_i = 0;
    for (auto& k : klasses) {
        if ((int)out_i >= max_n) break;
        std::vector<MethodSnapshot> methods;
        try { methods = methods_of(vm, k.address); }
        catch (...) { continue; }
        for (auto& m : methods) {
            if ((int)out_i >= max_n) break;
            uint64_t code = 0;
            try { code = vm->reader()->read_u64(m.address + code_f->offset); }
            catch (...) { continue; }
            if (!code) continue;
            int32_t blob_size = 0;
            try { blob_size = (int32_t)vm->reader()->read_u32(code + size_f->offset); }
            catch (...) {}
            if (blob_size <= 0 || blob_size > 1 << 20) blob_size = 0;

            duk_idx_t o = duk_push_object(c);
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)code);
            duk_push_string(c, buf); duk_put_prop_string(c, o, "nmethod");
            duk_push_int(c, blob_size); duk_put_prop_string(c, o, "size");
            std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)m.address);
            duk_push_string(c, buf); duk_put_prop_string(c, o, "method");
            std::string name = k.name + "." + m.name + m.signature;
            duk_push_string(c, name.c_str()); duk_put_prop_string(c, o, "name");
            duk_put_prop_index(c, arr, out_i++);
        }
    }
    return 1;
}

} // namespace

void register_codecache_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_codeCache, 1);
    duk_put_prop_string(ctx, ns_idx, "_codeCache");
}

} // namespace marrow
