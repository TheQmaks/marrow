#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "agent_js.hpp"
#include "vm_meta.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>

namespace marrow {
namespace {

duk_ret_t js_heapRegions(duk_context* c) {
    int min_mb = duk_get_int_default(c, 0, 1);
    auto* vm = current_vm(c);
    duk_idx_t arr = duk_push_array(c);
    if (!vm) return 1;

    auto regions = vm->reader()->enumerate_regions(true);
    duk_uarridx_t i = 0;
    for (auto& r : regions) {
        if ((int)(r.size / (1024*1024)) < min_mb) continue;
        const char* kind = (r.size >= 64*1024*1024)
            ? "heap-candidate"
            : (r.size >= 4*1024*1024 ? "code-or-meta" : "small");
        duk_idx_t o = duk_push_object(c);
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)r.base);
        duk_push_string(c, buf); duk_put_prop_string(c, o, "base");
        duk_push_number(c, (double)r.size); duk_put_prop_string(c, o, "size");
        duk_push_string(c, kind); duk_put_prop_string(c, o, "kind");
        duk_put_prop_index(c, arr, i++);
    }
    return 1;
}

} // anon

void register_gcmap_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_heapRegions, 1);
    duk_put_prop_string(ctx, ns_idx, "_heapRegions");
}

} // namespace marrow
