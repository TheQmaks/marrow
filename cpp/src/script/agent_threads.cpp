#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "walker.hpp"
#include "vm_meta.hpp"
#include "duktape.h"
#include <cstdio>

namespace marrow {
namespace {

duk_ret_t js_threads(duk_context* c) {
    auto* vm = current_vm(c);
    duk_idx_t arr = duk_push_array(c);
    if (!vm) return 1;

    try {
        ThreadWalker tw(vm);
        auto threads = tw.list();
        duk_uarridx_t out_i = 0;
        for (auto& t : threads) {
            duk_idx_t o = duk_push_object(c);
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llx",
                          static_cast<unsigned long long>(t.address));
            duk_push_string(c, buf);
            duk_put_prop_string(c, o, "addr");

            duk_push_uint(c, t.os_tid);
            duk_put_prop_string(c, o, "tid");

            duk_push_string(c, t.state_name.c_str());
            duk_put_prop_string(c, o, "state");

            std::snprintf(buf, sizeof(buf), "0x%llx",
                          static_cast<unsigned long long>(t.thread_obj));
            duk_push_string(c, buf);
            duk_put_prop_string(c, o, "threadObj");

            std::snprintf(buf, sizeof(buf), "0x%llx",
                          static_cast<unsigned long long>(t.vthread));
            duk_push_string(c, buf);
            duk_put_prop_string(c, o, "vthread");

            duk_put_prop_index(c, arr, out_i++);
        }
    } catch (...) { /* return whatever we collected */ }
    return 1;
}

} // namespace

void register_threads_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_threads, 0);
    duk_put_prop_string(ctx, ns_idx, "threads");
}

} // namespace marrow
