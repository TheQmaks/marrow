#include "agent_modules.hpp"
#include "duktape.h"
#include <atomic>
#include <cstdio>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace marrow {

extern std::mutex g_hook_counters_mu;
extern std::unordered_map<uint64_t, std::atomic<uint64_t>> g_hook_counters;

namespace {

duk_ret_t js_hookCounts(duk_context* c) {
    uint64_t cookie_min = duk_get_number_default(c, 0, 0.0) >= 0.0
                          ? static_cast<uint64_t>(duk_get_number_default(c, 0, 0.0)) : 0;
    uint64_t cookie_max = duk_is_undefined(c, 1)
                          ? ~uint64_t(0)
                          : static_cast<uint64_t>(duk_get_number_default(c, 1, 0.0));
    duk_idx_t arr = duk_push_array(c);

    std::vector<std::pair<uint64_t, uint64_t>> snapshot;
    {
        std::lock_guard<std::mutex> g(g_hook_counters_mu);
        for (auto& kv : g_hook_counters) {
            if (kv.first < cookie_min) continue;
            if (kv.first > cookie_max) continue;
            snapshot.push_back({kv.first, kv.second.load(std::memory_order_relaxed)});
        }
    }

    duk_uarridx_t i = 0;
    for (auto& [cookie, count] : snapshot) {
        duk_idx_t o = duk_push_object(c);
        duk_push_uint(c, (duk_uint_t)cookie); duk_put_prop_string(c, o, "cookie");
        duk_push_number(c, (double)count);     duk_put_prop_string(c, o, "count");
        duk_put_prop_index(c, arr, i++);
    }
    return 1;
}

} // anon

void register_hooklist_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_hookCounts, 2);
    duk_put_prop_string(ctx, ns_idx, "_hookCounts");
}

} // namespace marrow
