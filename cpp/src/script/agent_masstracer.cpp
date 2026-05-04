#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "agent_js.hpp"
#include "vm_meta.hpp"
#include "walker.hpp"
#include "method_walker.hpp"
#include "hooks.hpp"
#include "duktape.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <unordered_map>

namespace marrow {

extern std::mutex g_hook_counters_mu;
extern std::unordered_map<uint64_t, std::atomic<uint64_t>> g_hook_counters;
extern void on_counting_hook(HookContext* ctx);

namespace {

bool icontains(const std::string& s, const std::string& sub) {
    if (sub.empty()) return true;
    if (s.size() < sub.size()) return false;
    for (size_t i = 0; i + sub.size() <= s.size(); ++i) {
        bool m = true;
        for (size_t j = 0; j < sub.size(); ++j)
            if (s[i+j] != sub[j]) { m = false; break; }
        if (m) return true;
    }
    return false;
}

duk_ret_t js_traceMatching(duk_context* c) {
    const char* class_pat = duk_require_string(c, 0);
    const char* method_pat = duk_require_string(c, 1);
    uint32_t cookie_base = (uint32_t)duk_require_uint(c, 2);
    int max_n = duk_get_int_default(c, 3, 256);
    auto* vm = current_vm(c);
    duk_idx_t result = duk_push_object(c);
    if (!vm) return 1;

    duk_push_uint(c, cookie_base); duk_put_prop_string(c, result, "cookieBase");
    duk_idx_t methods_arr = duk_push_array(c);

    int installed = 0;
    duk_uarridx_t out_i = 0;
    uint32_t cookie = cookie_base;
    std::string cls_pat(class_pat);
    std::string mth_pat(method_pat);

    try {
        ClassWalker cw(vm);
        auto klasses = cw.list();
        for (auto& k : klasses) {
            if (installed >= max_n) break;
            if (!icontains(k.name, cls_pat)) continue;
            std::vector<MethodSnapshot> methods;
            try { methods = methods_of(vm, k.address); }
            catch (...) { continue; }
            for (auto& m : methods) {
                if (installed >= max_n) break;
                if (!icontains(m.name, mth_pat)) continue;
                {
                    std::lock_guard<std::mutex> g(g_hook_counters_mu);
                    g_hook_counters[cookie].store(0);
                }
                try {
                    install_callback_hook(vm, m, &on_counting_hook, cookie);
                    duk_idx_t entry = duk_push_object(c);
                    duk_push_string(c, k.name.c_str()); duk_put_prop_string(c, entry, "klass");
                    duk_push_string(c, m.name.c_str()); duk_put_prop_string(c, entry, "name");
                    duk_push_uint(c, cookie); duk_put_prop_string(c, entry, "cookie");
                    duk_put_prop_index(c, methods_arr, out_i++);
                    ++installed;
                    ++cookie;
                } catch (...) {}
            }
        }
    } catch (...) {}

    duk_put_prop_string(c, result, "methods");
    duk_push_int(c, installed); duk_put_prop_string(c, result, "installed");
    return 1;
}

} // anon

void register_masstracer_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_traceMatching, 4);
    duk_put_prop_string(ctx, ns_idx, "_traceMatching");
}

} // namespace marrow
