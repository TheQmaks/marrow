#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "walker.hpp"
#include "method_walker.hpp"
#include "duktape.h"
#include <unordered_set>
#include <cstring>

namespace marrow {
namespace {

duk_ret_t js_symbols(duk_context* c) {
    const char* prefix = duk_get_string_default(c, 0, "");
    auto* vm = current_vm(c);
    duk_idx_t arr = duk_push_array(c);
    if (!vm) return 1;

    std::unordered_set<std::string> seen;
    duk_uarridx_t out_i = 0;

    auto push_if_match = [&](const std::string& name) {
        if (name.empty()) return;
        if (seen.count(name)) return;
        seen.insert(name);
        if (prefix && *prefix) {
            if (name.compare(0, std::strlen(prefix), prefix) != 0) return;
        }
        if (out_i >= 10000) return;
        duk_push_string(c, name.c_str());
        duk_put_prop_index(c, arr, out_i++);
    };

    try {
        ClassWalker cw(vm);
        auto klasses = cw.list();
        for (auto& k : klasses) {
            if (out_i >= 10000) break;
            push_if_match(k.name);
            try {
                auto methods = methods_of(vm, k.address);
                for (auto& m : methods) {
                    if (out_i >= 10000) break;
                    push_if_match(m.name);
                    push_if_match(m.signature);
                }
            } catch (...) { /* skip inaccessible methods */ }
        }
    } catch (...) { /* return partial results on walker failure */ }

    return 1;
}

} // anon

void register_symtab_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_symbols, 1);
    duk_put_prop_string(ctx, ns_idx, "symbols");
}

} // namespace marrow
