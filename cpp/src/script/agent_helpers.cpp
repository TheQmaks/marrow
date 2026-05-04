#include "agent_helpers.hpp"
#include <cstdlib>

namespace marrow {

VMMeta* current_vm(duk_context* c) {
    duk_push_global_stash(c);
    duk_get_prop_string(c, -1, "vm");
    auto* vm = static_cast<VMMeta*>(duk_to_pointer(c, -1));
    duk_pop_2(c);
    return vm;
}

JsHost* current_host(duk_context* c) {
    duk_push_global_stash(c);
    duk_get_prop_string(c, -1, "host");
    auto* h = static_cast<JsHost*>(duk_to_pointer(c, -1));
    duk_pop_2(c);
    return h;
}

uint64_t obj_addr(duk_context* c, duk_idx_t idx) {
    duk_get_prop_string(c, idx, "addr");
    const char* s = duk_get_string(c, -1);
    uint64_t v = s ? strtoull(s, nullptr, 0) : 0;
    duk_pop(c);
    return v;
}

} // namespace marrow
