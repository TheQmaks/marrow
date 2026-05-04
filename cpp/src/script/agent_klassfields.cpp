#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "field_reader.hpp"
#include "duktape.h"

namespace marrow {
namespace {

// Marrow._klassFields(klass_obj, includeStatic=true)
// Returns [{name, sig, offset, isStatic, modifiers}, ...]
duk_ret_t js_klassFields(duk_context* c) {
    uint64_t klass = obj_addr(c, 0);
    bool include_static = duk_get_boolean_default(c, 1, true);
    auto* vm = current_vm(c);

    duk_idx_t arr = duk_push_array(c);
    if (!vm || !klass) return 1;

    std::vector<FieldRecord> fields;
    try { fields = read_fields(vm, klass); } catch (...) { return 1; }

    duk_uarridx_t out_i = 0;
    for (auto& f : fields) {
        if (!include_static && f.is_static) continue;
        duk_idx_t o = duk_push_object(c);
        duk_push_string(c, f.name.c_str());      duk_put_prop_string(c, o, "name");
        duk_push_string(c, f.signature.c_str()); duk_put_prop_string(c, o, "sig");
        duk_push_int(c, f.offset);               duk_put_prop_string(c, o, "offset");
        duk_push_boolean(c, f.is_static);        duk_put_prop_string(c, o, "isStatic");
        duk_push_int(c, f.access_flags);         duk_put_prop_string(c, o, "modifiers");
        duk_put_prop_index(c, arr, out_i++);
    }
    return 1;
}

} // anon

void register_klassfields_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_klassFields, 2);
    duk_put_prop_string(ctx, ns_idx, "_klassFields");
}

} // namespace marrow
