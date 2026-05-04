#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>
#include <string>

namespace marrow {
namespace {

std::string read_klass_name(VMMeta* vm, uint64_t klass) {
    if (!klass) return "";
    const auto* kt = vm->type("Klass");
    const auto* st = vm->type("Symbol");
    if (!kt || !st) return "";
    try {
        const auto* name_fld = kt->field("_name");
        const auto* len_fld  = st->field("_length");
        const auto* body_fld = st->field("_body");
        if (!name_fld || !len_fld || !body_fld) return "";
        uint64_t name_sym = vm->reader()->read_u64(klass + name_fld->offset);
        if (!name_sym) return "";
        uint16_t len = vm->reader()->read_u16(name_sym + len_fld->offset);
        if (len > 1024) len = 1024;
        auto bytes = vm->reader()->read(name_sym + body_fld->offset, len);
        return std::string(bytes.begin(), bytes.end());
    } catch (...) { return ""; }
}

// Marrow._klassSupers(klass_obj) → string[]
duk_ret_t js_klassSupers(duk_context* c) {
    uint64_t klass = obj_addr(c, 0);
    auto* vm = current_vm(c);
    duk_idx_t arr = duk_push_array(c);
    if (!vm || !klass) return 1;
    const auto* kt = vm->type("Klass");
    if (!kt) return 1;
    const auto* super_fld = kt->field("_super");
    if (!super_fld) return 1;
    duk_uarridx_t i = 0;
    uint64_t cur = klass;
    for (int n = 0; n < 32 && cur; ++n) {
        uint64_t super = 0;
        try { super = vm->reader()->read_u64(cur + super_fld->offset); } catch (...) { break; }
        if (!super) break;
        std::string name = read_klass_name(vm, super);
        duk_push_string(c, name.c_str());
        duk_put_prop_index(c, arr, i++);
        cur = super;
    }
    return 1;
}

// Marrow._klassInterfaces(klass_obj, transitive) → string[]
duk_ret_t js_klassInterfaces(duk_context* c) {
    uint64_t klass    = obj_addr(c, 0);
    bool transitive   = duk_get_boolean_default(c, 1, false) != 0;
    auto* vm          = current_vm(c);
    duk_idx_t arr     = duk_push_array(c);
    if (!vm || !klass) return 1;
    const auto* ikt = vm->type("InstanceKlass");
    if (!ikt) return 1;
    const auto* fld = ikt->field(transitive ? "_transitive_interfaces" : "_local_interfaces");
    if (!fld) return 1;
    uint64_t array_ptr = 0;
    try { array_ptr = vm->reader()->read_u64(klass + fld->offset); } catch (...) { return 1; }
    if (!array_ptr) return 1;
    // Array<Klass*>: _length (int32) at +0, padding 4 bytes, data starts at +8
    int32_t length = 0;
    try { length = static_cast<int32_t>(vm->reader()->read_u32(array_ptr)); } catch (...) { return 1; }
    if (length <= 0 || length > 1024) return 1;
    duk_uarridx_t i = 0;
    for (int k = 0; k < length; ++k) {
        try {
            uint64_t ifc = vm->reader()->read_u64(array_ptr + 8 + static_cast<size_t>(k) * 8);
            if (!ifc) continue;
            std::string name = read_klass_name(vm, ifc);
            duk_push_string(c, name.c_str());
            duk_put_prop_index(c, arr, i++);
        } catch (...) { break; }
    }
    return 1;
}

// Marrow._klassSubclasses(klass_obj, maxN) → {addr, name}[]
duk_ret_t js_klassSubclasses(duk_context* c) {
    uint64_t klass = obj_addr(c, 0);
    int max_n      = duk_get_int_default(c, 1, 64);
    auto* vm       = current_vm(c);
    duk_idx_t arr  = duk_push_array(c);
    if (!vm || !klass || max_n <= 0) return 1;
    const auto* kt = vm->type("Klass");
    if (!kt) return 1;
    const auto* sub_fld  = kt->field("_subklass");
    const auto* next_fld = kt->field("_next_sibling");
    if (!sub_fld || !next_fld) return 1;
    uint64_t cur = 0;
    try { cur = vm->reader()->read_u64(klass + sub_fld->offset); } catch (...) { return 1; }
    duk_uarridx_t i = 0;
    while (cur && static_cast<int>(i) < max_n) {
        std::string name = read_klass_name(vm, cur);
        duk_idx_t o = duk_push_object(c);
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(cur));
        duk_push_string(c, buf);      duk_put_prop_string(c, o, "addr");
        duk_push_string(c, name.c_str()); duk_put_prop_string(c, o, "name");
        duk_put_prop_index(c, arr, i++);
        try { cur = vm->reader()->read_u64(cur + next_fld->offset); } catch (...) { break; }
    }
    return 1;
}

} // namespace

void register_klassinfo_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_klassSupers,     1);
    duk_put_prop_string(ctx, ns_idx, "_klassSupers");
    duk_push_c_function(ctx, js_klassInterfaces, 2);
    duk_put_prop_string(ctx, ns_idx, "_klassInterfaces");
    duk_push_c_function(ctx, js_klassSubclasses, 2);
    duk_put_prop_string(ctx, ns_idx, "_klassSubclasses");
}

} // namespace marrow
