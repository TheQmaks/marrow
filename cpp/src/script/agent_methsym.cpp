#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>
#include <string>

namespace marrow {
namespace {

std::string read_symbol(VMMeta* vm, uint64_t sym) {
    if (!plausible_metaspace(sym)) return "";
    auto* st = vm->type("Symbol");
    if (!st) return "";
    try {
        uint16_t len = vm->reader()->read_u16(sym + st->field("_length")->offset);
        if (len > 1024) len = 1024;
        if (len == 0) return "";
        auto bytes = vm->reader()->read(sym + st->field("_body")->offset, len);
        return std::string(bytes.begin(), bytes.end());
    } catch (...) { return ""; }
}

duk_ret_t js_methodName(duk_context* c) {
    const char* hex = duk_require_string(c, 0);
    uint64_t method = strtoull(hex, nullptr, 0);
    if (!plausible_metaspace(method)) { duk_push_null(c); return 1; }
    auto* vm = current_vm(c);
    if (!vm) { duk_push_null(c); return 1; }

    auto* mt  = vm->type("Method");
    auto* cmt = vm->type("ConstMethod");
    auto* cpt = vm->type("ConstantPool");
    auto* kt  = vm->type("Klass");
    if (!mt || !cmt || !cpt || !kt) { duk_push_null(c); return 1; }

    try {
        uint64_t cm = vm->reader()->read_u64(method + mt->field("_constMethod")->offset);
        if (!plausible_metaspace(cm)) { duk_push_null(c); return 1; }

        uint64_t cp       = vm->reader()->read_u64(cm + cmt->field("_constants")->offset);
        uint16_t name_idx = vm->reader()->read_u16(cm + cmt->field("_name_index")->offset);
        uint16_t sig_idx  = vm->reader()->read_u16(cm + cmt->field("_signature_index")->offset);

        if (!plausible_metaspace(cp)) { duk_push_null(c); return 1; }
        uint64_t cp_base = cp + cpt->size;

        uint64_t name_sym = vm->reader()->read_u64(cp_base + (uint64_t)name_idx * 8);
        uint64_t sig_sym  = vm->reader()->read_u64(cp_base + (uint64_t)sig_idx  * 8);

        std::string name = read_symbol(vm, name_sym);
        std::string sig  = read_symbol(vm, sig_sym);

        std::string class_name;
        auto* holder_f = cpt->field("_pool_holder");
        if (holder_f) {
            uint64_t holder = vm->reader()->read_u64(cp + holder_f->offset);
            if (plausible_metaspace(holder)) {
                uint64_t kname_sym = vm->reader()->read_u64(holder + kt->field("_name")->offset);
                class_name = read_symbol(vm, kname_sym);
            }
        }

        duk_idx_t o = duk_push_object(c);
        duk_push_string(c, class_name.c_str()); duk_put_prop_string(c, o, "className");
        duk_push_string(c, name.c_str());        duk_put_prop_string(c, o, "name");
        duk_push_string(c, sig.c_str());         duk_put_prop_string(c, o, "sig");
    } catch (...) {
        duk_push_null(c);
    }
    return 1;
}

} // anon

void register_methsym_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_methodName, 1);
    duk_put_prop_string(ctx, ns_idx, "_methodName");
}

} // namespace marrow
