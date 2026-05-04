#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>

namespace marrow {
namespace {

duk_ret_t js_nmDump(duk_context* c) {
    uint64_t method = duk_require_uint(c, 0);
    uint64_t method_hi = duk_require_uint(c, 1);
    method |= (method_hi << 32);
    auto* vm = current_vm(c);
    if (!vm) { duk_push_null(c); return 1; }

    auto* mt = vm->type("Method");
    if (!mt) { duk_push_null(c); return 1; }
    auto* code_field = mt->field("_code");
    if (!code_field) { duk_push_null(c); return 1; }
    uint64_t code = vm->reader()->read_u64(method + code_field->offset);
    if (!code) { duk_push_null(c); return 1; }

    auto get_off = [&](const char* tname, const char* fname) -> int64_t {
        auto* t = vm->type(tname);
        if (!t) return -1;
        auto* f = t->field(fname);
        if (!f) return -1;
        return (int64_t)f->offset;
    };

    int64_t size_off  = get_off("CodeBlob", "_size");
    int64_t entry_off = get_off("nmethod", "_entry_point");
    int64_t vep_off   = get_off("nmethod", "_verified_entry_point");

    if (size_off < 0) { duk_push_null(c); return 1; }
    int32_t blob_size = (int32_t)vm->reader()->read_u32(code + (uint64_t)size_off);
    if (blob_size <= 0 || blob_size > 1 << 20) { duk_push_null(c); return 1; }

    uint64_t entry = (entry_off >= 0)
        ? vm->reader()->read_u64(code + (uint64_t)entry_off) : 0;
    uint64_t vep   = (vep_off >= 0)
        ? vm->reader()->read_u64(code + (uint64_t)vep_off) : 0;

    int dump_size = std::min(blob_size, 65536);
    auto bytes = vm->reader()->read(code, (size_t)dump_size);

    duk_idx_t o = duk_push_object(c);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)code);
    duk_push_string(c, buf); duk_put_prop_string(c, o, "base");
    duk_push_int(c, blob_size); duk_put_prop_string(c, o, "size");
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)entry);
    duk_push_string(c, buf); duk_put_prop_string(c, o, "entry");
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)vep);
    duk_push_string(c, buf); duk_put_prop_string(c, o, "verifiedEntry");

    duk_idx_t arr = duk_push_array(c);
    for (size_t i = 0; i < bytes.size(); ++i) {
        duk_push_int(c, bytes[i]);
        duk_put_prop_index(c, arr, (duk_uarridx_t)i);
    }
    duk_put_prop_string(c, o, "bytes");
    return 1;
}

} // anon

void register_nmdump_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_nmDump, 2);
    duk_put_prop_string(ctx, ns_idx, "_nmDump");
}

} // namespace marrow
