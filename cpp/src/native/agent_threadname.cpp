#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "agent_js.hpp"
#include "vm_meta.hpp"
#include "walker.hpp"
#include "field_reader.hpp"
#include "oop_reader.hpp"
#include "zgc.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>

namespace marrow {
namespace {

duk_ret_t js_threadName(duk_context* c) {
    const char* tobj_hex = duk_require_string(c, 0);
    uint64_t tobj = strtoull(tobj_hex, nullptr, 0);
    if (!tobj) { duk_push_string(c, ""); return 1; }
    auto* vm   = current_vm(c);
    auto* host = current_host(c);
    if (!vm || !host) { duk_push_string(c, ""); return 1; }

    // Find java/lang/Thread klass address.
    uint64_t thread_klass = 0;
    try {
        ClassWalker cw(vm);
        for (auto& k : cw.list()) {
            if (k.name == "java/lang/Thread") { thread_klass = k.address; break; }
        }
    } catch (...) {}
    if (!thread_klass) { duk_push_string(c, ""); return 1; }

    // Locate the 'name' instance field offset.
    auto fr = find_field(vm, thread_klass, "name");
    if (!fr) { duk_push_string(c, ""); return 1; }

    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);

    // Read the String oop stored in Thread.name.
    uint64_t name_oop = 0;
    try {
        uint64_t slot = tobj + static_cast<uint64_t>(fr->offset);
        if (zgc->is_active())
            name_oop = zgc->decode(vm->reader()->read_u64(slot));
        else if (dec->oops_are_compressed())
            name_oop = dec->decode_oop(vm->reader()->read_u32(slot));
        else
            name_oop = vm->reader()->read_u64(slot);
    } catch (...) {}
    if (!name_oop) { duk_push_string(c, ""); return 1; }

    // Delegate decoding to Marrow._toString (String oop → UTF-8).
    // Stack before call: [..., Marrow, _toString_fn, hex_arg]
    // Stack after duk_pcall: [..., Marrow, result]
    duk_get_global_string(c, "Marrow");
    duk_get_prop_string(c, -1, "_toString");
    if (!duk_is_function(c, -1)) {
        duk_pop_2(c);
        duk_push_string(c, "");
        return 1;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(name_oop));
    duk_push_string(c, buf);
    if (duk_pcall(c, 1) != 0) {
        // Stack: [..., Marrow, err]; discard both.
        duk_pop_2(c);
        duk_push_string(c, "");
        return 1;
    }
    // Stack: [..., Marrow, result_str]
    const char* s = duk_get_string_default(c, -1, "");
    duk_push_string(c, s);   // [..., Marrow, result_str, name_copy]
    duk_remove(c, -2);       // [..., Marrow, name_copy]
    duk_remove(c, -2);       // [..., name_copy]
    return 1;
}

} // namespace

void register_threadname_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_threadName, 1);
    duk_put_prop_string(ctx, ns_idx, "_threadName");
}

} // namespace marrow
