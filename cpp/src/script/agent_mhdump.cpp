// agent_mhdump.cpp — MethodHandle / CallSite inspection bindings.
//
// Caveats:
//   - find_field may race with concurrent class-loading; callers should wrap
//     in Java.safe(...) at the JS layer (see project_live_deref_races.md).
//   - Only raw oop slots are exposed; deeper decoding (e.g. LambdaForm name)
//     requires further _mhDump / field reads on the returned addresses.
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
#include <string>

namespace marrow {
namespace {

uint64_t find_klass_by_name(VMMeta* vm, const char* name) {
    ClassWalker cw(vm);
    for (auto& k : cw.list()) {
        if (k.name == name) return k.address;
    }
    return 0;
}

uint64_t read_oop_field(VMMeta* vm, OopDecoder* dec, ZGCDecoder* zgc,
                        uint64_t obj, size_t offset) {
    uint64_t slot = obj + offset;
    if (zgc && zgc->is_active())
        return zgc->decode(vm->reader()->read_u64(slot));
    if (dec->oops_are_compressed())
        return dec->decode_oop(vm->reader()->read_u32(slot));
    return vm->reader()->read_u64(slot);
}

// js_mhDump(oop_hex) -> {form: hex, type: hex}
// Reads the two primary oop fields present on every MethodHandle instance.
// DirectMethodHandle's `member` field requires a subclass klass walk and is
// not included here to keep the implementation focused.
duk_ret_t js_mhDump(duk_context* c) {
    const char* oop_hex = duk_require_string(c, 0);
    uint64_t oop = strtoull(oop_hex, nullptr, 0);
    auto* vm   = current_vm(c);
    auto* host = current_host(c);
    if (!vm || !host || !oop) { duk_push_null(c); return 1; }

    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);

    uint64_t mh_klass = find_klass_by_name(vm, "java/lang/invoke/MethodHandle");
    if (!mh_klass) { duk_push_null(c); return 1; }

    duk_idx_t o = duk_push_object(c);
    char buf[32];

    auto try_field = [&](const char* fname, const char* prop) {
        try {
            auto fr = find_field(vm, mh_klass, fname);
            if (!fr) return;
            uint64_t v = read_oop_field(vm, dec, zgc, oop,
                                        static_cast<size_t>(fr->offset));
            std::snprintf(buf, sizeof(buf), "0x%llx",
                          static_cast<unsigned long long>(v));
            duk_push_string(c, buf);
            duk_put_prop_string(c, o, prop);
        } catch (...) {}
    };

    try_field("form", "form");
    try_field("type", "type");

    return 1;
}

// js_callsiteTarget(callsite_oop_hex) -> hex string of `target` oop, or null.
duk_ret_t js_callsiteTarget(duk_context* c) {
    const char* oop_hex = duk_require_string(c, 0);
    uint64_t oop = strtoull(oop_hex, nullptr, 0);
    auto* vm   = current_vm(c);
    auto* host = current_host(c);
    if (!vm || !host || !oop) { duk_push_null(c); return 1; }

    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);

    uint64_t cs_klass = find_klass_by_name(vm, "java/lang/invoke/CallSite");
    if (!cs_klass) { duk_push_null(c); return 1; }

    try {
        auto fr = find_field(vm, cs_klass, "target");
        if (!fr) { duk_push_null(c); return 1; }
        uint64_t target = read_oop_field(vm, dec, zgc, oop,
                                         static_cast<size_t>(fr->offset));
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(target));
        duk_push_string(c, buf);
    } catch (...) { duk_push_null(c); }
    return 1;
}

} // namespace

void register_mhdump_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_mhDump, 1);
    duk_put_prop_string(ctx, ns_idx, "_mhDump");
    duk_push_c_function(ctx, js_callsiteTarget, 1);
    duk_put_prop_string(ctx, ns_idx, "_callsiteTarget");
}

} // namespace marrow
