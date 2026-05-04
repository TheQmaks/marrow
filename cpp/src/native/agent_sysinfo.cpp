// agent_sysinfo.cpp — Marrow._systemPropsOop()
//
// Reads the `java/lang/System::props` static field and returns the oop of the
// java.util.Properties instance as a hex string.  Callers can then pass it to
// Java.explore() to walk the Hashtable without manual C++ traversal.
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

namespace marrow {
namespace {

// Marrow._systemPropsOop() -> "0x<addr>" | null
duk_ret_t js_systemPropsOop(duk_context* c) {
    auto* vm   = current_vm(c);
    auto* host = current_host(c);
    if (!vm || !host) { duk_push_null(c); return 1; }

    // 1. Locate java/lang/System Klass*.
    uint64_t sys_klass = 0;
    try {
        ClassWalker cw(vm);
        for (auto& k : cw.list()) {
            if (k.name == "java/lang/System") { sys_klass = k.address; break; }
        }
    } catch (...) {}
    if (!sys_klass) { duk_push_null(c); return 1; }

    // 2. Find the "props" static field record.
    auto fr = find_field(vm, sys_klass, "props");
    if (!fr) { duk_push_null(c); return 1; }

    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);

    // 3. Resolve the Java mirror oop for the klass (same as mirror_for_klass
    //    in agent_js.cpp; duplicated here to avoid cross-TU linkage).
    const auto* kt = vm->type("Klass");
    if (!kt) { duk_push_null(c); return 1; }
    const auto* mf = kt->field("_java_mirror");
    if (!mf) { duk_push_null(c); return 1; }
    uint64_t mirror = 0;
    try {
        uint64_t raw = vm->reader()->read_u64(sys_klass + mf->offset);
        mirror = (mf->type_string == "OopHandle")
                     ? vm->reader()->read_u64(raw) : raw;
        if (zgc->is_active()) mirror = zgc->decode(mirror);
    } catch (...) {}
    if (!mirror) { duk_push_null(c); return 1; }

    // 4. Read the static field slot from the mirror.
    uint64_t slot = mirror + static_cast<uint64_t>(fr->offset);
    uint64_t props_oop = 0;
    try {
        if (zgc->is_active())
            props_oop = zgc->decode(vm->reader()->read_u64(slot));
        else if (dec->oops_are_compressed())
            props_oop = dec->decode_oop(vm->reader()->read_u32(slot));
        else
            props_oop = vm->reader()->read_u64(slot);
    } catch (...) {}
    if (!props_oop) { duk_push_null(c); return 1; }

    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(props_oop));
    duk_push_string(c, buf);
    return 1;
}

} // namespace

void register_sysinfo_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_systemPropsOop, 0);
    duk_put_prop_string(ctx, ns_idx, "_systemPropsOop");
}

} // namespace marrow
