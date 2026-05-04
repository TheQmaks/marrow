// agent_heapfilter.cpp — filtered heap walker bindings for Duktape JS host.
#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "agent_js.hpp"
#include "field_reader.hpp"
#include "heap_walker.hpp"
#include "oop_reader.hpp"
#include "zgc.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace marrow {
namespace {

// JS: Marrow._findInstancesByField(klass_obj, fieldName, type, expectedValue, limit)
// Returns an array of hex-string oop addresses whose named field matches expectedValue.
// type is a single JVM signature prefix: I B S C Z J L [
// For L/[ expectedValue is a hex string; for primitives it is a Number.
// limit == 0 means unbounded.
duk_ret_t js_findInstancesByField(duk_context* c) {
    uint64_t klass       = obj_addr(c, 0);
    const char* fname    = duk_require_string(c, 1);
    const char* type_str = duk_require_string(c, 2);
    char tag             = type_str[0];
    int limit            = duk_get_int_default(c, 4, 0);

    auto* vm   = current_vm(c);
    auto* host = current_host(c);

    duk_idx_t arr = duk_push_array(c);

    if (!vm || !klass || !host) return 1;

    auto fr = find_field(vm, klass, fname);
    if (!fr) return 1;

    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto found = find_instances_by_klass(vm, dec, klass, 0);

    duk_uarridx_t out_i = 0;
    for (auto& oop : found) {
        if (limit > 0 && static_cast<int>(out_i) >= limit) break;

        uint64_t slot = oop + static_cast<uint64_t>(fr->offset);
        bool match = false;

        try {
            if (tag == 'I') {
                auto expected = static_cast<int32_t>(duk_require_number(c, 3));
                auto got      = static_cast<int32_t>(vm->reader()->read_u32(slot));
                match = (got == expected);
            } else if (tag == 'B' || tag == 'Z') {
                int expected = duk_require_int(c, 3);
                auto bytes   = vm->reader()->read(slot, 1);
                match = !bytes.empty() && static_cast<int8_t>(bytes[0]) == static_cast<int8_t>(expected);
            } else if (tag == 'S') {
                auto expected = static_cast<int16_t>(duk_require_int(c, 3));
                auto got      = static_cast<int16_t>(vm->reader()->read_u16(slot));
                match = (got == expected);
            } else if (tag == 'C') {
                auto expected = static_cast<uint16_t>(duk_require_int(c, 3));
                uint16_t got  = vm->reader()->read_u16(slot);
                match = (got == expected);
            } else if (tag == 'J') {
                const char* s  = duk_require_string(c, 3);
                uint64_t expected = strtoull(s, nullptr, 0);
                uint64_t got      = vm->reader()->read_u64(slot);
                match = (got == expected);
            } else if (tag == 'L' || tag == '[') {
                const char* s     = duk_require_string(c, 3);
                uint64_t expected = strtoull(s, nullptr, 0);
                auto* zgc         = static_cast<ZGCDecoder*>(host->zgc_);
                uint64_t got      = 0;
                if (zgc->is_active()) {
                    got = zgc->decode(vm->reader()->read_u64(slot));
                } else if (dec->oops_are_compressed()) {
                    got = dec->decode_oop(vm->reader()->read_u32(slot));
                } else {
                    got = vm->reader()->read_u64(slot);
                }
                match = (got == expected);
            }
        } catch (...) {
            match = false;
        }

        if (match) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(oop));
            duk_push_string(c, buf);
            duk_put_prop_index(c, arr, out_i++);
        }
    }
    return 1;
}

} // namespace

void register_heapfilter_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_findInstancesByField, 5);
    duk_put_prop_string(ctx, ns_idx, "_findInstancesByField");
}

} // namespace marrow
