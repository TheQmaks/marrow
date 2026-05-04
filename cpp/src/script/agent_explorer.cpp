// agent_explorer.cpp — recursive object field explorer.
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
#include <cstring>
#include <string>

namespace marrow {
namespace {

uint64_t resolve_klass_from_oop(VMMeta* vm, OopDecoder* dec, uint64_t oop) {
    try {
        if (dec->compressed_klass()) {
            uint32_t narrow = vm->reader()->read_u32(oop + 8);
            const auto& kp = dec->klass_params;
            return kp.enabled() ? (kp.base + ((uint64_t)narrow << kp.shift)) : (uint64_t)narrow;
        } else {
            return vm->reader()->read_u64(oop + 8);
        }
    } catch (...) { return 0; }
}

std::string read_klass_name(VMMeta* vm, uint64_t klass) {
    if (!klass || (klass & 7)) return "";
    auto* kt = vm->type("Klass");
    auto* st = vm->type("Symbol");
    if (!kt || !st) return "";
    try {
        uint64_t name_sym = vm->reader()->read_u64(klass + kt->field("_name")->offset);
        if (!name_sym) return "";
        uint16_t len = vm->reader()->read_u16(name_sym + st->field("_length")->offset);
        if (len > 1024) len = 1024;
        auto bytes = vm->reader()->read(name_sym + st->field("_body")->offset, len);
        return std::string(bytes.begin(), bytes.end());
    } catch (...) { return ""; }
}

void explore_one(duk_context* c, VMMeta* vm, OopDecoder* dec, ZGCDecoder* zgc,
                 uint64_t oop, int depth_remaining);

void push_value(duk_context* c, VMMeta* vm, OopDecoder* dec, ZGCDecoder* zgc,
                uint64_t oop, int field_offset, char tag, int depth) {
    uint64_t slot = oop + (uint64_t)field_offset;
    char buf[32];
    try {
        if (tag == 'I') {
            duk_push_number(c, (double)(int32_t)vm->reader()->read_u32(slot));
        } else if (tag == 'B' || tag == 'Z') {
            auto bytes = vm->reader()->read(slot, 1);
            duk_push_int(c, (int8_t)bytes[0]);
        } else if (tag == 'S') {
            duk_push_int(c, (int16_t)vm->reader()->read_u16(slot));
        } else if (tag == 'C') {
            duk_push_int(c, (int)vm->reader()->read_u16(slot));
        } else if (tag == 'F') {
            uint32_t raw = vm->reader()->read_u32(slot);
            float f; std::memcpy(&f, &raw, 4);
            duk_push_number(c, (double)f);
        } else if (tag == 'J' || tag == 'D') {
            uint64_t raw = vm->reader()->read_u64(slot);
            std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)raw);
            duk_push_string(c, buf);
        } else { // L, [
            uint64_t ref = 0;
            if (zgc->is_active())
                ref = zgc->decode(vm->reader()->read_u64(slot));
            else if (dec->oops_are_compressed())
                ref = dec->decode_oop(vm->reader()->read_u32(slot));
            else
                ref = vm->reader()->read_u64(slot);
            if (depth > 0 && ref) {
                explore_one(c, vm, dec, zgc, ref, depth - 1);
            } else {
                std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ref);
                duk_push_string(c, buf);
            }
        }
    } catch (...) {
        duk_push_null(c);
    }
}

void explore_one(duk_context* c, VMMeta* vm, OopDecoder* dec, ZGCDecoder* zgc,
                 uint64_t oop, int depth_remaining) {
    duk_idx_t obj = duk_push_object(c);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)oop);
    duk_push_string(c, buf); duk_put_prop_string(c, obj, "oop");

    uint64_t klass = resolve_klass_from_oop(vm, dec, oop);
    if (!klass || (klass & 7)) {
        duk_push_string(c, "?"); duk_put_prop_string(c, obj, "klassName");
        return;
    }
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)klass);
    duk_push_string(c, buf); duk_put_prop_string(c, obj, "klass");
    duk_push_string(c, read_klass_name(vm, klass).c_str());
    duk_put_prop_string(c, obj, "klassName");

    duk_idx_t fields = duk_push_object(c);
    try {
        auto field_records = read_fields(vm, klass);
        int n = 0;
        for (auto& f : field_records) {
            if (f.is_static) continue;
            if (n++ >= 64) break;
            char tag = f.signature.empty() ? '\0' : f.signature[0];
            push_value(c, vm, dec, zgc, oop, f.offset, tag, depth_remaining);
            duk_put_prop_string(c, fields, f.name.c_str());
        }
    } catch (...) {}
    duk_put_prop_string(c, obj, "fields");
}

duk_ret_t js_explore(duk_context* c) {
    const char* oop_hex = duk_require_string(c, 0);
    int max_depth = duk_get_int_default(c, 1, 1);
    if (max_depth < 0) max_depth = 0;
    if (max_depth > 4) max_depth = 4;

    auto* host = current_host(c);
    if (!host || !host->vm_) { duk_push_null(c); return 1; }

    auto* vm  = host->vm_;
    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);
    if (!dec || !zgc) { duk_push_null(c); return 1; }

    uint64_t oop = strtoull(oop_hex, nullptr, 0);
    if (!oop) { duk_push_null(c); return 1; }

    explore_one(c, vm, dec, zgc, oop, max_depth);
    return 1;
}

} // anon

void register_explorer_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_explore, 2);
    duk_put_prop_string(ctx, ns_idx, "_explore");
}

} // namespace marrow
