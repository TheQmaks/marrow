// agent_arrays.cpp — Marrow._readArray(oop_hex, type_tag, max_elems)
// Reads up to max_elems elements from a Java array oop.
// Type tags follow JVM signature convention.
#include "agent_modules.hpp"
#include "agent_js.hpp"
#include "oop_reader.hpp"
#include "zgc.hpp"
#include "duktape.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

namespace marrow {

// ---------- stash helpers (mirrors agent_js.cpp's anon-namespace versions) ---

static VMMeta* current_vm(duk_context* c) {
    duk_push_global_stash(c);
    duk_get_prop_string(c, -1, "vm");
    auto* vm = static_cast<VMMeta*>(duk_to_pointer(c, -1));
    duk_pop_2(c);
    return vm;
}

static JsHost* current_host(duk_context* c) {
    duk_push_global_stash(c);
    duk_get_prop_string(c, -1, "host");
    auto* h = static_cast<JsHost*>(duk_to_pointer(c, -1));
    duk_pop_2(c);
    return h;
}

// ---------- js_readArray --------------------------------------------------
// arg0: oop hex string
// arg1: type tag string (one char: I J F D B S C Z L [)
// arg2: max_elems (int, 0 = use full array length, capped at 4096)
// Returns: JS array of decoded values, or null on error.

static duk_ret_t js_readArray(duk_context* ctx) {
    const char* oop_str  = duk_require_string(ctx, 0);
    const char* tag_str  = duk_require_string(ctx, 1);
    int         max_arg  = duk_get_int(ctx, 2);

    if (!tag_str || tag_str[0] == '\0') { duk_push_null(ctx); return 1; }
    char tag = tag_str[0];

    auto* vm   = current_vm(ctx);
    auto* host = current_host(ctx);
    if (!vm || !host) { duk_push_null(ctx); return 1; }

    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);
    if (!dec) { duk_push_null(ctx); return 1; }

    uint64_t oop = std::strtoull(oop_str, nullptr, 0);
    if (!oop) { duk_push_null(ctx); return 1; }

    // Array header offsets: compressed klass => (12,16), else (16,24).
    size_t len_off, data_off;
    if (dec->compressed_klass()) { len_off = 12; data_off = 16; }
    else                          { len_off = 16; data_off = 24; }

    Reader* r = vm->reader();

    // Read and validate array length.
    int32_t length = r->read_i32(oop + len_off);
    if (length < 0 || length > (1 << 24)) { duk_push_null(ctx); return 1; }

    size_t n = std::min<size_t>(size_t(length),
                                size_t(max_arg > 0 ? max_arg : 4096));

    // Determine element width.
    size_t elem_width = 0;
    bool   is_oop_tag = false;
    switch (tag) {
        case 'I': case 'F': elem_width = 4; break;
        case 'J': case 'D': elem_width = 8; break;
        case 'B': case 'Z': elem_width = 1; break;
        case 'S': case 'C': elem_width = 2; break;
        case 'L': case '[':
            is_oop_tag = true;
            // oop slot width depends on compression / ZGC mode.
            elem_width = (zgc && zgc->is_active())
                            ? 8
                            : (dec->oops_are_compressed() ? 4 : 8);
            break;
        default:
            duk_push_null(ctx);
            return 1;
    }

    if (n == 0) {
        duk_push_array(ctx);
        return 1;
    }

    // Bulk read — one round-trip for the entire data slice.
    size_t total_bytes = n * elem_width;
    std::vector<uint8_t> raw = r->read(oop + data_off, total_bytes);
    if (raw.size() < total_bytes) { duk_push_null(ctx); return 1; }

    duk_idx_t arr = duk_push_array(ctx);

    for (size_t i = 0; i < n; ++i) {
        const uint8_t* p = raw.data() + i * elem_width;
        char hex[32];

        if (is_oop_tag) {
            uint64_t slot_val = 0;
            if (elem_width == 4) {
                uint32_t narrow;
                std::memcpy(&narrow, p, 4);
                if (zgc && zgc->is_active()) {
                    // ZGC stores 8-byte coloured pointers; this branch is
                    // unreachable because elem_width==8 for ZGC, kept for
                    // safety.
                    slot_val = narrow;
                } else {
                    slot_val = dec->decode_oop(narrow);
                }
            } else { // 8-byte slot
                uint64_t raw64;
                std::memcpy(&raw64, p, 8);
                if (zgc && zgc->is_active()) {
                    slot_val = zgc->decode(raw64);
                } else {
                    slot_val = raw64; // wide oop, no further decoding
                }
            }
            std::snprintf(hex, sizeof(hex), "0x%llx",
                          (unsigned long long)slot_val);
            duk_push_string(ctx, hex);

        } else if (tag == 'I') {
            int32_t v; std::memcpy(&v, p, 4);
            duk_push_int(ctx, v);

        } else if (tag == 'F') {
            float f; std::memcpy(&f, p, 4);
            duk_push_number(ctx, double(f));

        } else if (tag == 'J') {
            int64_t v; std::memcpy(&v, p, 8);
            std::snprintf(hex, sizeof(hex), "0x%llx", (unsigned long long)v);
            duk_push_string(ctx, hex);

        } else if (tag == 'D') {
            double d; std::memcpy(&d, p, 8);
            // Push as hex string to preserve full bit pattern.
            uint64_t bits; std::memcpy(&bits, p, 8);
            std::snprintf(hex, sizeof(hex), "0x%llx",
                          (unsigned long long)bits);
            duk_push_string(ctx, hex);

        } else if (tag == 'B') {
            int8_t v; std::memcpy(&v, p, 1);
            duk_push_int(ctx, v);

        } else if (tag == 'Z') {
            duk_push_int(ctx, p[0] ? 1 : 0);

        } else if (tag == 'S') {
            int16_t v; std::memcpy(&v, p, 2);
            duk_push_int(ctx, v);

        } else { // 'C'
            uint16_t v; std::memcpy(&v, p, 2);
            duk_push_uint(ctx, v);
        }

        duk_put_prop_index(ctx, arr, duk_uarridx_t(i));
    }

    return 1;
}

// ---------- registrar -------------------------------------------------------

void register_arrays_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_readArray, 3);
    duk_put_prop_string(ctx, ns_idx, "_readArray");
}

} // namespace marrow
