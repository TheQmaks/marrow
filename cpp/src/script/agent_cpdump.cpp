// agent_cpdump.cpp — ConstantPool dump binding for the Duktape JS engine.
// Exposes Marrow._cpDump(klass_obj, maxEntries) -> [{idx, tag, raw}].
//
// RAW MODE only: returns {idx, tag, raw_hex} per CP slot. We deliberately
// do NOT dereference Symbol*/Klass* pointers from the slots, because even
// with all JavaThreads suspended, HotSpot's GC service threads can free or
// relocate Symbol*/Klass* concurrently, causing segfaults.
//
// Bulk-reading the CP header, tags array, and slot bytes is safe (the
// memory itself doesn't move). Decoding values that requires following
// pointers must be done by the JS caller using readField / Java.toString
// (which has its own SuspendAll-wrapped path).
#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace marrow {
namespace {

duk_ret_t js_cpDump(duk_context* c) {
    uint64_t klass    = obj_addr(c, 0);
    int max_entries   = duk_get_int_default(c, 1, 64);
    auto* vm          = current_vm(c);
    duk_idx_t arr     = duk_push_array(c);
    if (!vm || !klass) return 1;

    if (max_entries > 256) max_entries = 256;

    const TypeInfo* ikt = vm->type("InstanceKlass");
    const TypeInfo* cpt = vm->type("ConstantPool");
    if (!ikt || !cpt) return 1;

    const FieldInfo* constants_f = ikt->field("_constants");
    const FieldInfo* length_f    = cpt->field("_length");
    const FieldInfo* tags_f      = cpt->field("_tags");
    if (!constants_f || !length_f || !tags_f) return 1;

    uint64_t cp = 0;
    try { cp = vm->reader()->read_u64(klass + constants_f->offset); } catch (...) {}
    if (!cp) return 1;

    int32_t length = 0;
    try { length = (int32_t)vm->reader()->read_u32(cp + length_f->offset); } catch (...) {}
    if (length <= 0 || length > 65535) return 1;
    if (max_entries > length) max_entries = length;

    uint64_t tags_arr = 0;
    try { tags_arr = vm->reader()->read_u64(cp + tags_f->offset); } catch (...) {}
    if (!tags_arr) return 1;

    // Array<u1> data offset (4 in HotSpot 17 — _length jint at offset 0).
    uint64_t tags_data_off = 4;
    if (const TypeInfo* arr_u1_t = vm->type("Array<u1>")) {
        if (const FieldInfo* data_f = arr_u1_t->field("_data"))
            tags_data_off = data_f->offset;
    }
    uint64_t tags_data = tags_arr + tags_data_off;

    // CP slot data starts after the ConstantPool header struct.
    uint64_t cp_base = cp + cpt->size;

    // Bulk snapshots — safe, the underlying memory doesn't move.
    std::vector<uint8_t> tag_bytes;
    try {
        auto raw = vm->reader()->read(tags_data, (size_t)length);
        tag_bytes.assign(raw.begin(), raw.end());
    } catch (...) { return 1; }

    std::vector<uint8_t> slot_bytes;
    try {
        auto raw = vm->reader()->read(cp_base, (size_t)length * 8);
        slot_bytes.assign(raw.begin(), raw.end());
    } catch (...) { return 1; }

    duk_uarridx_t out_i = 0;
    for (int idx = 1; idx < max_entries; ++idx) {
        uint8_t tag = tag_bytes[(size_t)idx];
        uint64_t raw = 0;
        std::memcpy(&raw, slot_bytes.data() + (size_t)idx * 8, 8);

        duk_idx_t o = duk_push_object(c);
        duk_push_int(c, idx); duk_put_prop_string(c, o, "idx");
        duk_push_int(c, tag); duk_put_prop_string(c, o, "tag");
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)raw);
        duk_push_string(c, buf); duk_put_prop_string(c, o, "raw");
        duk_put_prop_index(c, arr, out_i++);

        // Long/Double take 2 slots — skip the empty next entry.
        if (tag == 5 || tag == 6) ++idx;
    }
    return 1;
}

} // namespace

void register_cpdump_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_cpDump, 2);
    duk_put_prop_string(ctx, ns_idx, "_cpDump");
}

} // namespace marrow
