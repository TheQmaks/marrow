#include "oop_reader.hpp"
#include <cstring>
#include <stdexcept>
#include <tuple>

namespace marrow {

// Candidate (type, base_field, shift_field) tuples, probed in order.
static const std::vector<std::tuple<const char*, const char*, const char*>> OOP_CANDS = {
    {"CompressedOops", "_base",             "_shift"},             // JDK 25
    {"CompressedOops", "_narrow_oop._base", "_narrow_oop._shift"}, // JDK 17/21
    {"Universe",       "_narrow_oop._base", "_narrow_oop._shift"}, // JDK 8/11
};

static const std::vector<std::tuple<const char*, const char*, const char*>> KLASS_CANDS = {
    {"CompressedKlassPointers", "_base",               "_shift"},
    {"CompressedKlassPointers", "_narrow_klass._base", "_narrow_klass._shift"},
    {"Universe",                "_narrow_klass._base", "_narrow_klass._shift"},
};

NarrowParams OopDecoder::resolve_params(
    const std::vector<std::tuple<const char*, const char*, const char*>>& cands)
{
    for (auto& c : cands) {
        auto [tn, bf, sf] = c;
        if (!vm_->has_type(tn)) continue;
        const TypeInfo* t = vm_->type(tn);
        if (!t->has_field(bf) || !t->has_field(sf)) continue;
        uint64_t base = r_->read_u64(t->field(bf)->address);
        int32_t  shift = r_->read_i32(t->field(sf)->address);
        return NarrowParams{base, shift};
    }
    return NarrowParams{};
}

OopDecoder::OopDecoder(VMMeta* vm)
    : vm_(vm), r_(vm->reader())
{
    oop_params   = resolve_params(OOP_CANDS);
    klass_params = resolve_params(KLASS_CANDS);
    has_compressed_oops_type_ = vm_->has_type("CompressedOops");
    if (auto* k = vm_->type("Klass")) {
        if (auto* f = k->field("_name")) name_offset_ = f->offset;
    }
    prime_from_static();
}

uint64_t OopDecoder::probe_heap_base()
{
    const TypeInfo* u = vm_->type("Universe");
    if (!u || !u->has_field("_collectedHeap")) return 0;
    uint64_t heap = 0;
    try {
        heap = r_->read_u64(u->field("_collectedHeap")->address);
    } catch (...) { return 0; }
    if (!heap) return 0;
    const TypeInfo* ch = vm_->type("CollectedHeap");
    if (!ch || !ch->has_field("_reserved")) return 0;
    try {
        return r_->read_u64(heap + ch->field("_reserved")->offset);
    } catch (...) { return 0; }
}

uint64_t OopDecoder::probe_live_oop()
{
    const TypeInfo* u = vm_->type("Universe");
    if (!u) return 0;
    for (const char* name : {"_main_thread_group", "_system_thread_group"}) {
        if (!u->has_field(name)) continue;
        const FieldInfo* f = u->field(name);
        uint64_t val = 0;
        try { val = r_->read_u64(f->address); } catch (...) { continue; }
        if (!val) continue;
        if (f->type_string == "OopHandle") {
            try { val = r_->read_u64(val); } catch (...) { continue; }
        }
        if (val) return val;
    }
    return 0;
}

void OopDecoder::prime_from_static()
{
    uint64_t heap_base = probe_heap_base();
    if (oop_params.enabled()) {
        oops_compressed_ = true;
    } else if (heap_base) {
        oops_compressed_ = heap_base <= 0xFFFFFFFFu;
    }
    uint64_t oop_val = probe_live_oop();
    if (oop_val) {
        try { klass_of(oop_val); } catch (...) {}
    }
    if (!compressed_klass_.has_value()) {
        // Klass compression is independent of oop compression; rely on
        // the klass_params base/shift metadata as the authoritative signal.
        compressed_klass_ = klass_params.enabled();
    }
}

bool OopDecoder::oops_are_compressed()
{
    if (oops_compressed_.has_value()) return *oops_compressed_;
    if (oop_params.enabled()) { oops_compressed_ = true; return true; }
    uint64_t heap_base = probe_heap_base();
    if (heap_base) {
        oops_compressed_ = heap_base <= 0xFFFFFFFFu;
    } else {
        oops_compressed_ = has_compressed_oops_type_ && compressed_klass_.value_or(false);
    }
    return *oops_compressed_;
}

uint32_t OopDecoder::encode_oop(uint64_t wide) const
{
    if (wide == 0) return 0;
    uint64_t narrow = (wide - oop_params.base) >> oop_params.shift;
    if (narrow > 0xFFFFFFFFull)
        throw std::runtime_error("wide oop outside narrow range");
    return static_cast<uint32_t>(narrow);
}

uint64_t OopDecoder::deref_oop_handle(uint64_t obj_slot_ptr)
{
    if (!obj_slot_ptr) return 0;
    return r_->read_u64(obj_slot_ptr);
}

uint64_t OopDecoder::resolve_forwarding(uint64_t oop_addr)
{
    if (!oop_addr) return 0;
    uint64_t mark = 0;
    try { mark = r_->read_u64(oop_addr); } catch (...) { return oop_addr; }
    if ((mark & 0x3) == 0x2) {
        uint64_t fwd = mark & ~uint64_t(0x3);
        if (fwd && fwd != oop_addr) return fwd;
    }
    return oop_addr;
}

uint64_t OopDecoder::klass_of(uint64_t oop_addr)
{
    if (!oop_addr) return 0;
    oop_addr = resolve_forwarding(oop_addr);
    uint64_t slot = oop_addr + klass_slot_offset_;
    if (!compressed_klass_.has_value()) compressed_klass_ = probe_klass_mode(slot);
    if (*compressed_klass_) return decode_klass(r_->read_u32(slot));
    return r_->read_u64(slot);
}

bool OopDecoder::probe_klass_mode(uint64_t slot)
{
    try {
        uint32_t narrow = r_->read_u32(slot);
        if (narrow && klass_looks_valid(decode_klass(narrow))) return true;
    } catch (...) {}
    try {
        uint64_t wide = r_->read_u64(slot);
        if (wide && klass_looks_valid(wide)) return false;
    } catch (...) {}
    return klass_params.enabled();
}

bool OopDecoder::klass_looks_valid(uint64_t klass_ptr)
{
    if (!klass_ptr || klass_ptr < 0x10000) return false;
    try {
        uint64_t name_ptr = r_->read_u64(klass_ptr + name_offset_);
        if (!name_ptr || name_ptr < 0x10000) return false;
        const TypeInfo* sym = vm_->type("Symbol");
        if (!sym || !sym->has_field("_length")) return false;
        uint16_t length = r_->read_u16(name_ptr + sym->field("_length")->offset);
        return length > 0 && length < 2048;
    } catch (...) {
        return false;
    }
}

} // namespace marrow
