#include "barriers.hpp"

namespace marrow {

static constexpr int  CARD_SHIFT = 9;
static constexpr uint8_t CARD_DIRTY = 0x00;

uint64_t get_card_byte_map_base(VMMeta* vm)
{
    Reader* r = vm->reader();
    const TypeInfo* bs_t = vm->type("BarrierSet");
    if (bs_t && bs_t->has_field("_barrier_set")) {
        // JDK 11+ path.
        uint64_t bs = r->read_u64(bs_t->field("_barrier_set")->address);
        if (!bs) return 0;
        const TypeInfo* ctbs = vm->type("CardTableBarrierSet");
        const TypeInfo* ct_t = vm->type("CardTable");
        if (!ctbs || !ct_t) return 0;
        // The installed BarrierSet may not be a CardTableBarrierSet (Shen,
        // ZGC, Epsilon). Reading the `_card_table` offset against a non-CT
        // subclass yields garbage; guard with a pointer-plausibility check
        // (user-mode VA tops out at 0x7FFF'FFFF'FFFF on x64).
        auto plausible = [](uint64_t p) {
            return p >= 0x10000 && p < 0x7FFFFFFFFFFFull;
        };
        uint64_t ct = 0;
        try {
            ct = r->read_u64(bs + ctbs->field("_card_table")->offset);
        } catch (...) { return 0; }
        if (!plausible(ct)) return 0;
        try {
            uint64_t base = r->read_u64(ct + ct_t->field("_byte_map_base")->offset);
            return plausible(base) ? base : 0;
        } catch (...) { return 0; }
    }

    // JDK 8 path.
    const TypeInfo* u = vm->type("Universe");
    const TypeInfo* ch = vm->type("CollectedHeap");
    if (!u || !ch || !u->has_field("_collectedHeap")) return 0;
    uint64_t heap = r->read_u64(u->field("_collectedHeap")->address);
    if (!heap) return 0;
    if (!ch->has_field("_barrier_set")) return 0;
    uint64_t bs = r->read_u64(heap + ch->field("_barrier_set")->offset);
    if (!bs) return 0;
    const TypeInfo* ctmb = vm->type("CardTableModRefBS");
    if (!ctmb || !ctmb->has_field("byte_map_base")) return 0;
    return r->read_u64(bs + ctmb->field("byte_map_base")->offset);
}

void mark_card_dirty(VMMeta* vm, uint64_t byte_map_base, uint64_t addr)
{
    if (!byte_map_base) return;
    uint64_t card_byte = byte_map_base + (addr >> CARD_SHIFT);
    uint8_t dirty = CARD_DIRTY;
    vm->reader()->write(card_byte, &dirty, 1);
}

} // namespace marrow
