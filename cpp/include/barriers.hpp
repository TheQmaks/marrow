#pragma once
// Card-table write barrier helpers for Serial/Parallel/G1. HotSpot slices
// the heap into 512-byte cards; writing a reference into an old-gen object
// sets `byte_map_base[addr >> 9] = 0x00` so the next young GC scans the
// card. Skipping this mark is a silent UAF risk.
//
// ZGC / Shenandoah use barrier-set mechanisms that don't live in a card
// table; `get_card_byte_map_base` returns 0 for them and mark becomes a
// no-op.

#include "vm_meta.hpp"
#include <cstdint>

namespace marrow {

// Return the pre-biased byte_map_base, or 0 if the active BarrierSet
// isn't card-table-based. Walks two known layouts:
//   JDK 11+: BarrierSet::_barrier_set -> CardTableBarrierSet::_card_table
//            -> CardTable::_byte_map_base
//   JDK 8  : CollectedHeap::_barrier_set -> CardTableModRefBS::byte_map_base
uint64_t get_card_byte_map_base(VMMeta* vm);

// Mark the card covering `addr` as dirty. No-op if byte_map_base is 0.
void mark_card_dirty(VMMeta* vm, uint64_t byte_map_base, uint64_t addr);

} // namespace marrow
