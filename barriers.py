"""GC write-barrier helpers — card table for generational / G1 collectors.

HotSpot generational and G1 GCs use a card table: the heap is sliced into
512-byte "cards", and when a reference is written into an older-gen object
the runtime writes `dirty = 0x00` at `byte_map_base[addr >> 9]`. On the
next young-gen collection the GC scans only dirty cards for inter-gen
pointers. If we mutate a reference without marking the card, the pointee
may be reclaimed while our reference still exists — a silent UAF.

Scope:
  * get_card_byte_map_base(vm)  — resolves byte_map_base across JDK 8..25.
  * mark_card_dirty(vm, addr)   — marks the card covering a mutated oop slot.

Limitations:
  * Works only when the active BarrierSet is a CardTableBarrierSet (default
    SerialGC / ParallelGC / G1). For ZGC / Shenandoah this is a no-op; those
    barriers are concurrent and colour-bit based, not documented here yet.
"""
from __future__ import annotations

from vm_meta import VMMeta, _ptr

# HotSpot constants — stable across JDK 8..25.
_CARD_SHIFT = 9      # 2^9 = 512 bytes per card
_CARD_DIRTY = 0x00   # CardTable::dirty_card_val()


def get_card_byte_map_base(vm: VMMeta) -> int:
    """Return the card-table byte_map_base address (pre-biased).

    Layout differs between JDK 8 and 11+:

      * JDK 8 — CollectedHeap::_barrier_set is a `CardTableModRefBS*`
        (or subclass), and its `byte_map_base` field is exposed directly.

      * JDK 11+ — A static `BarrierSet::_barrier_set` is downcast to a
        `CardTableBarrierSet*`. That holds `_card_table : CardTable*`, and
        `CardTable::_byte_map_base` gives the biased base.

    Returns 0 if the active BarrierSet isn't card-table-based (e.g. ZGC).
    """
    r = vm.reader
    bs_t = vm.type("BarrierSet") if vm.has_type("BarrierSet") else None
    if bs_t is not None and bs_t.has_field("_barrier_set"):
        # JDK 11+ path.
        bs = _ptr(r, bs_t.static_field("_barrier_set").address)
        if not bs:
            return 0
        if not (vm.has_type("CardTableBarrierSet") and vm.has_type("CardTable")):
            return 0
        ct_off = vm.type("CardTableBarrierSet").field("_card_table").offset
        ct = _ptr(r, bs + ct_off)
        if not ct:
            return 0
        bmb_off = vm.type("CardTable").field("_byte_map_base").offset
        return _ptr(r, ct + bmb_off)

    # JDK 8 path.
    if not (vm.has_type("CollectedHeap") and vm.has_type("Universe")
            and vm.type("Universe").has_field("_collectedHeap")):
        return 0
    heap = _ptr(r, vm.type("Universe").static_field("_collectedHeap").address)
    if not heap:
        return 0
    bs_off = vm.type("CollectedHeap").field("_barrier_set").offset
    bs = _ptr(r, heap + bs_off)
    if not bs:
        return 0
    # CardTableModRefBS::byte_map_base (JDK 8 name, no leading underscore).
    if vm.has_type("CardTableModRefBS") \
            and vm.type("CardTableModRefBS").has_field("byte_map_base"):
        bmb_off = vm.type("CardTableModRefBS").field("byte_map_base").offset
        return _ptr(r, bs + bmb_off)
    return 0


def mark_card_dirty(vm: VMMeta, byte_map_base: int, addr: int) -> None:
    """Mark the card covering `addr` as dirty, so the next young GC will
    scan this card for inter-generational references.

    No-op if byte_map_base is 0 (non-card-table BarrierSet such as ZGC).
    """
    if not byte_map_base:
        return
    card_byte = byte_map_base + (addr >> _CARD_SHIFT)
    # card_byte is a valid pointer inside the card-table region; RPM write
    # will bypass normal write barriers in the target (which is the point).
    vm.reader.write(card_byte, bytes([_CARD_DIRTY]))
