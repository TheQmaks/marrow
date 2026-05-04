"""Locate per-JavaThread SATB queue by plausibility scan.

Shenandoah (and G1 in earlier JDKs) keep a per-thread `SATBMarkQueue`
nested inside `ShenandoahThreadLocalData` / `G1ThreadLocalData`, which
the JVM stores in the trailing `_gc_data` region of `JavaThread`. That
outer offset isn't exported to vmStructs on any JDK >= 11, so we scan
the region between `last_known_field_end` and `sizeof(JavaThread)` for
a qword sequence that fits a SATBMarkQueue layout:

    offset 0:   _index (size_t)  — 0 or a small count
    offset 16:  _buf  (void**)   — NULL or plausible heap/C heap pointer
    offset 24:  _active (bool)   — 0 or 1 in the low byte

Any hit is verified by checking the low byte of `_active` and rejecting
_buf values whose numeric ranges are implausible. Typical result: one
match per JavaThread tail. If several candidates survive, we keep the
first — caller can tighten via `max_candidates=0` to get the list.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from vm_meta import VMMeta


@dataclass
class SATBQueueProbe:
    offset_in_thread: int
    index: int
    buf: int
    active: bool


def _sizeof_satb_queue(vm: VMMeta) -> int:
    if vm.has_type("SATBMarkQueue"):
        return vm.type("SATBMarkQueue").size
    return 32  # sensible default for JDK 11..21


def _ptrqueue_field_offsets(vm: VMMeta) -> tuple[int, int]:
    """Return (`_index` offset, `_buf` offset) within the PtrQueue base."""
    if not vm.has_type("PtrQueue"):
        return (0, 16)
    pq = vm.type("PtrQueue")
    idx = pq.field("_index").offset if pq.has_field("_index") else 0
    buf = pq.field("_buf").offset if pq.has_field("_buf") else 16
    return (idx, buf)


def _satb_active_offset(vm: VMMeta) -> int:
    if vm.has_type("SATBMarkQueue") \
            and vm.type("SATBMarkQueue").has_field("_active"):
        return vm.type("SATBMarkQueue").field("_active").offset
    return 24


def _last_known_field_end(vm: VMMeta) -> int:
    """Highest byte offset of any JavaThread (or Thread) field actually
    exported. _gc_data lives somewhere past this — the gap between this
    and sizeof(JavaThread) is our scan window."""
    high = 0
    for tname in ("JavaThread", "Thread"):
        if not vm.has_type(tname):
            continue
        for f in vm.type(tname).fields():
            if f.is_static:
                continue
            high = max(high, f.offset + 8)  # conservative +8 for size-less types
    return high


def find_satb_queue(vm: VMMeta, java_thread: int,
                    max_candidates: int = 1) -> list[SATBQueueProbe]:
    """Scan the `_gc_data` region of a JavaThread for a plausible SATB
    queue. Returns up to `max_candidates` matches in ascending offset
    order (0 = unlimited)."""
    r = vm.reader
    sz = vm.type("JavaThread").size
    gap_start = _last_known_field_end(vm)
    gap_len = sz - gap_start
    if gap_len <= 0:
        return []
    q_size = _sizeof_satb_queue(vm)
    idx_off, buf_off = _ptrqueue_field_offsets(vm)
    act_off = _satb_active_offset(vm)

    region = r.read(java_thread + gap_start, gap_len)
    out: list[SATBQueueProbe] = []
    # Align to 8 — SATBMarkQueue is qword-aligned as a struct member.
    for pos in range(0, gap_len - q_size, 8):
        index_val = struct.unpack_from("<Q", region, pos + idx_off)[0]
        buf_val   = struct.unpack_from("<Q", region, pos + buf_off)[0]
        active_byte = region[pos + act_off]
        # Plausibility filters:
        # - _active must be 0 or 1
        # - _buf must be NULL or look like a pointer (0x1000+)
        # - _index must be non-absurd: either 0, a small sensible count,
        #   or the "empty" sentinel encoded as ~0 / cached-0
        if active_byte not in (0, 1):
            continue
        if buf_val != 0 and buf_val < 0x10000:
            continue
        if index_val > (1 << 40) and index_val != 0xFFFFFFFFFFFFFFFF:
            # Index above 1 TB is absurd; sentinel is typically u64-max
            # or buffer-size-aligned.
            continue
        out.append(SATBQueueProbe(
            offset_in_thread=gap_start + pos,
            index=index_val,
            buf=buf_val,
            active=(active_byte == 1),
        ))
        if max_candidates and len(out) >= max_candidates:
            break
    return out
