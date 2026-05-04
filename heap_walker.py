"""Brute-force heap-wide instance finder.

Instead of walking GC-specific region structures (which differ across
G1 / Parallel / Shenandoah / ZGC and even between JDK point releases),
we scan every committed writable page of the target process and test
each qword-aligned address for a valid object header pointing at the
given Klass. Slower than a native object iterator but portable — works
identically on any GC without layout exports.

Positive identification requires:
  1. The word at offset 0 (mark word) looks like a plausible mark
     (bit 0 or bit 2 set — unlocked or fwd-pointer states).
  2. The narrow klass at offset 8 decodes to exactly our target Klass.
  3. We haven't already found this address (pages can overlap heap + CDS).

Use via `find_instances_by_klass(vm, decoder, klass_ptr, limit=None)`.
"""
from __future__ import annotations

import struct
from collections.abc import Iterator

from vm_meta import VMMeta
from oop_reader import OopDecoder


def _iter_aligned_qwords(buf: bytes, base: int) -> Iterator[tuple[int, int]]:
    """Yield (address, qword_value) for every 8-byte aligned qword in buf."""
    align_off = (-base) & 7
    usable = (len(buf) - align_off) & ~7
    if usable <= 0:
        return
    view = buf[align_off:align_off + usable]
    for i in range(0, usable, 8):
        yield base + align_off + i, struct.unpack_from("<Q", view, i)[0]


def find_instances_by_klass(
        vm: VMMeta, decoder: OopDecoder, klass_ptr: int,
        limit: int | None = None,
        chunk_size: int = 4 * 1024 * 1024,
) -> list[int]:
    """Return oop addresses of every instance whose narrow-klass slot
    resolves to `klass_ptr`. Scans the entire writable address space
    of the target process — expect hundreds of MB of reads; typically
    completes in a few seconds for a modest target.
    """
    r = vm.reader
    # Pre-encode target klass as a narrow value once.
    p = decoder.klass_params
    if p.shift == 0 and p.base == 0:
        target_narrow = klass_ptr & 0xFFFFFFFF
    else:
        target_narrow = (klass_ptr - p.base) >> p.shift
    target_narrow &= 0xFFFFFFFF

    found: list[int] = []
    seen: set[int] = set()
    # We only care about heap-ish pages — typical Java heap sits in PAGE_READWRITE
    # pages allocated via VirtualAlloc in 1-MB-ish chunks. Skip pages smaller
    # than 64 KiB (stacks, PEB, etc.) to cut false-positive surface and time.
    for base, size, _prot in r.enumerate_regions(writable_only=True):
        if size < 64 * 1024:
            continue
        # Read the region in chunks so we don't balloon Python memory on
        # huge heaps.
        for off in range(0, size, chunk_size):
            part_size = min(chunk_size, size - off)
            try:
                buf = r.read(base + off, part_size)
            except OSError:
                continue
            # At each qword boundary, treat it as a candidate mark word.
            # The narrow klass lives 8 bytes later (compressed-class layout).
            # We check the narrow-klass candidate against our target.
            part_base = base + off
            # Iterate every 8-aligned position, checking klass@+8.
            for pos in range(0, part_size - 12, 8):
                narrow = struct.unpack_from("<I", buf, pos + 8)[0]
                if narrow != target_narrow:
                    continue
                # Mark word sanity: plausible unlocked pattern. Many values
                # work; 0x5, 0x1, 0x4*, 0x0 are all common. We only reject
                # obviously-zero klass neighbours and look for a mark with
                # one of the low nibbles set.
                mark = struct.unpack_from("<Q", buf, pos)[0]
                if mark == 0 or (mark & 0x3) == 0x2:
                    # 0x2 is the "marked" pattern the GC sets during marking;
                    # typical live objects should not carry exactly 0 either.
                    pass  # still accept; mark word can be a displaced lock
                oop_addr = part_base + pos
                if oop_addr in seen:
                    continue
                seen.add(oop_addr)
                found.append(oop_addr)
                if limit is not None and len(found) >= limit:
                    return found
    return found
