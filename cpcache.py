"""Scan ConstantPoolCache entries to find the cache index corresponding
to an existing CP Methodref.

HotSpot rewrites bytecode at class-load time: `invokestatic #cp_idx`
becomes `invokestatic #cache_idx` where cache_idx is the position of
that call site in `ConstantPoolCache`. The cache entry stores the
original CP index in its `_indices` field (low 16 bits of one half).

Layout (JDK 17/21):
    ConstantPoolCache (MetaspaceObj)
      _length : int @ 0
      _constant_pool : ConstantPool* @ 8
      ... header padding ...
      CPCacheEntry[_length] inline, 32 bytes each, starting at sizeof(CPCache)

Each ConstantPoolCacheEntry:
    _indices : intx @ 0   -- packed bytecode + cp_index info
    _f1      : Metadata* @ 8  -- resolved Method* / Klass*
    _f2      : intx @ 16  -- secondary data
    _flags   : intx @ 24  -- tos + flags + count

`_indices` encoding (HotSpot rewriter, verified empirically):
    bits  0..15 : cp_index (u2, pointing at the original Methodref)
    bits 16..23 : b1        (original bytecode opcode, e.g. 0xB8 invokestatic)
    bits 24..31 : b2        (secondary rewrite byte, often 0)
On x64 intx is 8 bytes — only the low 32 bits are meaningful for
this packing.

JDK 25 removes inline ConstantPoolCacheEntry entirely and uses an
Array<ResolvedMethodEntry> on the cache. Handled separately.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from vm_meta import VMMeta, _i32, _ptr


@dataclass
class CacheEntryInfo:
    index: int
    indices_raw: int
    cp_index: int
    f1: int
    b1: int  # the original bytecode opcode (invokestatic = 0xB8)


def _cpcache_header_size(vm: VMMeta) -> int:
    if vm.has_type("ConstantPoolCache"):
        return vm.type("ConstantPoolCache").size
    return 32  # JDK 17 default


def find_cpcache(vm: VMMeta, cp_ptr: int) -> int:
    """Return ConstantPoolCache* that belongs to this ConstantPool."""
    return _ptr(vm.reader, cp_ptr + 16)  # stable `_cache` offset across JDKs


def iterate_cpcache_entries_legacy(vm: VMMeta, cpcache: int) -> list[CacheEntryInfo]:
    """Walk the inline ConstantPoolCacheEntry array for JDK 17/21."""
    if not vm.has_type("ConstantPoolCacheEntry"):
        return []  # JDK 25+: ConstantPoolCacheEntry was removed
    r = vm.reader
    length = _i32(r, cpcache + 0)
    header_size = _cpcache_header_size(vm)
    entries: list[CacheEntryInfo] = []
    entry_size = vm.type("ConstantPoolCacheEntry").size
    for i in range(length):
        base = cpcache + header_size + i * entry_size
        indices_raw = struct.unpack_from("<Q", r.read(base + 0, 8))[0]
        f1 = _ptr(r, base + 8)
        low = indices_raw & 0xFFFFFFFF
        cp_index = low & 0xFFFF
        b1 = (low >> 16) & 0xFF
        entries.append(CacheEntryInfo(
            index=i, indices_raw=indices_raw, cp_index=cp_index,
            f1=f1, b1=b1))
    return entries


def clone_and_extend_cpcache_legacy(
        vm: VMMeta, cp_ptr: int, extra_entries: int,
        new_cp_indices: list[tuple[int, int]],
        sigs: list[str | None] | None = None,
        is_static: list[bool] | None = None,
        override_f1: list[int] | None = None,
) -> tuple[int, int, list[int]]:
    """Clone the (legacy inline-entry) ConstantPoolCache with extra slots
    and redirect `ConstantPool::_cache` at the new one.

    Parameters
    ----------
    new_cp_indices : list of (cp_index, b1_opcode) for each new entry.
        Donor cache entry matching each (cp_index, b1) is used as the
        layout template (memcpy). Caller may then override per-entry:

    sigs : optional list of JVM method descriptors like "(J)V". When
        provided, `_flags` is re-synthesised from the descriptor
        (parameter size + TosState), leaving other bits inherited from
        the donor. Useful when the donor's signature differs from the
        method we really want to invoke at the new cache slot.
    is_static : optional list of bools paired with `sigs`; defaults True.
    override_f1 : optional per-entry Method* to install in `_f1`,
        replacing the donor's resolved Method pointer.

    Returns (old_cpcache_ptr, new_cpcache_ptr, new_entry_cache_indices).
    Only works on JDK with inline ConstantPoolCacheEntry (8/11/17/21).
    """
    from signature import synth_flags_legacy
    assert vm.has_type("ConstantPoolCacheEntry"), \
        "legacy inline CPCache layout not present"
    r = vm.reader
    cpcache_old = find_cpcache(vm, cp_ptr)
    if not cpcache_old:
        raise RuntimeError("CP has no cache to extend")

    header_size = _cpcache_header_size(vm)
    entry_size = vm.type("ConstantPoolCacheEntry").size
    old_len = _i32(r, cpcache_old + 0)
    assert len(new_cp_indices) == extra_entries

    new_len = old_len + extra_entries
    new_total = header_size + new_len * entry_size
    new_page = (new_total + 0xFFF) & ~0xFFF
    cpcache_new = r.alloc(new_page, executable=False)

    # Copy full header + existing entries.
    r.write(cpcache_new, r.read(cpcache_old, header_size + old_len * entry_size))
    # Patch _length in clone.
    r.write(cpcache_new + 0, struct.pack("<i", new_len))
    # Append new entries in UNRESOLVED state.
    # For each requested new entry:
    #  1. copy donor bytes (matching on cp_index+b1) for layout/flags;
    #  2. optionally replace `_f1` with a caller-supplied Method*;
    #  3. optionally re-synthesize `_flags` from a descriptor.
    new_indices_out: list[int] = []
    existing = iterate_cpcache_entries_legacy(vm, cpcache_old)
    for i, (cp_idx, b1) in enumerate(new_cp_indices):
        # Donor matching: first a perfect (cp_idx, b1) donor; else any
        # resolved entry with matching b1 (for signature-synth path).
        donor = next((e for e in existing
                      if e.cp_index == cp_idx and e.b1 == b1), None)
        if donor is None and sigs and sigs[i]:
            donor = next((e for e in existing if e.b1 == b1 and e.f1 != 0),
                         None)
        if donor is None:
            raise RuntimeError(
                f"no existing CPCache donor for cp_idx={cp_idx} b1={b1:#x}"
                " — cannot extend cache without a resolved template")
        donor_slot = cpcache_old + header_size + donor.index * entry_size
        slot = cpcache_new + header_size + (old_len + i) * entry_size
        r.write(slot, r.read(donor_slot, entry_size))

        # Patch _indices to point at OUR cp_idx (donor may have different).
        donor_indices = _i32(r, slot + 0) & 0xFFFFFFFF  # low 32 bits only
        new_indices = (donor_indices & ~0xFFFF) | (cp_idx & 0xFFFF)
        # Preserve high half (possibly unused intx sign extension).
        orig64 = struct.unpack_from("<Q", r.read(slot + 0, 8))[0]
        new_u64 = (orig64 & ~0xFFFFFFFF) | new_indices
        r.write(slot + 0, struct.pack("<Q", new_u64))

        # Optionally replace _f1 with caller's Method*.
        if override_f1 and override_f1[i]:
            r.write(slot + 8, struct.pack("<Q", override_f1[i]))

        # Optionally synthesise _flags from a method descriptor.
        if sigs and sigs[i]:
            static_flag = (is_static[i] if is_static and i < len(is_static)
                           else True)
            donor_flags = struct.unpack_from("<Q", r.read(slot + 24, 8))[0]
            new_flags = synth_flags_legacy(donor_flags, sigs[i],
                                            is_static=static_flag)
            r.write(slot + 24, struct.pack("<Q", new_flags))

        new_indices_out.append(old_len + i)

    # Redirect CP._cache at the clone.
    r.write(cp_ptr + 16, struct.pack("<Q", cpcache_new))
    return cpcache_old, cpcache_new, new_indices_out


def clone_and_extend_cpcache_modern(
        vm: VMMeta, cp_ptr: int, extra_entries: int,
        new_cp_indices: list[int]
) -> tuple[int, int, list[int]]:
    """JDK 25 variant: the cache itself is untouched; we grow its
    `_resolved_method_entries : Array<ResolvedMethodEntry>*` by cloning
    the array into our page with `extra_entries` extra slots at the end.
    Each new slot is a byte-for-byte copy of an existing donor whose
    `_cpool_index` matches one of `new_cp_indices`, with only its own
    `_cpool_index` u2 overwritten. Returns
    (old_array_ptr, new_array_ptr, list_of_new_indices).
    """
    r = vm.reader
    if not vm.has_type("ResolvedMethodEntry"):
        raise RuntimeError("modern ResolvedMethodEntry layout not in vmStructs")

    cpcache = find_cpcache(vm, cp_ptr)
    if not cpcache:
        raise RuntimeError("CP has no cache")
    cc_t = vm.type("ConstantPoolCache")
    rme_arr_off = cc_t.field("_resolved_method_entries").offset
    rme_arr_old = _ptr(r, cpcache + rme_arr_off)
    if not rme_arr_old:
        raise RuntimeError("no _resolved_method_entries to extend")

    rme_size = vm.type("ResolvedMethodEntry").size
    cpool_off = vm.type("ResolvedMethodEntry").field("_cpool_index").offset
    old_len = _i32(r, rme_arr_old + 0)
    new_len = old_len + extra_entries
    data_off = 8  # Array<T>::_data
    total = data_off + new_len * rme_size
    page = (total + 0xFFF) & ~0xFFF
    rme_arr_new = r.alloc(page, executable=False)

    # Header: _length as int @0; padding; data @8.
    r.write(rme_arr_new + 0, struct.pack("<i", new_len))
    r.write(rme_arr_new + data_off,
            r.read(rme_arr_old + data_off, old_len * rme_size))

    # Append donor-cloned entries.
    out: list[int] = []
    for i, cp_idx in enumerate(new_cp_indices):
        # Find donor entry with matching _cpool_index in old array.
        donor_bytes = None
        existing = r.read(rme_arr_old + data_off, old_len * rme_size)
        for j in range(old_len):
            e_cpool = struct.unpack_from("<H", existing,
                                          j * rme_size + cpool_off)[0]
            if e_cpool == cp_idx:
                donor_bytes = existing[j * rme_size:(j + 1) * rme_size]
                break
        if donor_bytes is None:
            raise RuntimeError(
                f"no ResolvedMethodEntry donor with cp_idx={cp_idx}")
        dest = rme_arr_new + data_off + (old_len + i) * rme_size
        r.write(dest, donor_bytes)
        # Donor's cp_index already equals cp_idx; leave it. The new
        # index into the array is what matters for dispatch.
        out.append(old_len + i)

    # Redirect the cache's Array<ResolvedMethodEntry>* at the clone.
    r.write(cpcache + rme_arr_off, struct.pack("<Q", rme_arr_new))
    return rme_arr_old, rme_arr_new, out


@dataclass
class CacheTemplate:
    """A resolved CPCache entry suitable for reuse as a layout template."""
    source_klass: int
    source_cache: int
    entry_bytes: bytes


def scan_all_caches_for_template(
        vm: VMMeta, bytecode: int, arg_count_hint: int = -1
) -> list[CacheTemplate]:
    """Walk every loaded InstanceKlass and pull out CPCache entries whose
    _indices match the given bytecode. Useful when the target class's own
    cache has no donor for the invoke we want to inject.

    Returns a list of raw entry bytes we can memcpy into a new cache slot.
    """
    from walker import ClassWalker
    r = vm.reader
    ik_t = vm.type("InstanceKlass")
    constants_off = ik_t.field("_constants").offset
    entry_size = (vm.type("ConstantPoolCacheEntry").size
                  if vm.has_type("ConstantPoolCacheEntry") else 32)
    results: list[CacheTemplate] = []
    for k in ClassWalker(vm):
        if k.kind != "instance":
            continue
        try:
            cp = _ptr(r, k.address + constants_off)
            if not cp:
                continue
            cc = find_cpcache(vm, cp)
            if not cc:
                continue
            hdr = _cpcache_header_size(vm)
            for e in iterate_cpcache_entries_legacy(vm, cc):
                if e.b1 != bytecode:
                    continue
                if e.f1 == 0:
                    continue  # skip unresolved donors
                slot = cc + hdr + e.index * entry_size
                results.append(CacheTemplate(
                    source_klass=k.address,
                    source_cache=cc,
                    entry_bytes=r.read(slot, entry_size)))
        except Exception:
            continue
    return results


def cache_index_for_cp(vm: VMMeta, cp_ptr: int, cp_index: int,
                       bytecode: int = 0xB8) -> int | None:
    """Return the CPCache index whose entry resolves CP[cp_index] for
    the given bytecode (default invokestatic).

    Covers both layouts:
      * JDK 17/21: inline ConstantPoolCacheEntry with _indices packing.
      * JDK 25+: Array<ResolvedMethodEntry>; we scan `_cpool_index`
        fields and return the array position. Bytecode discriminator
        doesn't apply — the new layout stores invoke kind separately.
    """
    cpcache = find_cpcache(vm, cp_ptr)
    if not cpcache:
        return None
    # Legacy inline entries.
    for e in iterate_cpcache_entries_legacy(vm, cpcache):
        if e.cp_index == cp_index and e.b1 == bytecode:
            return e.index
    # JDK 25+: Array<ResolvedMethodEntry>
    if vm.has_type("ResolvedMethodEntry") \
            and vm.has_type("ConstantPoolCache") \
            and vm.type("ConstantPoolCache").has_field("_resolved_method_entries"):
        r = vm.reader
        rme_arr_off = vm.type("ConstantPoolCache").field(
            "_resolved_method_entries").offset
        rme_arr = _ptr(r, cpcache + rme_arr_off)
        if not rme_arr:
            return None
        rme_len = _i32(r, rme_arr + 0)
        rme_size = vm.type("ResolvedMethodEntry").size
        cpool_off = vm.type("ResolvedMethodEntry").field("_cpool_index").offset
        data_off = 8  # Array<T>::_data for 8-byte-aligned types
        raw = r.read(rme_arr + data_off, rme_len * rme_size)
        for i in range(rme_len):
            cpool_idx_i = struct.unpack_from(
                "<H", raw, i * rme_size + cpool_off)[0]
            if cpool_idx_i == cp_index:
                return i
    return None
