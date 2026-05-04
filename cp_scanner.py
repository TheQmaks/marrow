"""ConstantPool scanner: enumerate existing entries by tag + resolve
references back to their Symbol strings. Lets us find which CP index
holds e.g. Methodref for `java.lang.Thread.sleep(J)V`, so we can reuse
the resolution chain (or duplicate it into an extended slot).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from collections.abc import Iterator

from vm_meta import VMMeta, _i32, _ptr
from walker import read_symbol

# CP tag constants (from metaspace.py, re-exported for convenience)
JVM_CONSTANT_Utf8 = 1
JVM_CONSTANT_Class = 7
JVM_CONSTANT_Fieldref = 9
JVM_CONSTANT_Methodref = 10
JVM_CONSTANT_InterfaceMethodref = 11
JVM_CONSTANT_NameAndType = 12
JVM_CONSTANT_ClassResolved = 0x67  # HotSpot internal: tag 7 | 0x60 when resolved


@dataclass
class CPEntry:
    index: int
    tag: int
    raw_u64: int     # raw 8 bytes of the slot


@dataclass
class ResolvedMethodref:
    index: int
    class_index: int
    nat_index: int
    class_name: str
    method_name: str
    signature: str


def iterate_cp(vm: VMMeta, cp_ptr: int) -> Iterator[CPEntry]:
    r = vm.reader
    cp_t = vm.type("ConstantPool")
    header_size = cp_t.size
    length = _i32(r, cp_ptr + cp_t.field("_length").offset)
    tags_ptr = _ptr(r, cp_ptr + cp_t.field("_tags").offset)
    # tags Array<u1>: length @0, data @4
    tag_bytes = r.read(tags_ptr + 4, length)
    slots = r.read(cp_ptr + header_size, length * 8)
    for i in range(length):
        raw = struct.unpack_from("<Q", slots, i * 8)[0]
        yield CPEntry(index=i, tag=tag_bytes[i], raw_u64=raw)


def utf8_symbol(vm: VMMeta, cp_ptr: int, index: int) -> str:
    """Resolve a Utf8 CP slot to its string content. Returns "" for
    non-Utf8 tags or unresolved entries."""
    r = vm.reader
    cp_t = vm.type("ConstantPool")
    slot_addr = cp_ptr + cp_t.size + index * 8
    sym_ptr = _ptr(r, slot_addr)
    if not sym_ptr:
        return ""
    return read_symbol(vm, r, sym_ptr)


def class_name(vm: VMMeta, cp_ptr: int, index: int) -> str:
    """Return the FQN for a Class CP entry.

    HotSpot's `CPSlot` encodes:
      * `raw & 1 == 1` -> unresolved; the value with the low bit cleared
        is a Symbol* pointing at the class name.
      * `raw & 1 == 0`, 8-aligned -> resolved; Klass*. Follow Klass::_name.
      * Anything else -> probably a raw u2 name_index (older encoding).
    We try paths in that order and catch memory-read errors as "unknown".
    """
    r = vm.reader
    cp_t = vm.type("ConstantPool")
    slot = cp_ptr + cp_t.size + index * 8
    try:
        raw = _ptr(r, slot)
    except OSError:
        return ""
    if raw == 0:
        return ""
    # Unresolved class: low bit flag, Symbol* in the rest.
    if raw & 1:
        try:
            return read_symbol(vm, r, raw & ~1)
        except OSError:
            return ""
    # Resolved Klass*: must be 8-aligned and heap-ish.
    if (raw & 0x7) == 0 and raw > 0x10000:
        klass_t = vm.type("Klass")
        name_off = klass_t.field("_name").offset
        try:
            sym = _ptr(r, raw + name_off)
            if sym:
                return read_symbol(vm, r, sym)
        except OSError:
            pass
    # Fallback: slot low u2 = name_index in original (pre-resolution) CP.
    return utf8_symbol(vm, cp_ptr, raw & 0xFFFF)


def resolve_methodref(vm: VMMeta, cp_ptr: int,
                       index: int) -> ResolvedMethodref | None:
    """Decode the Methodref at `index` into (class_name, method_name, sig).

    Returns None if any slot lookup fails (unresolved pieces or corrupt CP).
    """
    try:
        r = vm.reader
        cp_t = vm.type("ConstantPool")
        slot = cp_ptr + cp_t.size + index * 8
        raw = struct.unpack_from("<Q", r.read(slot, 8))[0]
        class_idx = raw & 0xFFFF
        nat_idx = (raw >> 16) & 0xFFFF
        cls = class_name(vm, cp_ptr, class_idx)
        nat_slot = cp_ptr + cp_t.size + nat_idx * 8
        nat_raw = struct.unpack_from("<Q", r.read(nat_slot, 8))[0]
        name_idx = nat_raw & 0xFFFF
        sig_idx = (nat_raw >> 16) & 0xFFFF
        name = utf8_symbol(vm, cp_ptr, name_idx)
        sig = utf8_symbol(vm, cp_ptr, sig_idx)
        return ResolvedMethodref(index=index, class_index=class_idx,
                                  nat_index=nat_idx, class_name=cls,
                                  method_name=name, signature=sig)
    except OSError:
        return None


def find_methodref(vm: VMMeta, cp_ptr: int,
                    class_name_want: str, method_name_want: str,
                    signature_want: str) -> ResolvedMethodref | None:
    """Scan CP for a Methodref matching `(class, name, sig)`. If
    `class_name_want` is "" we ignore class and match only on
    method+signature — useful when resolved Class slots can't be decoded
    through our scanner (the Klass* shape varies in uncommon configs).
    """
    for entry in iterate_cp(vm, cp_ptr):
        if entry.tag != JVM_CONSTANT_Methodref:
            continue
        m = resolve_methodref(vm, cp_ptr, entry.index)
        if not m:
            continue
        if m.method_name != method_name_want:
            continue
        if m.signature != signature_want:
            continue
        if class_name_want and m.class_name != class_name_want:
            continue
        return m
    return None
