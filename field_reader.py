"""InstanceKlass field-metadata reader.

Supports both formats HotSpot has shipped:
  * Legacy — `_fields : Array<u2>*` with 6 u2 slots per FieldInfo
             (JDK 8, 11, 17; layout stable since JDK 7).
  * Stream — `_fieldinfo_stream : Array<u1>*` using UNSIGNED5 variable-
             length encoding, introduced in JDK 18 and used by 21 / 25.

Both formats reference field names through a ConstantPool index; we resolve
Utf8 CP entries as Symbol* directly (Utf8 tag = 1). No Klass mutation is
performed — the reader is strictly passive.

Public entry points
-------------------
    read_fields(vm, klass_ptr)      -> list[FieldRecord]
    find_field(vm, klass_ptr, name) -> FieldRecord | None
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from vm_meta import VMMeta, Reader, _i32, _ptr
from walker import read_symbol


# --- UNSIGNED5 decoder (HotSpot utilities/unsigned5.hpp) ------------------
# One byte holds 6-bit "digit" (range 0..63) plus a 2-bit continuation tag.
# First byte of each value must be >= X; high bytes (>= X+L) continue, low
# bytes terminate. The decode sums weighted contributions up to 5 bytes.
_U5_X  = 1
_U5_L  = 191
_U5_LG_H = 6   # log2(64): each extra byte shifts by 6


def _u5_read(buf: bytes, pos: int) -> tuple[int, int]:
    """Decode one UNSIGNED5 integer from buf starting at pos. Returns
    (value, new_pos)."""
    b0 = buf[pos]
    if b0 == 0:
        # Terminator / null byte — caller treats as end-of-stream.
        return (0, pos + 1)
    s = b0 - _U5_X
    if s < _U5_L:
        return (s, pos + 1)
    lg = _U5_LG_H
    for i in range(1, 5):
        bi = buf[pos + i]
        s += (bi - _U5_X) << lg
        if bi < _U5_X + _U5_L or i == 4:
            return (s, pos + i + 1)
        lg += _U5_LG_H
    return (s, pos + 5)


# --- Array<T> helpers (HotSpot Array layout: int _length @0, _data @4) ---

def _read_u1_array(r: Reader, arr_ptr: int) -> bytes:
    if not arr_ptr:
        return b""
    length = _i32(r, arr_ptr + 0)
    if length <= 0:
        return b""
    return r.read(arr_ptr + 4, length)


def _read_u2_array(r: Reader, arr_ptr: int) -> list[int]:
    if not arr_ptr:
        return []
    length = _i32(r, arr_ptr + 0)
    if length <= 0:
        return []
    raw = r.read(arr_ptr + 4, length * 2)
    return list(struct.unpack(f"<{length}H", raw))


# --- ConstantPool access --------------------------------------------------

class _ConstantPool:
    """Resolves name_index → Symbol* → UTF-8 string.

    The pool is packed right after the C++ ConstantPool header, one 8-byte
    slot per entry. For Utf8 entries the slot holds a Symbol*; other tags
    hold different types, but for our needs (field and method names) Utf8
    is what we get.
    """

    def __init__(self, vm: VMMeta, cp_ptr: int):
        self._vm = vm
        self._r = vm.reader
        self._cp = cp_ptr
        self._header_size = vm.type("ConstantPool").size
        self._length = (_i32(self._r, cp_ptr + vm.type("ConstantPool").field("_length").offset)
                        if cp_ptr else 0)

    def symbol(self, index: int) -> str:
        if not self._cp or index <= 0 or index >= self._length:
            return ""
        try:
            sym_ptr = _ptr(self._r, self._cp + self._header_size + index * 8)
            if not sym_ptr or sym_ptr < 0x10000:
                return ""
            return read_symbol(self._vm, self._r, sym_ptr)
        except OSError:
            # CP slot held a non-Symbol payload (other tag), or a stale
            # pointer — treat as "no name" so the caller can skip this field.
            return ""


# --- FieldRecord + format dispatch ----------------------------------------

# Stream-format `field_flags` bits documented in fieldInfo.hpp; only the
# ones that affect payload length matter here.
_FF_INITIALIZED = 1 << 0
_FF_GENERIC     = 1 << 2
_FF_CONTENDED   = 1 << 4


@dataclass(frozen=True)
class FieldRecord:
    name: str
    signature: str
    access_flags: int
    offset: int
    is_static: bool     # bit 0x0008 (ACC_STATIC)

    def __repr__(self) -> str:
        tag = "static" if self.is_static else f"offset={self.offset}"
        return f"Field({self.name!r}:{self.signature}, {tag})"


def read_fields(vm: VMMeta, klass_ptr: int) -> list[FieldRecord]:
    """Enumerate every declared field of an InstanceKlass."""
    if not klass_ptr:
        return []
    r = vm.reader
    ik = vm.type("InstanceKlass")
    cp_ptr = _ptr(r, klass_ptr + ik.field("_constants").offset)
    cp = _ConstantPool(vm, cp_ptr)

    if ik.has_field("_fieldinfo_stream"):
        return _read_stream(vm, klass_ptr, ik, cp)
    if ik.has_field("_fields"):
        return _read_legacy(vm, klass_ptr, ik, cp)
    return []


def find_field(vm: VMMeta, klass_ptr: int, name: str) -> FieldRecord | None:
    for f in read_fields(vm, klass_ptr):
        if f.name == name:
            return f
    return None


# --- Legacy format (JDK 8/11/17) -----------------------------------------
# 6 u2 slots per field: [access_flags, name_idx, sig_idx, initval_idx,
#                        low_packed, high_packed]
# offset = ((high << 16) | low) >> 2   (bottom 2 bits are tag flags)

_LEGACY_SLOTS_PER_FIELD = 6
_LEGACY_TAG_SIZE = 2

def _read_legacy(vm: VMMeta, klass_ptr: int, ik, cp: _ConstantPool) -> list[FieldRecord]:
    r = vm.reader
    arr_ptr = _ptr(r, klass_ptr + ik.field("_fields").offset)
    words = _read_u2_array(r, arr_ptr)
    out: list[FieldRecord] = []
    # Trailing extra u2s can appear (generic signature table or similar);
    # only whole 6-slot records are decoded.
    for start in range(0, (len(words) // _LEGACY_SLOTS_PER_FIELD) * _LEGACY_SLOTS_PER_FIELD,
                       _LEGACY_SLOTS_PER_FIELD):
        access_flags = words[start + 0]
        name_idx     = words[start + 1]
        sig_idx      = words[start + 2]
        low          = words[start + 4]
        high         = words[start + 5]
        packed = (high << 16) | low
        offset = packed >> _LEGACY_TAG_SIZE
        out.append(FieldRecord(
            name=cp.symbol(name_idx),
            signature=cp.symbol(sig_idx),
            access_flags=access_flags,
            offset=offset,
            is_static=(access_flags & 0x0008) != 0,
        ))
    return out


# --- Stream format (JDK 18+) ---------------------------------------------
# Header: num_java_fields, num_injected_fields (UNSIGNED5 uints)
# Per field (UNSIGNED5 uints): name_idx, sig_idx, offset, access_flags,
#                              field_flags, [initval]?, [gsig]?, [group]?
# Terminator: single null byte (0x00) — UNSIGNED5 never produces one.

def _read_stream(vm: VMMeta, klass_ptr: int, ik, cp: _ConstantPool) -> list[FieldRecord]:
    r = vm.reader
    arr_ptr = _ptr(r, klass_ptr + ik.field("_fieldinfo_stream").offset)
    buf = _read_u1_array(r, arr_ptr)
    if not buf:
        return []

    pos = 0
    num_java, pos = _u5_read(buf, pos)
    num_injected, pos = _u5_read(buf, pos)
    total = num_java + num_injected

    out: list[FieldRecord] = []
    for _ in range(total):
        if pos >= len(buf):
            break
        name_idx, pos     = _u5_read(buf, pos)
        sig_idx, pos      = _u5_read(buf, pos)
        offset, pos       = _u5_read(buf, pos)
        access_flags, pos = _u5_read(buf, pos)
        field_flags, pos  = _u5_read(buf, pos)
        if field_flags & _FF_INITIALIZED:
            _initval, pos = _u5_read(buf, pos)
        if field_flags & _FF_GENERIC:
            _gsig, pos    = _u5_read(buf, pos)
        if field_flags & _FF_CONTENDED:
            _group, pos   = _u5_read(buf, pos)
        out.append(FieldRecord(
            name=cp.symbol(name_idx),
            signature=cp.symbol(sig_idx),
            access_flags=access_flags,
            offset=offset,
            is_static=(access_flags & 0x0008) != 0,
        ))
    return out
