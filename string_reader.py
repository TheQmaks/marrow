"""java.lang.String reader.

Decodes a live String oop into a Python str using the target VM's
String layout. Handles both pre-Compact-Strings (JDK 8: char[] in `value`)
and Compact-Strings (JDK 9+: byte[] in `value` with `coder` picking Latin1
vs UTF-16-LE).

Layout introspection is fully dynamic — offsets come from the target VM's
field metadata via field_reader, so version drift is absorbed automatically.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from vm_meta import VMMeta, _i32, _ptr
from field_reader import find_field
from oop_reader import OopDecoder
from walker import ClassWalker
from zgc import ZGCDecoder


# Java element type sizes (for typeArrayOop layout). The header is always
# mark(8) + klass(4 or 8) + array_length(4) and data starts 8-byte aligned
# after that. We probe both alignments at read time.


@dataclass
class _StringLayout:
    """Cached per-VMMeta offsets for the String/byte[]/char[] trio."""
    value_offset: int            # String.value (reference)
    coder_offset: int | None  # String.coder (byte), None on JDK 8 pre-Compact Strings
    array_length_offset: int     # offset of length field inside array oop
    array_data_offset: int       # offset of first element inside array oop


def _find_klass_by_name(vm: VMMeta, name: str) -> int:
    """Scan the CLDG/SystemDictionary for the named class, return Klass*."""
    for k in ClassWalker(vm):
        if k.name == name:
            return k.address
    return 0


def _build_layout(vm: VMMeta) -> _StringLayout:
    string_klass = _find_klass_by_name(vm, "java/lang/String")
    if not string_klass:
        raise RuntimeError("java/lang/String not loaded in target")

    value_field = find_field(vm, string_klass, "value")
    if value_field is None:
        raise RuntimeError("java/lang/String has no `value` field")
    coder_field = find_field(vm, string_klass, "coder")  # JDK 9+

    # Array header layout: typeArrayOop / objArrayOop share the same prefix.
    # HotSpot's header is: mark(8) + klass(narrow=4 or wide=8) + length(4).
    # When compressed class pointers are on (default), klass is 4 bytes and
    # length lands at offset 12; then data is 8-byte aligned to 16.
    # Otherwise length lands at 16 and data at 24. The decoder probes.
    return _StringLayout(
        value_offset=value_field.offset,
        coder_offset=coder_field.offset if coder_field else None,
        array_length_offset=12,   # will be re-verified per call
        array_data_offset=16,
    )


def _array_header_offsets(oop_decoder: OopDecoder) -> tuple[int, int]:
    """Return (length_offset, data_offset) for typeArrayOop/objArrayOop.

    Depends on compressed class pointers, which the decoder already probed.
    """
    if oop_decoder._compressed_klass:
        return (12, 16)
    return (16, 24)


class StringReader:
    """Cache layout once, decode many Strings from the same target VM.

    Under ZGC the `value` reference field (and the String oop we get
    passed) carry colour bits that must be stripped before dereference.
    Pass a ZGCDecoder built from the same VMMeta if the target might be
    running under ZGC; otherwise it's optional and the reader falls
    through to standard compressed/wide oop decoding.
    """

    def __init__(self, vm: VMMeta, oop_decoder: OopDecoder,
                 zgc: ZGCDecoder | None = None):
        self._vm = vm
        self._r = vm.reader
        self._oop = oop_decoder
        self._zgc = zgc if (zgc is not None and zgc.is_active) else None
        self._layout = _build_layout(vm)

    def read(self, string_oop: int, max_bytes: int = 4096) -> str:
        """Decode a String oop into Python str. Returns "" for null / bad.

        `string_oop` must be a plain heap address; callers working under
        ZGC should uncolour before passing. Internal reference fields
        (e.g. the byte[]/char[] behind `value`) are uncoloured inline
        when a ZGCDecoder was supplied at construction.
        """
        if not string_oop:
            return ""
        r = self._r
        dec = self._oop

        # Resolve mark-word forwarding: under Shenandoah / STW copying GCs
        # an oop may have been relocated and its mark word rewritten to the
        # new address with tag 0b10. Follow one hop.
        string_oop = dec.resolve_forwarding(string_oop)

        # Read String.value — a reference field.
        v_slot = string_oop + self._layout.value_offset
        if self._zgc is not None:
            # Under ZGC reference fields hold wide coloured pointers.
            raw = struct.unpack_from("<Q", r.read(v_slot, 8))[0]
            value_oop = self._zgc.decode(raw)
        elif dec.oops_are_compressed:
            narrow = struct.unpack_from("<I", r.read(v_slot, 4))[0]
            value_oop = dec.decode_oop(narrow)
        else:
            value_oop = _ptr(r, v_slot)
        if not value_oop:
            return ""
        # The value array (byte[]/char[]) may also be forwarded.
        value_oop = dec.resolve_forwarding(value_oop)

        # Optional coder byte: 0=Latin1 (1 byte/char), 1=UTF-16LE (2 bytes/char).
        # JDK 8 has no coder — always UTF-16 in char[].
        if self._layout.coder_offset is not None:
            coder = r.read(string_oop + self._layout.coder_offset, 1)[0]
        else:
            coder = 1  # treat as UTF-16 / char[]

        # Array header → length + data.
        len_off, data_off = _array_header_offsets(dec)
        length = _i32(r, value_oop + len_off)
        if length <= 0:
            return ""
        if coder == 0:
            # Latin1: length is byte count.
            n = min(length, max_bytes)
            raw = r.read(value_oop + data_off, n)
            return raw.decode("latin-1", errors="replace")
        # coder == 1 → UTF-16 (2 bytes per code unit).
        # JDK 8 char[]: length counts char slots (2 bytes each).
        # JDK 9+ byte[] with coder=1: length is byte count (2 per char).
        if self._layout.coder_offset is None:
            # JDK 8 char[]: length in chars; data 2 bytes per char.
            n_chars = min(length, max_bytes // 2)
            raw = r.read(value_oop + data_off, n_chars * 2)
        else:
            # JDK 9+ byte[] with coder=1: length is byte count.
            n_bytes = min(length, max_bytes)
            raw = r.read(value_oop + data_off, n_bytes)
        return raw.decode("utf-16-le", errors="replace")
