"""Oop / compressed-pointer decoder for HotSpot heap access.

Resolves compressed-oop + compressed-Klass parameters from VM globals,
decodes narrow pointers, dereferences OopHandle, and reads an object's
Klass pointer from its header. The companion `field_reader` module
layers by-name instance-field access on top, and `string_reader`
provides java.lang.String decoding.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from vm_meta import VMMeta, Reader, _i32, _ptr, _u32, _u64


# --- CompressedOops / CompressedKlassPointers parameter resolution -------

# Probed in declaration order; first match wins. Each entry:
#   (type_name, base_field, shift_field).
# Covers the three layouts we've seen empirically:
#   JDK 8/11  : base/shift live on Universe as nested _narrow_oop._base
#   JDK 17/21 : moved to CompressedOops class, same nested form
#   JDK 25    : flattened on CompressedOops (no sub-struct)
_OOP_PARAM_CANDIDATES = [
    ("CompressedOops", "_base",             "_shift"),              # 25
    ("CompressedOops", "_narrow_oop._base", "_narrow_oop._shift"),  # 17/21
    ("Universe",       "_narrow_oop._base", "_narrow_oop._shift"),  # 8/11
]

_KLASS_PARAM_CANDIDATES = [
    ("CompressedKlassPointers", "_base",               "_shift"),                  # 25
    ("CompressedKlassPointers", "_narrow_klass._base", "_narrow_klass._shift"),    # 17/21
    ("Universe",                "_narrow_klass._base", "_narrow_klass._shift"),    # 8/11
]


@dataclass
class NarrowParams:
    """Decoded parameters of compressed pointer encoding.

    `wide = (narrow << shift) + base`, with narrow==0 encoding NULL.
    base==0 and shift==0 together mean the encoding is the identity — valid
    when compressed oops are disabled or when the heap sits in the low 4 GiB.
    """
    base: int
    shift: int

    @property
    def enabled(self) -> bool:
        return self.base != 0 or self.shift != 0

    def decode(self, narrow: int) -> int:
        if narrow == 0:
            return 0
        return ((narrow << self.shift) + self.base) & 0xFFFFFFFFFFFFFFFF


def _resolve_params(vm: VMMeta, r: Reader,
                    candidates: list[tuple[str, str, str]]) -> NarrowParams:
    for type_name, base_field, shift_field in candidates:
        if not vm.has_type(type_name):
            continue
        t = vm.type(type_name)
        if not (t.has_field(base_field) and t.has_field(shift_field)):
            continue
        base_addr = t.static_field(base_field).address
        shift_addr = t.static_field(shift_field).address
        # `_base` is an `address` (char*) — read 8 bytes as a pointer.
        base = _ptr(r, base_addr)
        shift = _i32(r, shift_addr)
        return NarrowParams(base=base, shift=shift)
    return NarrowParams(base=0, shift=0)


# --- OopDecoder ----------------------------------------------------------

class OopDecoder:
    """Bundle of encoding params and convenience readers over a VMMeta.

    Reads HotSpot object headers, decodes narrow pointers, and dereferences
    OopHandles. Stateless beyond the cached parameters and field offsets.
    """

    def __init__(self, vm: VMMeta):
        self._vm = vm
        self._r = vm.reader
        self.oop_params = _resolve_params(vm, self._r, _OOP_PARAM_CANDIDATES)
        self.klass_params = _resolve_params(vm, self._r, _KLASS_PARAM_CANDIDATES)
        # Compressed oops can be on with base=0 AND shift=0 — happens when
        # the heap is mapped into the low 4 GiB of the address space (seen
        # on Shenandoah). The raw `enabled` property can't tell this apart
        # from "no compression at all". We consult CompressedOops type
        # presence as a secondary signal.
        self._has_compressed_oops_type = vm.has_type("CompressedOops")

        # oopDesc header: mark word (8) + klass metadata. The oopDesc.size
        # from vmStructs reflects sizeof() which is 16 on x64 regardless of
        # compression (union { Klass*; narrowKlass }). Real compression is
        # a runtime/compile flag — we detect it by probing a known-good oop.
        self._klass_slot_offset = 8
        self._name_offset = vm.type("Klass").field("_name").offset
        self._compressed_klass: bool | None = None  # lazy probe
        self._oops_compressed_cache: bool | None = None  # lazy probe
        # Eagerly prime via a stable global oop so callers that never invoke
        # klass_of() (e.g. the array-header helpers in string_reader) still
        # see a resolved compressed-klass flag.
        self._prime_from_static()

    def _probe_heap_base(self) -> int:
        """Return the live Java heap base address, or 0 if we can't find it.

        Uses the GC-agnostic `CollectedHeap::_reserved._start` (a MemRegion
        field always present since JDK 8). Works for Serial/Parallel/G1/
        Shenandoah/ZGC alike. The low-4GB check against this base is what
        distinguishes compressed-identity from uncompressed-low-address.
        """
        u = self._vm
        if not (u.has_type("Universe") and u.type("Universe").has_field("_collectedHeap")):
            return 0
        try:
            heap_ptr = _ptr(self._r, u.type("Universe").static_field("_collectedHeap").address)
            if not heap_ptr:
                return 0
            ch = u.type("CollectedHeap") if u.has_type("CollectedHeap") else None
            if ch is None or not ch.has_field("_reserved"):
                return 0
            res_off = ch.field("_reserved").offset
            return _ptr(self._r, heap_ptr + res_off)
        except Exception:
            return 0

    def _probe_live_oop(self) -> int:
        """Return the wide heap address of a known live oop, or 0 if none.

        Walks Universe statics (only useful pre-JDK 17). Follows one extra
        indirection when the field was retrofitted to OopHandle (JDK 13+).
        """
        u = self._vm
        if not u.has_type("Universe"):
            return 0
        ut = u.type("Universe")
        for field_name in ("_main_thread_group", "_system_thread_group"):
            if not ut.has_field(field_name):
                continue
            f = ut.static_field(field_name)
            try:
                val = _ptr(self._r, f.address)
            except Exception:
                continue
            if not val:
                continue
            # OopHandle wraps the slot in an extra level of indirection.
            if f.type_string == "OopHandle":
                try:
                    val = _ptr(self._r, val)
                except Exception:
                    continue
            if val:
                return val
        return 0

    def _prime_from_static(self) -> None:
        """Probe compressed-klass AND oop storage size using heap metadata.

        Oop storage size (4 vs 8 bytes) is derived from the heap base: if
        the heap lives in the low 4 GiB, compressed oops are active (either
        shifted or identity-mapped). Otherwise wide storage is in use. This
        correctly distinguishes `-XX:-UseCompressedOops` from the identity-
        compressed case where `CompressedOops._base/_shift` are both zero.

        Klass-storage compression is a separate concern and is probed via a
        known live oop (pre-JDK 17 only; the lazy `_probe_klass_mode` path
        covers JDK 17+ once a caller hits `klass_of`).
        """
        heap_base = self._probe_heap_base()
        if self.oop_params.enabled:
            self._oops_compressed_cache = True
        elif heap_base:
            self._oops_compressed_cache = heap_base <= 0xFFFFFFFF
        # Klass-mode probe via a live oop (best effort, pre-JDK 17 only).
        oop_val = self._probe_live_oop()
        if oop_val:
            try:
                self.klass_of(oop_val)
            except Exception:
                pass
        if self._compressed_klass is None:
            # Klass compression is INDEPENDENT of oop compression — JDK 17+
            # keeps `UseCompressedClassPointers` on even when
            # `-UseCompressedOops` is passed. The klass-params base/shift
            # (narrow_klass._base pointing into metaspace) is the reliable
            # signal; `enabled` handles both the shifted and unshifted
            # metaspace-based encodings.
            self._compressed_klass = self.klass_params.enabled

    # --- Narrow decoders ---------------------------------------------------

    def decode_oop(self, narrow: int) -> int:
        return self.oop_params.decode(narrow)

    @property
    def oops_are_compressed(self) -> bool:
        """True when reference slots hold 4-byte narrow oops. Separately
        from oop_params.enabled because identity-mapped compression
        (base=0, shift=0) still uses 4-byte slots.

        Resolved once at construction via a live-oop heap-address probe
        and cached. If the prime couldn't find a live oop, a late probe
        runs here on first access.
        """
        if self._oops_compressed_cache is not None:
            return self._oops_compressed_cache
        if self.oop_params.enabled:
            self._oops_compressed_cache = True
            return True
        heap_base = self._probe_heap_base()
        if heap_base:
            self._oops_compressed_cache = heap_base <= 0xFFFFFFFF
        else:
            # Last-ditch heuristic matching the historical behaviour.
            self._oops_compressed_cache = (
                self._has_compressed_oops_type and self._compressed_klass is True)
        return self._oops_compressed_cache

    def decode_klass(self, narrow: int) -> int:
        return self.klass_params.decode(narrow)

    def encode_oop(self, wide: int) -> int:
        """Inverse of decode_oop: wide oop address -> narrow oop slot value.

        `encode_oop(0) == 0` so NULL round-trips. Raises if compression is
        disabled and a 32-bit narrow representation was requested anyway.
        """
        if wide == 0:
            return 0
        p = self.oop_params
        narrow = (wide - p.base) >> p.shift
        if narrow < 0 or narrow > 0xFFFFFFFF:
            raise ValueError(
                f"wide oop {wide:#x} outside narrow range "
                f"(base={p.base:#x}, shift={p.shift})")
        return narrow

    # --- OopHandle (one extra indirection introduced in JDK 17) ----------

    def deref_oop_handle(self, obj_slot_ptr: int) -> int:
        """Given the already-read value of OopHandle::_obj (i.e. the slot
        pointer), return the wide oop stored in that slot.

        JDK 8/11 hold references as direct `oop` fields (no handle), so
        callers must check `field.type_string == "OopHandle"` before wrapping.
        """
        if not obj_slot_ptr:
            return 0
        # One deref: OopHandle._obj already points at the oop slot; the slot
        # contains the wide oop. (Slot storage stays wide even when the heap
        # uses compressed oops — that compression applies inside objects.)
        return _ptr(self._r, obj_slot_ptr)

    # --- Forwarding (Shenandoah / generic mark-word forwarding) ----------

    def resolve_forwarding(self, oop_addr: int) -> int:
        """If the mark word at `oop_addr` indicates forwarding (tag 0b10),
        return the forwardee; otherwise return `oop_addr` unchanged.

        Applies to any GC that forwards via mark word: Shenandoah during
        concurrent marking / evacuation, and generic HotSpot during STW
        copying GCs. Callers reading any oop should route through this
        before touching the header or fields.
        """
        if not oop_addr:
            return 0
        try:
            mark = _u64(self._r, oop_addr)
        except OSError:
            return oop_addr
        if (mark & 0x3) == 0x2:
            fwd = mark & ~0x3
            if fwd and fwd != oop_addr:
                return fwd
        return oop_addr

    # --- Klass from oop header --------------------------------------------

    def klass_of(self, oop_addr: int) -> int:
        """Return the Klass* for a live oop. Handles compressed class ptrs
        and mark-word forwarding (Shenandoah / STW copying GCs).

        On first call, auto-detects whether this VM uses compressed class
        pointers by trying narrow decoding and checking for a plausible
        Symbol at Klass::_name. Falls back to wide if narrow fails.
        """
        if not oop_addr:
            return 0
        oop_addr = self.resolve_forwarding(oop_addr)
        slot = oop_addr + self._klass_slot_offset
        if self._compressed_klass is None:
            self._compressed_klass = self._probe_klass_mode(slot)
        if self._compressed_klass:
            return self.decode_klass(_u32(self._r, slot))
        return _ptr(self._r, slot)

    def _probe_klass_mode(self, slot: int) -> bool:
        """Return True if this VM stores narrow (4-byte) klass pointers."""
        narrow = _u32(self._r, slot)
        if narrow and self._klass_looks_valid(self.decode_klass(narrow)):
            return True
        wide = _ptr(self._r, slot)
        if wide and self._klass_looks_valid(wide):
            return False
        # Neither path produced a readable Symbol. Default to narrow if the
        # klass params say compression is enabled; otherwise wide.
        return self.klass_params.enabled

    def _klass_looks_valid(self, klass_ptr: int) -> bool:
        """Heuristic: Klass::_name should point to a Symbol with 1..2047
        ASCII-ish bytes. Junk pointers almost never satisfy this."""
        if not klass_ptr or klass_ptr < 0x10000:
            return False
        try:
            name_ptr = _ptr(self._r, klass_ptr + self._name_offset)
            if not name_ptr or name_ptr < 0x10000:
                return False
            # Symbol header: u2 length at _length offset (empirically 0 or 4).
            sym_t = self._vm.type("Symbol")
            length = struct.unpack_from(
                "<H", self._r.read(name_ptr + sym_t.field("_length").offset, 2))[0]
            return 0 < length < 2048
        except Exception:
            return False

    # --- introspection -----------------------------------------------------

    def __repr__(self) -> str:
        ck = {True: "on", False: "off", None: "?"}[self._compressed_klass]
        return (f"OopDecoder(oop_shift={self.oop_params.shift}, "
                f"klass_shift={self.klass_params.shift}, "
                f"compressed_klass={ck})")
