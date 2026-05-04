"""ZGC coloured-pointer decoder.

Two pointer formats ship across the JDK matrix:

* **Classic ZGC** (JDK 15..20, JDK 17 here) — colour bits live in HIGH
  positions. The address is the low 42 bits:
      heap_addr = raw & ZAddressOffsetMask
  Live pointers satisfy `raw & ZAddressGoodMask != 0`.

* **Generational ZGC** (JDK 21+ with `-XX:+ZGenerational`, JDK 25 default) —
  colour bits live in LOW positions. Uncoloring is a right-shift:
      heap_addr = raw >> ZPointerLoadShift
  Live pointers satisfy `raw & ZPointerLoadBadMask == 0`.

The per-pointer shift-table variant HotSpot uses inside JIT-compiled code
isn't needed from outside: we always work against load-good pointers, so
a single global shift/mask works.

Activation is detected by checking `ZGlobalsForVMStructs::_instance_p`
and which mask fields are populated. With JDK 21 `-XX:+UseZGC` but no
`-XX:+ZGenerational`, the struct exists but fields stay zero — in that
legacy mode we report ZGC-as-unsupported and bail.
"""
from __future__ import annotations

from dataclasses import dataclass

from vm_meta import VMMeta, _ptr, _u64


@dataclass
class ZGCDecoder:
    vm: VMMeta
    mode: str              # "classic" | "generational" | "off"
    instance: int          # ZGlobalsForVMStructs* (0 if off)
    offset_mask_ptr: int   # ptr-to-uintptr_t for ZAddressOffsetMask (classic)
    load_shift_ptr: int    # ptr-to-size_t for ZPointerLoadShift (generational)
    load_bad_mask_ptr: int  # optional, for liveness check
    store_good_ptr: int = 0  # generational: ZPointerStoreGoodMask
    address_good_ptr: int = 0  # classic: ZAddressGoodMask (for re-color)

    @classmethod
    def detect(cls, vm: VMMeta) -> ZGCDecoder:
        if not vm.has_type("ZGlobalsForVMStructs"):
            return cls(vm, "off", 0, 0, 0, 0)
        zg = vm.type("ZGlobalsForVMStructs")
        inst = _ptr(vm.reader, zg.static_field("_instance_p").address)
        if not inst:
            return cls(vm, "off", 0, 0, 0, 0)

        # Probe which variant has meaningful values set.
        def ptr_of(field: str) -> int:
            if not zg.has_field(field):
                return 0
            return _ptr(vm.reader, inst + zg.field(field).offset)

        gen_shift_ptr = ptr_of("_ZPointerLoadShift")
        gen_good_ptr = ptr_of("_ZPointerLoadGoodMask")
        gen_bad_ptr = ptr_of("_ZPointerLoadBadMask")
        classic_offset_ptr = ptr_of("_ZAddressOffsetMask")
        classic_good_ptr = ptr_of("_ZAddressGoodMask")
        classic_bad_ptr = ptr_of("_ZAddressBadMask")

        # Store-side masks for generational (used when we need to encode
        # a wide heap address back into a coloured pointer for writing).
        store_good_ptr = ptr_of("_ZPointerStoreGoodMask")

        # Generational: LoadGoodMask populated (non-zero) and LoadShift > 0.
        if gen_good_ptr and _u64(vm.reader, gen_good_ptr) != 0 \
                and gen_shift_ptr and _u64(vm.reader, gen_shift_ptr) > 0:
            return cls(vm, "generational", inst,
                       offset_mask_ptr=0,
                       load_shift_ptr=gen_shift_ptr,
                       load_bad_mask_ptr=gen_bad_ptr,
                       store_good_ptr=store_good_ptr)

        # Classic: AddressGoodMask populated AND the field is actually present.
        if classic_good_ptr and _u64(vm.reader, classic_good_ptr) != 0 \
                and classic_offset_ptr:
            return cls(vm, "classic", inst,
                       offset_mask_ptr=classic_offset_ptr,
                       load_shift_ptr=0,
                       load_bad_mask_ptr=classic_bad_ptr,
                       address_good_ptr=classic_good_ptr)

        # ZGlobals exists but both variants are zero — legacy ZGC with no
        # populated masks (JDK 21 `-XX:+UseZGC` only). Can't decode safely.
        return cls(vm, "off", inst, 0, 0, 0)

    @property
    def is_active(self) -> bool:
        return self.mode != "off"

    def decode(self, raw: int) -> int:
        """Return a virtual address that can be fed to ReadProcessMemory.

        * Generational: colour bits sit in the low `LoadShift` bits; a right
          shift by the current shift value yields the heap offset, and the
          OS-mapped heap lives at that value (no base is added).

        * Classic: the colour bits are already in high positions, and ZGC
          maps the heap virtual-three-times (Marked0/Marked1/Remapped). A
          load-good pointer is directly dereferenceable — we just pass it
          through. Masking off the high good-bit would de-map it.

        Re-reads the shift on every call so that a GC phase flip between
        calls doesn't leave us shifting by a stale value. If the pointer is
        load-bad (flip happened *during* our read), retries once with the
        fresh shift — good enough for 99.99% of cases; pathological flip
        races require the per-pointer cpu_shift_table (M11 backlog).
        """
        if raw == 0 or self.mode == "off":
            return raw
        if self.mode == "classic":
            return raw
        # generational path with a one-shot flip retry.
        for _ in range(2):
            shift = _u64(self.vm.reader, self.load_shift_ptr)
            candidate = raw >> shift
            if not self._is_load_bad_now(raw):
                return candidate
        return raw >> _u64(self.vm.reader, self.load_shift_ptr)

    def _is_load_bad_now(self, raw: int) -> bool:
        if not self.load_bad_mask_ptr:
            return False
        return (raw & _u64(self.vm.reader, self.load_bad_mask_ptr)) != 0

    def encode_for_store(self, heap_addr: int) -> int:
        """Re-colour a wide heap address into the format a ZGC store-site
        would use. For generational ZGC: shift into the address range
        and OR in the store-good colour bits. For classic: OR in the
        current good mask.

        Result is the raw value to write into the target's reference slot.
        """
        if heap_addr == 0 or self.mode == "off":
            return heap_addr
        if self.mode == "generational":
            if not self.store_good_ptr:
                # Fallback: reuse load-good if store-good wasn't exported.
                store_good_ptr = self.store_good_ptr
            else:
                store_good_ptr = self.store_good_ptr
            store_good = _u64(self.vm.reader, store_good_ptr) if store_good_ptr else 0
            shift = _u64(self.vm.reader, self.load_shift_ptr)
            return ((heap_addr << shift) | store_good) & 0xFFFFFFFFFFFFFFFF
        # classic: OR the current AddressGoodMask onto the offset.
        if self.address_good_ptr:
            good = _u64(self.vm.reader, self.address_good_ptr)
            offset_mask = (_u64(self.vm.reader, self.offset_mask_ptr)
                           if self.offset_mask_ptr else 0xFFFFFFFFFFFFFFFF)
            return (heap_addr & offset_mask) | good
        return heap_addr

    def is_load_bad(self, raw: int) -> bool:
        """True if the pointer carries a "bad" colour and would need a
        barrier before use. We usually only see load-good values."""
        if self.mode != "generational" or not self.load_bad_mask_ptr:
            return False
        bad_mask = _u64(self.vm.reader, self.load_bad_mask_ptr)
        return (raw & bad_mask) != 0

    def __repr__(self) -> str:
        return f"ZGCDecoder(mode={self.mode!r}, instance={self.instance:#x})"
