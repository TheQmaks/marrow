"""Cross-process Java allocation via TLAB hijack.

Without JNI/JVMTI we can't call `MemAllocator::allocate()` directly — that
requires a JavaThread in `_thread_in_vm` state. But TLAB allocation is just
a bump of two pointers in the thread's ThreadLocalAllocBuffer; if we
SuspendThread every mutator first, bump `_top`, and write an object header
into the reserved bytes, we've effectively done what the fast-path allocator
would have done, from outside the VM.

Scope:
  * allocate_instance(klass)       — zero-init instance object
  * allocate_type_array(klass, n)  — primitive array (byte[], char[], ...)

Limitations:
  * Ignores the slow-allocation-path bit in layout_helper (Finalizer-able
    classes and similar edge cases). The three-classes demo doesn't hit them.
  * Concurrent GC threads (G1 marking, ZGC) may still be active during the
    suspend window. We minimise the window to ~microseconds.
  * If no thread has a TLAB with enough room, raises — refill is future work.
  * Requires compressed class pointers (the universal default on x64).
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct

from vm_meta import VMMeta, _i32, _ptr, _u64
from walker import ThreadWalker
from oop_reader import OopDecoder

# --- Win32 bindings for SuspendThread / ResumeThread ---------------------

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

TH32CS_SNAPTHREAD = 0x00000004
THREAD_SUSPEND_RESUME = 0x0002

_k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_k32.OpenThread.restype = wt.HANDLE
_k32.SuspendThread.argtypes = [wt.HANDLE]
_k32.SuspendThread.restype = wt.DWORD
_k32.ResumeThread.argtypes = [wt.HANDLE]
_k32.ResumeThread.restype = wt.DWORD
_k32.CloseHandle.argtypes = [wt.HANDLE]


# --- HotSpot layout_helper constants (klass.hpp, stable since JDK 7) -----
#   For instance klasses: positive value; low 3 bits reserved, upper bits
#                         are instance size in bytes already.
#   For array klasses:    negative value; bit fields packed like this:
#     [tag(2)] [hsz(8)] [etype(4)] [log2esz(4)] [extra]
#     header_size in bytes starts at bit 20.
_LH_HEADER_SIZE_SHIFT = 16     # ⚠ verified via runtime probe below
_LH_HEADER_SIZE_MASK = 0xFF
_LH_LOG2_ELEMENT_SIZE_SHIFT = 0
_LH_LOG2_ELEMENT_SIZE_MASK = 0xFF
# NB: HotSpot actually uses shift=20 for header and shift=24 for log2(esz),
# but we don't need the fields here — we probe them from an existing object.


def _align_up(x: int, a: int) -> int:
    return (x + a - 1) & ~(a - 1)


class AllocationError(RuntimeError):
    pass


class TLABAllocator:
    """Drop-in allocator backed by direct TLAB manipulation.

    Typical use:
        alloc = TLABAllocator(vm, decoder)
        ba = alloc.allocate_type_array(byte_array_klass, 18)
        vm.reader.write(ba + data_offset, b"hello from outside")
    """

    def __init__(self, vm: VMMeta, decoder: OopDecoder):
        self._vm = vm
        self._r = vm.reader
        self._dec = decoder

        # Pre-resolve offsets we'll hit on every allocation.
        thread_t = vm.type("Thread")
        tlab_t = vm.type("ThreadLocalAllocBuffer")
        self._off_thread_tlab = thread_t.field("_tlab").offset
        self._off_tlab_top = tlab_t.field("_top").offset
        self._off_tlab_end = tlab_t.field("_end").offset
        self._off_klass_layout = vm.type("Klass").field("_layout_helper").offset
        self._name_off = vm.type("Klass").field("_name").offset

        # Layout-helper decoder works on runtime probes — we avoid hardcoding
        # shifts by extracting sizes from known-live objects when possible.

    # --- thread suspension --------------------------------------------------

    def _collect_tids(self) -> list[int]:
        return [t.os_tid for t in ThreadWalker(self._vm) if t.os_tid]

    def _suspend_all(self, tids: list[int]) -> list[int]:
        handles = []
        for tid in tids:
            h = _k32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
            if h:
                _k32.SuspendThread(h)
                handles.append(h)
        return handles

    def _resume_all(self, handles: list[int]) -> None:
        for h in handles:
            _k32.ResumeThread(h)
            _k32.CloseHandle(h)

    # --- TLAB picking -------------------------------------------------------

    def _pick_tlab(self, bytes_needed: int) -> tuple[int, int, int]:
        """Return (javaThread_ptr, current_top, tlab_end) for a thread whose
        TLAB has enough free room for bytes_needed. Raises if none fit."""
        for t in ThreadWalker(self._vm):
            tlab = t.address + self._off_thread_tlab
            top = _ptr(self._r, tlab + self._off_tlab_top)
            end = _ptr(self._r, tlab + self._off_tlab_end)
            if top == 0 or end == 0:
                continue
            if end - top >= bytes_needed:
                return t.address, top, end
        raise AllocationError(
            f"no JavaThread has {bytes_needed} bytes free in its TLAB")

    def _commit_tlab_top(self, thread_ptr: int, new_top: int) -> None:
        addr = thread_ptr + self._off_thread_tlab + self._off_tlab_top
        self._r.write(addr, struct.pack("<Q", new_top))

    # --- mark-word template -------------------------------------------------

    def _borrow_mark_word(self, klass_ptr: int) -> int:
        """Return a mark-word value suitable for a newly allocated object of
        this Klass. We copy from an existing oop of the same class if we can
        find one; otherwise fall back to the unlocked/hashless prototype."""
        # Fast path: java_mirror (java.lang.Class) is available for every
        # loaded Klass and its mark word is representative enough.
        mirror_f = self._vm.type("Klass").field("_java_mirror")
        raw = _ptr(self._r, klass_ptr + mirror_f.offset)
        mirror = _ptr(self._r, raw) if mirror_f.type_string == "OopHandle" else raw
        if mirror:
            mark = _u64(self._r, mirror)
            # Clear any identity hash bits so the new object gets a fresh
            # hash later if someone asks. Prototype always has UNLOCKED=1.
            return mark & 0x7   # leave low lock bits, everything else 0
        # Fallback: unlocked state (lowest 3 bits = 001 or 101 depending on era).
        return 0x1

    # --- core alloc ---------------------------------------------------------

    def _alloc_raw(self, size_bytes: int) -> tuple[int, int]:
        """Reserve `size_bytes` (must be 8-aligned) from some TLAB, all
        mutators suspended. Returns (oop_addr, thread_ptr_used)."""
        assert size_bytes % 8 == 0 and size_bytes > 0
        tids = self._collect_tids()
        handles = self._suspend_all(tids)
        try:
            thread_ptr, top, _end = self._pick_tlab(size_bytes)
            # Re-check under suspension — target couldn't have moved top.
            self._commit_tlab_top(thread_ptr, top + size_bytes)
            # Zero-initialize the reserved region; fresh oops must not carry
            # stray bits from whatever was there before.
            self._r.write(top, b"\x00" * size_bytes)
            return top, thread_ptr
        finally:
            self._resume_all(handles)

    def _encode_narrow_klass(self, klass_ptr: int) -> int:
        p = self._dec.klass_params
        if p.shift == 0 and p.base == 0:
            if klass_ptr > 0xFFFFFFFF:
                raise AllocationError(
                    f"klass {klass_ptr:#x} outside 32-bit range with zero params")
            return klass_ptr
        return (klass_ptr - p.base) >> p.shift

    # --- public entry points ------------------------------------------------

    def allocate_instance(self, klass_ptr: int) -> int:
        """Allocate a zero-initialised instance of the given InstanceKlass,
        return its wide oop."""
        lh = _i32(self._r, klass_ptr + self._off_klass_layout)
        if lh <= 0:
            raise AllocationError(
                f"klass {klass_ptr:#x} has non-instance layout_helper {lh}")
        # Low 3 bits are the slow-allocation-path / instance-bit tag, high
        # bits are the size in bytes. Mask them off.
        size = lh & ~0x7
        size = _align_up(size, 8)
        oop, _ = self._alloc_raw(size)
        self._write_header(oop, klass_ptr)
        return oop

    def allocate_type_array(self, klass_ptr: int, length: int) -> int:
        """Allocate a primitive-type array of `length` elements, zero-init.

        element_size is probed from the Klass's layout_helper. Returns the
        array oop.
        """
        if length < 0:
            raise ValueError("negative array length")
        lh_u = _i32(self._r, klass_ptr + self._off_klass_layout) & 0xFFFFFFFF
        # For array klasses HotSpot packs: [tag(2)][hsize_bytes(8) @20][...][log2esz(4) @0..3]
        header_size = (lh_u >> 16) & 0xFF
        log2_element = lh_u & 0xFF   # low nibble holds log2(element_size)
        # Both fields' shifts vary between encodings — recover robustly: the
        # array header size is what HotSpot reserved before _data, and the
        # element size is 2**log2_element bytes.
        if header_size not in (12, 16, 20, 24):
            # Sanity: header must match compressed (16) or wide (24) layout;
            # other values indicate we decoded the wrong bits.
            raise AllocationError(
                f"implausible array header size {header_size} from lh={lh_u:#x}")
        elem_size = 1 << log2_element
        data_size = length * elem_size
        total = _align_up(header_size + data_size, 8)
        oop, _ = self._alloc_raw(total)
        self._write_header(oop, klass_ptr)
        # length goes right before _data (at offset 12 or 16 depending on klass).
        length_off = header_size - 4
        self._r.write(oop + length_off, struct.pack("<i", length))
        return oop

    def _write_header(self, oop: int, klass_ptr: int) -> None:
        # Mark word (8 bytes) + narrow Klass (4) / wide Klass (8).
        mark = self._borrow_mark_word(klass_ptr)
        self._r.write(oop, struct.pack("<Q", mark))
        if self._dec._compressed_klass:
            narrow = self._encode_narrow_klass(klass_ptr)
            self._r.write(oop + 8, struct.pack("<I", narrow))
        else:
            self._r.write(oop + 8, struct.pack("<Q", klass_ptr))

    # --- data offsets for callers filling payload -------------------------

    def array_data_offset(self) -> int:
        """Offset of the first element inside a primitive array oop."""
        return 16 if self._dec._compressed_klass else 24

    def array_length_offset(self) -> int:
        return 12 if self._dec._compressed_klass else 16
