"""Runtime walkers over live HotSpot state read via VMMeta.

Currently provides:
    ThreadWalker — iterate every JavaThread in a target JVM, auto-picking
                   between the JDK 8/11 legacy linked list and the
                   JDK 17+ Threads-SMR snapshot array.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from collections.abc import Iterator

from vm_meta import VMMeta, Reader, _i32, _ptr, _u16, _u32

# HotSpot JavaThreadState enum (globalDefinitions.hpp). Values are stable
# across JDK 8..25; gaps are intentional (transition states interleaved).
# Overridden at runtime by any `_thread_*` constants the target JVM exports.
_FALLBACK_STATE_NAMES = {
    0:  "_thread_uninitialized",
    2:  "_thread_new",
    3:  "_thread_new_trans",
    4:  "_thread_in_native",
    5:  "_thread_in_native_trans",
    6:  "_thread_in_vm",
    7:  "_thread_in_vm_trans",
    8:  "_thread_in_Java",
    9:  "_thread_in_Java_trans",
    10: "_thread_blocked",
    11: "_thread_blocked_trans",
    12: "_thread_max_state",
}


@dataclass(frozen=True)
class ThreadSnapshot:
    address: int           # JavaThread*
    state_raw: int         # JavaThread::_thread_state enum
    state_name: str
    os_tid: int            # native OS thread id (Windows TID), 0 if unknown
    osthread_addr: int     # OSThread* — 0 if NULL
    thread_obj: int        # raw _threadObj (oop in 8/11, OopHandle addr in 17+)
    vthread: int           # JDK 21+: raw _vthread handle; 0 on <21 or unmounted

    def __repr__(self) -> str:
        vt = f" vthread={self.vthread:#x}" if self.vthread else ""
        return (f"Thread({self.address:#x} tid={self.os_tid} "
                f"{self.state_name}{vt})")


class ThreadWalker:
    """Enumerate JavaThreads. Two strategies, auto-selected per JDK."""

    def __init__(self, vm: VMMeta):
        self._vm = vm
        self._reader = vm.reader
        self.strategy = self._pick_strategy()
        self._state_names = self._build_state_names()

        # Fields resolved once at construction — cheaper than per-thread lookups.
        # Note: there is no Thread::_name in vmStructs (despite what SA
        # research suggested). Real Java thread names live in the Java heap
        # at _threadObj → java.lang.Thread.name and require the M3 oop reader.
        jt = vm.type("JavaThread")
        os_ = vm.type("OSThread")
        self._off_state = jt.field("_thread_state").offset
        self._off_threadobj = jt.field("_threadObj").offset
        self._off_osthread_tid = os_.field("_thread_id").offset
        # _osthread lives on JavaThread in JDK 8..21 but was hoisted up to
        # the base Thread class in JDK 25. Resolve wherever it's exported.
        self._off_osthread = self._resolve_inherited("_osthread",
                                                    ["JavaThread", "Thread"])
        self._off_vthread = (jt.field("_vthread").offset
                             if jt.has_field("_vthread") else None)

    def _resolve_inherited(self, field: str, types: list[str]) -> int | None:
        """Return first offset where `field` is exported across the given
        types. Offsets from a base class are valid on derived objects because
        C++ single-inheritance keeps base members at their declared offset.
        """
        for t in types:
            if self._vm.has_type(t) and self._vm.type(t).has_field(field):
                return self._vm.type(t).field(field).offset
        return None

    # --- strategy selection -------------------------------------------------

    def _pick_strategy(self) -> str:
        if self._vm.type("Threads").has_field("_thread_list"):
            return "legacy"
        if self._vm.has_type("ThreadsSMRSupport"):
            return "smr"
        raise RuntimeError("no supported thread-enumeration path in this JVM")

    def _build_state_names(self) -> dict[int, str]:
        names = dict(_FALLBACK_STATE_NAMES)
        for k, v in self._vm.int_constants().items():
            if k.startswith("_thread_"):
                names[v] = k
        return names

    def _state_label(self, raw: int) -> str:
        return self._state_names.get(raw, f"<unknown:{raw}>")

    # --- thread snapshot reader --------------------------------------------

    def _read_thread(self, thread_ptr: int) -> ThreadSnapshot:
        r = self._reader
        state_raw = _i32(r, thread_ptr + self._off_state)
        osthread = (_ptr(r, thread_ptr + self._off_osthread)
                    if self._off_osthread is not None else 0)
        # OSThread::_thread_id is typedef-opaque; on Windows x64 it's a DWORD
        # (32-bit OS TID). Read 4 bytes — reading 8 would walk into whatever
        # follows the field and pollute the low word.
        os_tid = _u32(r, osthread + self._off_osthread_tid) if osthread else 0
        # _threadObj is `oop` on JDK 8/11 (direct pointer to java.lang.Thread)
        # and OopHandle on 17+ (pointer to a pointer slot). We record the raw
        # value either way; the oop reader (M3) will know what to do.
        thread_obj = _ptr(r, thread_ptr + self._off_threadobj)
        vthread = (_ptr(r, thread_ptr + self._off_vthread)
                   if self._off_vthread is not None else 0)
        return ThreadSnapshot(
            address=thread_ptr,
            state_raw=state_raw,
            state_name=self._state_label(state_raw),
            os_tid=os_tid,
            osthread_addr=osthread,
            thread_obj=thread_obj,
            vthread=vthread,
        )

    # --- public iteration ---------------------------------------------------

    def __iter__(self) -> Iterator[ThreadSnapshot]:
        return self._walk_legacy() if self.strategy == "legacy" else self._walk_smr()

    def _walk_legacy(self) -> Iterator[ThreadSnapshot]:
        r = self._reader
        head_addr = self._vm.type("Threads").static_field("_thread_list").address
        next_off = self._vm.type("JavaThread").field("_next").offset
        t = _ptr(r, head_addr)
        seen = set()
        while t:
            if t in seen:  # cycle guard — VM races can produce loops
                break
            seen.add(t)
            yield self._read_thread(t)
            t = _ptr(r, t + next_off)

    def _walk_smr(self) -> Iterator[ThreadSnapshot]:
        r = self._reader
        smr_static = self._vm.type("ThreadsSMRSupport").static_field("_java_thread_list")
        tl = _ptr(r, smr_static.address)
        if not tl:
            return
        tl_type = self._vm.type("ThreadsList")
        length = _u32(r, tl + tl_type.field("_length").offset)
        array_ptr = _ptr(r, tl + tl_type.field("_threads").offset)
        if not array_ptr or length == 0:
            return
        # Bulk-read the array — one ReadProcessMemory beats N small ones.
        raw = r.read(array_ptr, length * 8)
        for i in range(length):
            t = struct.unpack_from("<Q", raw, i * 8)[0]
            if t:
                yield self._read_thread(t)

    # --- convenience --------------------------------------------------------

    def list(self) -> list[ThreadSnapshot]:
        return list(self)

    def __repr__(self) -> str:
        return f"ThreadWalker(strategy={self.strategy!r})"


# ==========================================================================
# Symbol decoder
# ==========================================================================

def read_symbol(vm: VMMeta, reader: Reader, addr: int) -> str:
    """Decode a HotSpot Symbol to its UTF-8 string (class/method/field name).

    Empirically unified across JDK 8..25: every version exports both
    `Symbol::_length` (u2) and `Symbol::_body` via vmStructs. The three
    header epochs (independent _refcount vs packed _length_and_refcount vs
    _hash_and_refcount) differ only in fields we don't need for decoding.
    """
    if not addr or addr < 0x10000:
        return ""
    sym_t = vm.type("Symbol")
    try:
        length = _u16(reader, addr + sym_t.field("_length").offset)
        if length == 0 or length > 4096:
            return ""
        body = addr + sym_t.field("_body").offset
        return reader.read(body, length).decode("utf-8", "replace")
    except OSError:
        return ""


# ==========================================================================
# ClassWalker
# ==========================================================================

# Klass::_layout_helper encoding (klass.hpp):
#   positive  -> InstanceKlass (value = instance size in bytes, plus low bits)
#   negative  -> ArrayKlass; bits 30-31 distinguish type vs obj arrays.
# Values come from HotSpot's _lh_array_tag_type_value / _obj_value constants.
_LH_ARRAY_TAG_TYPE = 0x3
_LH_ARRAY_TAG_OBJ = 0x2


def _classify_layout_helper(lh: int) -> str:
    if lh > 0:
        return "instance"
    if lh == 0:
        return "?"
    # Treat as unsigned 32-bit so the bit extraction is unambiguous.
    tag = ((lh & 0xFFFFFFFF) >> 30) & 0x3
    if tag == _LH_ARRAY_TAG_TYPE:
        return "type_array"
    if tag == _LH_ARRAY_TAG_OBJ:
        return "obj_array"
    return "array"


@dataclass(frozen=True)
class KlassSnapshot:
    address: int
    name: str
    kind: str                # "instance" | "obj_array" | "type_array" | "array" | "?"
    layout_helper: int
    loader_data: int         # ClassLoaderData* (0 if unknown)

    def __repr__(self) -> str:
        return f"Klass({self.address:#x}, {self.kind}, {self.name!r})"


class ClassWalker:
    """Enumerate every loaded Klass. Two strategies auto-selected per JDK."""

    def __init__(self, vm: VMMeta):
        self._vm = vm
        self._reader = vm.reader
        self.strategy = self._pick_strategy()

        klass_t = vm.type("Klass")
        self._off_name = klass_t.field("_name").offset
        self._off_layout = klass_t.field("_layout_helper").offset
        self._off_next_link = (klass_t.field("_next_link").offset
                               if klass_t.has_field("_next_link") else None)

        if self.strategy == "CLDG":
            cld_t = vm.type("ClassLoaderData")
            self._off_cld_klasses = cld_t.field("_klasses").offset
            self._off_cld_next = cld_t.field("_next").offset
        else:
            # SystemDictionary walker — inherits layout from the exported
            # sibling instantiation BasicHashtable<mtInternal>. Template
            # parameters affect only allocation tags, not binary layout,
            # so these offsets apply to the Dictionary<Klass*, mtClass>
            # instance rooted at SystemDictionary::_dictionary.
            bh = vm.type("BasicHashtable<mtInternal>")
            self._off_dict_size = bh.field("_table_size").offset   # 0
            self._off_dict_buckets = bh.field("_buckets").offset   # 8
            self._bucket_stride = vm.type("HashtableBucket<mtInternal>").size
            self._entry_base_size = vm.type("BasicHashtableEntry<mtInternal>").size
            self._off_entry_next = vm.type(
                "BasicHashtableEntry<mtInternal>").field("_next").offset
            # _literal (the Klass*) sits at the first offset past the base.
            self._off_entry_literal = self._entry_base_size
            self._off_entry_cld = vm.type("DictionaryEntry").field("_loader_data").offset

    # --- strategy selection -------------------------------------------------

    def _pick_strategy(self) -> str:
        vm = self._vm
        if (vm.has_type("ClassLoaderDataGraph")
            and vm.has_type("ClassLoaderData")
            and vm.type("ClassLoaderData").has_field("_klasses")
            and vm.type("Klass").has_field("_next_link")):
            return "CLDG"
        if (vm.has_type("SystemDictionary")
            and vm.has_type("BasicHashtable<mtInternal>")
            and vm.has_type("DictionaryEntry")):
            return "SystemDictionary"
        raise RuntimeError("no supported class-enumeration path in this JVM")

    # --- traversal ----------------------------------------------------------

    def __iter__(self) -> Iterator[KlassSnapshot]:
        if self.strategy == "CLDG":
            return self._walk_cldg()
        return self._walk_sysdict()

    def _walk_cldg(self) -> Iterator[KlassSnapshot]:
        r = self._reader
        head_addr = self._vm.type("ClassLoaderDataGraph").static_field("_head").address
        cld = _ptr(r, head_addr)
        cld_seen: set[int] = set()
        while cld and cld not in cld_seen:
            cld_seen.add(cld)
            k = _ptr(r, cld + self._off_cld_klasses)
            k_seen: set[int] = set()
            while k and k not in k_seen:
                k_seen.add(k)
                yield self._read_klass(k, cld)
                k = _ptr(r, k + self._off_next_link)
            cld = _ptr(r, cld + self._off_cld_next)

    def _walk_sysdict(self) -> Iterator[KlassSnapshot]:
        r = self._reader
        dict_slot = self._vm.type("SystemDictionary").static_field("_dictionary").address
        dict_ptr = _ptr(r, dict_slot)
        if not dict_ptr:
            return
        table_size = _i32(r, dict_ptr + self._off_dict_size)
        buckets = _ptr(r, dict_ptr + self._off_dict_buckets)
        if not buckets or table_size <= 0:
            return
        # Pass 1: every InstanceKlass reachable from the dictionary.
        instance_klasses: list[int] = []
        for i in range(table_size):
            entry = _ptr(r, buckets + i * self._bucket_stride)
            entry_seen: set[int] = set()
            while entry and entry not in entry_seen:
                entry_seen.add(entry)
                klass = _ptr(r, entry + self._off_entry_literal)
                cld = _ptr(r, entry + self._off_entry_cld)
                if klass:
                    instance_klasses.append(klass)
                    yield self._read_klass(klass, cld)
                entry = _ptr(r, entry + self._off_entry_next)
        # Pass 2: walk each InstanceKlass's `_array_klasses` chain — array
        # klasses aren't registered in the SystemDictionary on JDK 8.
        # `_higher_dimension` lives on ArrayKlass (base) in JDK 8 and on
        # ObjArrayKlass in later JDKs; resolve either.
        if not self._vm.type("InstanceKlass").has_field("_array_klasses"):
            return
        array_off = self._vm.type("InstanceKlass").field("_array_klasses").offset
        higher_off = None
        for t in ("ObjArrayKlass", "ArrayKlass"):
            if self._vm.has_type(t) and self._vm.type(t).has_field("_higher_dimension"):
                higher_off = self._vm.type(t).field("_higher_dimension").offset
                break
        if higher_off is None:
            return
        seen_arrays: set[int] = set()
        for ik in instance_klasses:
            ak = _ptr(r, ik + array_off)
            while ak and ak not in seen_arrays:
                seen_arrays.add(ak)
                yield self._read_klass(ak, 0)
                ak = _ptr(r, ak + higher_off)
        # Pass 3 (JDK 8 only): primitive-type arrays live as
        # `Universe::_byteArrayKlassObj` etc. and aren't reachable through
        # any chain above.
        universe = self._vm.type("Universe") if self._vm.has_type("Universe") else None
        if universe is not None:
            for fld in ("_byteArrayKlassObj", "_charArrayKlassObj",
                        "_shortArrayKlassObj", "_intArrayKlassObj",
                        "_longArrayKlassObj", "_singleArrayKlassObj",
                        "_doubleArrayKlassObj", "_boolArrayKlassObj"):
                if not universe.has_field(fld):
                    continue
                ak = _ptr(r, universe.static_field(fld).address)
                while ak and ak not in seen_arrays:
                    seen_arrays.add(ak)
                    yield self._read_klass(ak, 0)
                    ak = _ptr(r, ak + higher_off)

    def _read_klass(self, klass_ptr: int, cld: int) -> KlassSnapshot:
        r = self._reader
        name_sym = _ptr(r, klass_ptr + self._off_name)
        name = read_symbol(self._vm, r, name_sym)
        lh = _i32(r, klass_ptr + self._off_layout)
        return KlassSnapshot(
            address=klass_ptr,
            name=name or "<anon>",
            kind=_classify_layout_helper(lh),
            layout_helper=lh,
            loader_data=cld,
        )

    # --- convenience --------------------------------------------------------

    def list(self) -> list[KlassSnapshot]:
        return list(self)

    def __repr__(self) -> str:
        return f"ClassWalker(strategy={self.strategy!r})"
