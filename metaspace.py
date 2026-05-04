"""ConstantPool cloning into our own metaspace-like region.

Metaspace (the native area where Klass / Method / ConstantPool live) has
a chunk-based allocator — we can't just "bump" it like TLAB. However,
HotSpot ultimately chases `InstanceKlass::_constants` by pointer, so if
we VirtualAllocEx a page in the target, copy the existing ConstantPool
bytes into it, and overwrite `_constants` to point at our copy, the VM
will happily follow the redirection.

Risks (documented, not defended against):
  * Any safepoint-time verifier that checks "this pointer lives inside a
    known metaspace range" will flag our CP as bad. HotSpot ships with
    `-XX:+VerifyMetaspace` off by default, so usually fine.
  * Class unloading may try to free metaspace regions containing this CP.
    We own the page (VirtualAllocEx), so HotSpot's Metaspace::deallocate
    wouldn't touch it — but some assertion might fire.
  * GC that walks CP entries expects metaspace-resident tags/resolved
    reference arrays. As long as we clone those too, we should be OK.

Scope here: clone only. Extending a CP with new entries is layered on top
but requires understanding the CP entry binary format (Utf8, Methodref,
NameAndType, etc.) — follow-up work.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from vm_meta import VMMeta, _i32, _ptr


@dataclass
class CPClone:
    orig_cp: int
    new_cp: int
    size: int
    page_size: int
    klass: int


def clone_constant_pool(vm: VMMeta, klass_ptr: int) -> CPClone:
    """Clone the ConstantPool referenced by `InstanceKlass::_constants`
    into a writable target page and redirect `_constants` to it.

    Does NOT free the original — it stays in metaspace where other
    references may still hold it.
    """
    r = vm.reader
    ik = vm.type("InstanceKlass")
    cp_t = vm.type("ConstantPool")

    constants_off = ik.field("_constants").offset
    length_off = cp_t.field("_length").offset
    header_size = cp_t.size

    orig_cp = _ptr(r, klass_ptr + constants_off)
    if not orig_cp:
        raise RuntimeError(f"klass {klass_ptr:#x} has no constants pool")
    length = _i32(r, orig_cp + length_off)
    if length <= 0:
        raise RuntimeError(f"cp {orig_cp:#x} reports length={length}")

    # CP memory layout: [ ConstantPool header ][ entries[length] each 8 bytes ]
    # Entries are already allocated in-line past the header. Tag array is
    # a separate Array<u1>* — we don't need to clone it since it's still
    # reachable from `_tags` inside the cloned header.
    total_size = header_size + length * 8
    # Page-align so OS accepts alloc.
    page_size = (total_size + 0xFFF) & ~0xFFF

    new_cp = r.alloc(page_size, executable=False)

    # Copy the whole thing in one shot.
    buf = r.read(orig_cp, total_size)
    r.write(new_cp, buf)

    # Redirect the InstanceKlass to use our clone.
    r.write(klass_ptr + constants_off, struct.pack("<Q", new_cp))

    return CPClone(orig_cp=orig_cp, new_cp=new_cp,
                   size=total_size, page_size=page_size,
                   klass=klass_ptr)


def restore_constant_pool(vm: VMMeta, clone: CPClone) -> None:
    """Put the original CP pointer back and free our clone."""
    r = vm.reader
    constants_off = vm.type("InstanceKlass").field("_constants").offset
    r.write(clone.klass + constants_off, struct.pack("<Q", clone.orig_cp))
    r.free(clone.new_cp)


# --- CP extension: grow length + tags so we can append new entries ---------

# HotSpot Array<T> header: int _length @0, then data at offset 4.
_ARRAY_DATA_OFFSET_U1 = 4


@dataclass
class CPExtension:
    clone: CPClone
    new_length: int
    orig_length: int
    new_tags_array: int     # the new Array<u1>* we allocated (for _tags)
    free_slot_start: int    # first newly-added CP index (0-based)


def extend_cp(vm: VMMeta, klass_ptr: int, extra_slots: int) -> CPExtension:
    """Clone the ConstantPool into a larger page and give us `extra_slots`
    extra entries at the end. The clone's `_length` is bumped and a fresh
    `_tags` Array<u1>* is allocated (copy of originals + zero-padding for
    new slots). New slots are zero-initialised; caller fills tag + slot
    bytes for each entry they want to add.
    """
    r = vm.reader
    ik = vm.type("InstanceKlass")
    cp_t = vm.type("ConstantPool")

    constants_off = ik.field("_constants").offset
    length_off = cp_t.field("_length").offset
    tags_off = cp_t.field("_tags").offset
    header_size = cp_t.size

    orig_cp = _ptr(r, klass_ptr + constants_off)
    orig_length = _i32(r, orig_cp + length_off)
    orig_tags = _ptr(r, orig_cp + tags_off)

    new_length = orig_length + extra_slots
    new_cp_size = header_size + new_length * 8
    new_page_size = (new_cp_size + 0xFFF) & ~0xFFF
    new_cp = r.alloc(new_page_size, executable=False)

    # Copy header
    r.write(new_cp, r.read(orig_cp, header_size))
    # Copy existing entries + zero-fill the new tail (alloc gives us zeros
    # but we copy explicitly to match layout size).
    r.write(new_cp + header_size, r.read(orig_cp + header_size, orig_length * 8))
    # Extra slots remain zeroed (tag 0 = JVM_CONSTANT_Invalid, harmless).

    # Update _length
    r.write(new_cp + length_off, struct.pack("<i", new_length))

    # Clone + extend the tags array.
    #   Array<u1>::_length @0, data starts at offset 4.
    orig_tags_len = _i32(r, orig_tags + 0)
    assert orig_tags_len == orig_length, \
        f"tags length {orig_tags_len} != cp length {orig_length}"
    new_tags_bytes = orig_tags_len + extra_slots
    new_tags_alloc = _ARRAY_DATA_OFFSET_U1 + new_tags_bytes
    new_tags_page_size = (new_tags_alloc + 0xFFF) & ~0xFFF
    new_tags = r.alloc(new_tags_page_size, executable=False)
    # length + original tag bytes; new slots tag=0.
    r.write(new_tags, struct.pack("<i", new_tags_bytes))
    r.write(new_tags + _ARRAY_DATA_OFFSET_U1,
            r.read(orig_tags + _ARRAY_DATA_OFFSET_U1, orig_tags_len))

    # Point the cloned CP at the new tags array, then install the clone.
    r.write(new_cp + tags_off, struct.pack("<Q", new_tags))
    r.write(klass_ptr + constants_off, struct.pack("<Q", new_cp))

    clone = CPClone(orig_cp=orig_cp, new_cp=new_cp,
                    size=new_cp_size, page_size=new_page_size,
                    klass=klass_ptr)
    return CPExtension(clone=clone, new_length=new_length,
                       orig_length=orig_length,
                       new_tags_array=new_tags,
                       free_slot_start=orig_length)


def set_cp_tag(vm: VMMeta, ext: CPExtension, index: int, tag: int) -> None:
    """Write `tag` into the tags array at CP index `index`."""
    vm.reader.write(
        ext.new_tags_array + _ARRAY_DATA_OFFSET_U1 + index,
        bytes([tag & 0xFF]))


def set_cp_slot_u64(vm: VMMeta, ext: CPExtension, index: int, value: int) -> None:
    """Write a raw 8-byte value into CP slot `index`. For Utf8 the value
    is a Symbol*; for Class (unresolved) the low u2 is the name index."""
    cp_t = vm.type("ConstantPool")
    slot_addr = ext.clone.new_cp + cp_t.size + index * 8
    vm.reader.write(slot_addr, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))


def set_cp_slot_name_and_type(vm: VMMeta, ext: CPExtension, index: int,
                               name_idx: int, sig_idx: int) -> None:
    """JVM_CONSTANT_NameAndType slot: (sig_idx << 16) | name_idx (u4)."""
    packed = ((sig_idx & 0xFFFF) << 16) | (name_idx & 0xFFFF)
    set_cp_slot_u64(vm, ext, index, packed)


def set_cp_slot_methodref(vm: VMMeta, ext: CPExtension, index: int,
                           class_idx: int, nat_idx: int) -> None:
    """JVM_CONSTANT_Methodref slot: (nat_idx << 16) | class_idx (u4)."""
    packed = ((nat_idx & 0xFFFF) << 16) | (class_idx & 0xFFFF)
    set_cp_slot_u64(vm, ext, index, packed)


# Standard JVM CP tag constants — values are the JVM spec's.
JVM_CONSTANT_Utf8           = 1
JVM_CONSTANT_Class          = 7
JVM_CONSTANT_String         = 8
JVM_CONSTANT_Fieldref       = 9
JVM_CONSTANT_Methodref      = 10
JVM_CONSTANT_InterfaceMethodref = 11
JVM_CONSTANT_NameAndType    = 12
