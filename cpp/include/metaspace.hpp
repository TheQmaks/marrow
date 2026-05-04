#pragma once
// ConstantPool cloning & extension in metaspace-adjacent VirtualAllocEx
// pages. HotSpot chases `InstanceKlass::_constants` by pointer, so our
// cloned CP is accepted once we redirect the pointer. Extension grows
// `_length` + allocates a fresh `_tags` Array<u1>*.

#include "vm_meta.hpp"
#include <cstdint>

namespace marrow {

// Standard JVM ConstantPool tag constants.
constexpr uint8_t JVM_CONSTANT_Utf8           = 1;
constexpr uint8_t JVM_CONSTANT_Class          = 7;
constexpr uint8_t JVM_CONSTANT_String         = 8;
constexpr uint8_t JVM_CONSTANT_Fieldref       = 9;
constexpr uint8_t JVM_CONSTANT_Methodref      = 10;
constexpr uint8_t JVM_CONSTANT_InterfaceMethodref = 11;
constexpr uint8_t JVM_CONSTANT_NameAndType    = 12;

struct CPClone {
    uint64_t orig_cp;
    uint64_t new_cp;
    size_t   size;
    size_t   page_size;
    uint64_t klass;
};

struct CPExtension {
    CPClone  clone;
    int32_t  new_length;
    int32_t  orig_length;
    uint64_t new_tags_array;
    int32_t  free_slot_start;
};

// Clone the CP and redirect `_constants`. Does NOT free the original.
CPClone clone_constant_pool(VMMeta* vm, uint64_t klass_ptr);
void    restore_constant_pool(VMMeta* vm, const CPClone& clone);

// Grow the CP by `extra_slots` (zero-initialised). Returns extension info
// the caller uses to fill in new tag bytes + slot payloads.
CPExtension extend_cp(VMMeta* vm, uint64_t klass_ptr, int32_t extra_slots);

void set_cp_tag(VMMeta* vm, const CPExtension& ext, int32_t index, uint8_t tag);
void set_cp_slot_u64(VMMeta* vm, const CPExtension& ext, int32_t index, uint64_t value);
void set_cp_slot_name_and_type(VMMeta* vm, const CPExtension& ext, int32_t index,
                                uint16_t name_idx, uint16_t sig_idx);
void set_cp_slot_methodref(VMMeta* vm, const CPExtension& ext, int32_t index,
                            uint16_t class_idx, uint16_t nat_idx);

} // namespace marrow
