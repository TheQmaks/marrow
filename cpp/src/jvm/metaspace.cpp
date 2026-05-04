#include "metaspace.hpp"
#include <stdexcept>
#include <cstring>

namespace marrow {

static constexpr size_t ARRAY_DATA_OFFSET_U1 = 4;
static constexpr size_t PAGE_MASK = 0xFFF;

static size_t page_align(size_t n) { return (n + PAGE_MASK) & ~PAGE_MASK; }

CPClone clone_constant_pool(VMMeta* vm, uint64_t klass_ptr)
{
    Reader* r = vm->reader();
    const TypeInfo* ik = vm->type("InstanceKlass");
    const TypeInfo* cp_t = vm->type("ConstantPool");
    if (!ik || !cp_t)
        throw std::runtime_error("InstanceKlass/ConstantPool type missing");
    size_t constants_off = ik->field("_constants")->offset;
    size_t length_off    = cp_t->field("_length")->offset;
    size_t header_size   = cp_t->size;

    uint64_t orig_cp = r->read_u64(klass_ptr + constants_off);
    if (!orig_cp) throw std::runtime_error("klass has no constants pool");
    int32_t length = r->read_i32(orig_cp + length_off);
    if (length <= 0) throw std::runtime_error("cp length <= 0");

    size_t total_size = header_size + size_t(length) * 8;
    size_t page_size = page_align(total_size);
    uint64_t new_cp = r->alloc(page_size, /*exec*/false);

    auto buf = r->read(orig_cp, total_size);
    r->write(new_cp, buf.data(), buf.size());

    uint64_t ptr_val = new_cp;
    r->write(klass_ptr + constants_off, &ptr_val, 8);

    return {orig_cp, new_cp, total_size, page_size, klass_ptr};
}

void restore_constant_pool(VMMeta* vm, const CPClone& c)
{
    size_t off = vm->type("InstanceKlass")->field("_constants")->offset;
    uint64_t v = c.orig_cp;
    vm->reader()->write(c.klass + off, &v, 8);
    vm->reader()->free(c.new_cp);
}

CPExtension extend_cp(VMMeta* vm, uint64_t klass_ptr, int32_t extra_slots)
{
    Reader* r = vm->reader();
    const TypeInfo* ik = vm->type("InstanceKlass");
    const TypeInfo* cp_t = vm->type("ConstantPool");
    size_t constants_off = ik->field("_constants")->offset;
    size_t length_off    = cp_t->field("_length")->offset;
    size_t tags_off      = cp_t->field("_tags")->offset;
    size_t header_size   = cp_t->size;

    uint64_t orig_cp = r->read_u64(klass_ptr + constants_off);
    int32_t orig_length = r->read_i32(orig_cp + length_off);
    uint64_t orig_tags = r->read_u64(orig_cp + tags_off);

    int32_t new_length = orig_length + extra_slots;
    size_t new_cp_size = header_size + size_t(new_length) * 8;
    size_t new_cp_page = page_align(new_cp_size);
    uint64_t new_cp = r->alloc(new_cp_page, false);

    auto header = r->read(orig_cp, header_size);
    r->write(new_cp, header.data(), header.size());
    auto entries = r->read(orig_cp + header_size, size_t(orig_length) * 8);
    r->write(new_cp + header_size, entries.data(), entries.size());
    // Tail slots are already zero (VirtualAllocEx gives zeroed pages).

    int32_t new_length_le = new_length;
    r->write(new_cp + length_off, &new_length_le, 4);

    int32_t orig_tags_len = r->read_i32(orig_tags + 0);
    if (orig_tags_len != orig_length)
        throw std::runtime_error("tags length != cp length");
    int32_t new_tags_bytes = orig_tags_len + extra_slots;
    size_t new_tags_alloc = ARRAY_DATA_OFFSET_U1 + size_t(new_tags_bytes);
    size_t new_tags_page = page_align(new_tags_alloc);
    uint64_t new_tags = r->alloc(new_tags_page, false);
    r->write(new_tags, &new_tags_bytes, 4);
    auto tag_bytes = r->read(orig_tags + ARRAY_DATA_OFFSET_U1, size_t(orig_tags_len));
    r->write(new_tags + ARRAY_DATA_OFFSET_U1, tag_bytes.data(), tag_bytes.size());

    uint64_t new_tags_ptr = new_tags;
    r->write(new_cp + tags_off, &new_tags_ptr, 8);
    uint64_t new_cp_ptr = new_cp;
    r->write(klass_ptr + constants_off, &new_cp_ptr, 8);

    CPClone clone{orig_cp, new_cp, new_cp_size, new_cp_page, klass_ptr};
    return {clone, new_length, orig_length, new_tags, orig_length};
}

void set_cp_tag(VMMeta* vm, const CPExtension& ext, int32_t index, uint8_t tag)
{
    vm->reader()->write(ext.new_tags_array + ARRAY_DATA_OFFSET_U1 + index, &tag, 1);
}

void set_cp_slot_u64(VMMeta* vm, const CPExtension& ext, int32_t index, uint64_t value)
{
    size_t header_size = vm->type("ConstantPool")->size;
    uint64_t slot = ext.clone.new_cp + header_size + size_t(index) * 8;
    vm->reader()->write(slot, &value, 8);
}

void set_cp_slot_name_and_type(VMMeta* vm, const CPExtension& ext, int32_t index,
                                uint16_t name_idx, uint16_t sig_idx)
{
    uint64_t packed = (uint64_t(sig_idx) << 16) | name_idx;
    set_cp_slot_u64(vm, ext, index, packed);
}

void set_cp_slot_methodref(VMMeta* vm, const CPExtension& ext, int32_t index,
                            uint16_t class_idx, uint16_t nat_idx)
{
    uint64_t packed = (uint64_t(nat_idx) << 16) | class_idx;
    set_cp_slot_u64(vm, ext, index, packed);
}

} // namespace marrow
