#include "zgc.hpp"

namespace marrow {

ZGCDecoder::ZGCDecoder(VMMeta* vm, Mode mode, uint64_t instance,
                       uint64_t offset_mask_ptr, uint64_t load_shift_ptr,
                       uint64_t load_bad_mask_ptr,
                       uint64_t store_good_ptr, uint64_t address_good_ptr)
    : vm_(vm), mode_(mode), instance_(instance),
      offset_mask_ptr_(offset_mask_ptr),
      load_shift_ptr_(load_shift_ptr),
      load_bad_mask_ptr_(load_bad_mask_ptr),
      store_good_ptr_(store_good_ptr),
      address_good_ptr_(address_good_ptr) {}

ZGCDecoder ZGCDecoder::detect(VMMeta* vm)
{
    if (!vm->has_type("ZGlobalsForVMStructs")) return ZGCDecoder{};
    const TypeInfo* zg = vm->type("ZGlobalsForVMStructs");
    if (!zg->has_field("_instance_p")) return ZGCDecoder{};
    uint64_t inst = vm->reader()->read_u64(zg->field("_instance_p")->address);
    if (!inst) return ZGCDecoder{};

    auto ptr_of = [&](const char* name) -> uint64_t {
        if (!zg->has_field(name)) return 0;
        return vm->reader()->read_u64(inst + zg->field(name)->offset);
    };

    uint64_t gen_shift   = ptr_of("_ZPointerLoadShift");
    uint64_t gen_good    = ptr_of("_ZPointerLoadGoodMask");
    uint64_t gen_bad     = ptr_of("_ZPointerLoadBadMask");
    uint64_t cls_offset  = ptr_of("_ZAddressOffsetMask");
    uint64_t cls_good    = ptr_of("_ZAddressGoodMask");
    uint64_t cls_bad     = ptr_of("_ZAddressBadMask");
    uint64_t gen_store   = ptr_of("_ZPointerStoreGoodMask");

    if (gen_good && vm->reader()->read_u64(gen_good) != 0
            && gen_shift && vm->reader()->read_u64(gen_shift) > 0) {
        return ZGCDecoder(vm, Mode::Generational, inst,
                          /*offset*/0, gen_shift, gen_bad, gen_store, 0);
    }
    if (cls_good && vm->reader()->read_u64(cls_good) != 0 && cls_offset) {
        return ZGCDecoder(vm, Mode::Classic, inst,
                          cls_offset, 0, cls_bad, 0, cls_good);
    }
    return ZGCDecoder{};
}

bool ZGCDecoder::is_load_bad_now(uint64_t raw)
{
    if (!load_bad_mask_ptr_) return false;
    return (raw & vm_->reader()->read_u64(load_bad_mask_ptr_)) != 0;
}

uint64_t ZGCDecoder::decode(uint64_t raw)
{
    if (raw == 0 || mode_ == Mode::Off) return raw;
    if (mode_ == Mode::Classic) return raw; // already dereferenceable
    for (int retry = 0; retry < 2; ++retry) {
        uint64_t shift = vm_->reader()->read_u64(load_shift_ptr_);
        uint64_t cand = raw >> shift;
        if (!is_load_bad_now(raw)) return cand;
    }
    return raw >> vm_->reader()->read_u64(load_shift_ptr_);
}

uint64_t ZGCDecoder::encode_for_store(uint64_t heap_addr)
{
    if (heap_addr == 0 || mode_ == Mode::Off) return heap_addr;
    if (mode_ == Mode::Generational) {
        uint64_t store_good = store_good_ptr_ ? vm_->reader()->read_u64(store_good_ptr_) : 0;
        uint64_t shift = vm_->reader()->read_u64(load_shift_ptr_);
        return (heap_addr << shift) | store_good;
    }
    if (address_good_ptr_) {
        uint64_t good = vm_->reader()->read_u64(address_good_ptr_);
        uint64_t mask = offset_mask_ptr_
            ? vm_->reader()->read_u64(offset_mask_ptr_)
            : 0xFFFFFFFFFFFFFFFFull;
        return (heap_addr & mask) | good;
    }
    return heap_addr;
}

bool ZGCDecoder::is_load_bad(uint64_t raw)
{
    if (mode_ != Mode::Generational || !load_bad_mask_ptr_) return false;
    uint64_t bad = vm_->reader()->read_u64(load_bad_mask_ptr_);
    return (raw & bad) != 0;
}

} // namespace marrow
