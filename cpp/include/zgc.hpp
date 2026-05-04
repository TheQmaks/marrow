#pragma once
// ZGC coloured-pointer decoder. Two formats:
//   * Classic (JDK 15..20): colour bits in high positions; load-good
//     pointers are directly dereferenceable.
//   * Generational (JDK 21+ with -XX:+ZGenerational, JDK 25 default):
//     colour bits in low `ZPointerLoadShift` positions; heap address is
//     `raw >> shift`.
//
// Re-reads shift/masks on every call so a GC-phase flip between calls
// doesn't silently break decoding.

#include "vm_meta.hpp"
#include <cstdint>

namespace marrow {

// String reader already uses a minimal ZGCDecoder interface; we implement
// the full one here and keep the same vtable so existing callers link.
class ZGCDecoder {
public:
    enum class Mode { Off, Classic, Generational };

    static ZGCDecoder detect(VMMeta* vm);

    ZGCDecoder() = default;

    virtual ~ZGCDecoder() = default;
    virtual bool is_active() const { return mode_ != Mode::Off; }
    virtual uint64_t decode(uint64_t raw);

    Mode mode() const { return mode_; }
    uint64_t instance() const { return instance_; }

    // Encode a wide heap address back into a coloured value fit for a store.
    uint64_t encode_for_store(uint64_t heap_addr);

    bool is_load_bad(uint64_t raw);

private:
    ZGCDecoder(VMMeta* vm, Mode mode, uint64_t instance,
               uint64_t offset_mask_ptr, uint64_t load_shift_ptr,
               uint64_t load_bad_mask_ptr,
               uint64_t store_good_ptr, uint64_t address_good_ptr);

    bool is_load_bad_now(uint64_t raw);

    VMMeta* vm_ = nullptr;
    Mode mode_ = Mode::Off;
    uint64_t instance_ = 0;
    uint64_t offset_mask_ptr_ = 0;
    uint64_t load_shift_ptr_ = 0;
    uint64_t load_bad_mask_ptr_ = 0;
    uint64_t store_good_ptr_ = 0;
    uint64_t address_good_ptr_ = 0;
};

} // namespace marrow
