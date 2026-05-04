#pragma once
// TLAB hijack allocator. Without JNI/JVMTI we can't drive MemAllocator
// directly, but TLAB allocation is just a bump of `_top` in the
// ThreadLocalAllocBuffer of a JavaThread. Suspend every mutator, bump
// the pointer, write an object header — done.
//
// Limitations: ignores slow-path layout_helper bits (Finalizer etc.);
// concurrent GC threads (G1 marking, ZGC) may still be active during
// the suspend window; no TLAB refill if none has capacity.

#include "oop_reader.hpp"
#include "vm_meta.hpp"
#include "zgc.hpp"
#include <cstdint>
#include <stdexcept>
#include <utility>

namespace marrow {

class AllocationError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class TLABAllocator {
public:
    // `zgc` may be nullptr when the target isn't running under ZGC. When
    // supplied and active, mirror oops get uncoloured before dereference
    // so `borrow_mark_word` reads the real mark.
    TLABAllocator(VMMeta* vm, OopDecoder* decoder, ZGCDecoder* zgc = nullptr);

    // Allocate a zero-init instance of `klass`. Returns the wide oop.
    uint64_t allocate_instance(uint64_t klass_ptr);

    // Allocate a primitive-type array of `length` elements, zero-init.
    uint64_t allocate_type_array(uint64_t klass_ptr, int32_t length);

    // Offsets for callers filling payload after allocation.
    size_t array_data_offset()   const;
    size_t array_length_offset() const;

private:
    std::vector<uint32_t> collect_tids();
    std::vector<void*>    suspend_all(const std::vector<uint32_t>& tids);
    void                  resume_all(const std::vector<void*>& handles);

    std::tuple<uint64_t, uint64_t, uint64_t> pick_tlab(size_t bytes_needed);
    void commit_tlab_top(uint64_t thread_ptr, uint64_t new_top);
    uint64_t borrow_mark_word(uint64_t klass_ptr);
    std::pair<uint64_t, uint64_t> alloc_raw(size_t size_bytes);
    uint32_t encode_narrow_klass(uint64_t klass_ptr);
    void write_header(uint64_t oop, uint64_t klass_ptr);

    VMMeta* vm_;
    Reader* r_;
    OopDecoder* dec_;
    ZGCDecoder* zgc_;
    size_t off_thread_tlab_ = 0;
    size_t off_tlab_top_ = 0;
    size_t off_tlab_end_ = 0;
    size_t off_klass_layout_ = 0;
};

} // namespace marrow
