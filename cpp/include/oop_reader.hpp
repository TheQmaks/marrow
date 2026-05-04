#pragma once
// Oop / narrow-pointer decoder. Ports jvm-probe/oop_reader.py.
//
// Resolves CompressedOops + CompressedKlassPointers parameters from VM
// globals, decodes narrow pointers into wide addresses, dereferences
// OopHandles, and probes object headers for Klass*.
//
// Oop-storage size (4 vs 8 bytes in Java reference fields) is independent
// of klass-storage size on JDK 17+: `-XX:-UseCompressedOops` leaves
// `UseCompressedClassPointers` on. We probe each separately — oop size via
// `CollectedHeap::_reserved._start` low-4GB heuristic, klass size via
// `klass_params.enabled`.

#include "vm_meta.hpp"
#include <cstdint>
#include <optional>
#include <vector>

namespace marrow {

struct NarrowParams {
    uint64_t base  = 0;
    int32_t  shift = 0;
    bool enabled() const { return base != 0 || shift != 0; }
    uint64_t decode(uint64_t narrow) const {
        if (narrow == 0) return 0;
        return (narrow << shift) + base;
    }
};

class OopDecoder {
public:
    explicit OopDecoder(VMMeta* vm);

    NarrowParams oop_params;
    NarrowParams klass_params;

    bool oops_are_compressed();
    bool compressed_klass() { return compressed_klass_.value_or(false); }

    uint64_t decode_oop(uint64_t narrow)  const { return oop_params.decode(narrow); }
    uint64_t decode_klass(uint64_t narrow) const { return klass_params.decode(narrow); }

    // encode wide oop -> narrow. Throws runtime_error if out of range.
    uint32_t encode_oop(uint64_t wide) const;

    // Given the value of OopHandle::_obj (pointer to storage slot), read the
    // wide oop stored there. Storage slots in oopStorage are always wide.
    uint64_t deref_oop_handle(uint64_t obj_slot_ptr);

    // Follow Shenandoah / STW mark-word forwarding if present.
    uint64_t resolve_forwarding(uint64_t oop_addr);

    // Return Klass* for a live oop, handling compressed klass pointers.
    uint64_t klass_of(uint64_t oop_addr);

private:
    NarrowParams resolve_params(const std::vector<std::tuple<const char*, const char*, const char*>>& cands);
    uint64_t probe_heap_base();
    uint64_t probe_live_oop();
    void prime_from_static();
    bool probe_klass_mode(uint64_t slot);
    bool klass_looks_valid(uint64_t klass_ptr);

    VMMeta* vm_;
    Reader* r_;
    bool has_compressed_oops_type_ = false;
    size_t klass_slot_offset_ = 8;
    size_t name_offset_ = 0;
    std::optional<bool> compressed_klass_;
    std::optional<bool> oops_compressed_;
};

} // namespace marrow
