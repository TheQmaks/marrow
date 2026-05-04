#pragma once
// Locate a per-JavaThread SATBMarkQueue by plausibility scan of the
// `_gc_data` region. Shenandoah (JDK 11+) keeps its queue nested inside
// ShenandoahThreadLocalData, which HotSpot doesn't export to vmStructs.
// We scan aligned qwords past the last exported JavaThread field,
// filtering by (index, buf, active) plausibility.

#include "vm_meta.hpp"
#include <cstdint>
#include <vector>

namespace marrow {

struct SATBQueueProbe {
    uint64_t offset_in_thread;
    uint64_t index;
    uint64_t buf;
    bool     active;
};

// Return plausible queue candidates in ascending offset order.
// `max_candidates == 0` means return all; default 1 keeps it to the first.
std::vector<SATBQueueProbe>
find_satb_queue(VMMeta* vm, uint64_t java_thread, size_t max_candidates = 1);

} // namespace marrow
