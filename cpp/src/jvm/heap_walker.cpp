#include "heap_walker.hpp"
#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace marrow {

std::vector<uint64_t>
find_instances_by_klass(VMMeta* vm, OopDecoder* decoder,
                        uint64_t klass_ptr, size_t limit, size_t chunk_size)
{
    std::vector<uint64_t> found;
    if (!klass_ptr) return found;
    Reader* r = vm->reader();

    // Pre-encode the target Klass as narrow so we compare a single u32.
    const auto& kp = decoder->klass_params;
    uint32_t target_narrow;
    if (!kp.enabled()) {
        target_narrow = uint32_t(klass_ptr);
    } else {
        target_narrow = uint32_t((klass_ptr - kp.base) >> kp.shift);
    }

    // Restrict matches to the compressed-oop heap range so we exclude
    // class mirrors / metaspace / other regions that happen to contain
    // a u32 equal to target_narrow at offset +8. With heap_base = B and
    // shift = S, valid wide oops live in [B, B + 2^32 << S).
    //
    // When oops aren't compressed (large-heap mode), we fall back to a
    // looser upper bound to match historical behavior.
    uint64_t heap_lo = 0;
    uint64_t heap_hi = ~uint64_t(0);
    {
        const auto& op = decoder->oop_params;
        if (op.enabled() || decoder->oops_are_compressed()) {
            heap_lo = op.base;
            heap_hi = op.base + (uint64_t(1) << (32 + op.shift));
        }
    }

    std::unordered_set<uint64_t> seen;
    for (auto& region : r->enumerate_regions(/*writable_only*/true)) {
        if (region.size < 64 * 1024) continue;
        // Region overlap test against the heap window.
        uint64_t region_end = region.base + region.size;
        if (region_end <= heap_lo || region.base >= heap_hi) continue;
        for (uint64_t off = 0; off < region.size; off += chunk_size) {
            size_t part = size_t(std::min<uint64_t>(chunk_size, region.size - off));
            std::vector<uint8_t> buf;
            try { buf = r->read(region.base + off, part); }
            catch (...) { continue; }
            uint64_t part_base = region.base + off;
            // Walk at every 8-byte alignment; klass slot is at +8 (4 bytes).
            for (size_t pos = 0; pos + 12 <= buf.size(); pos += 8) {
                uint32_t narrow;
                std::memcpy(&narrow, buf.data() + pos + 8, 4);
                if (narrow != target_narrow) continue;
                uint64_t oop_addr = part_base + pos;
                // Final fence: the candidate address itself must encode
                // back into a valid narrow oop within the heap window.
                if (oop_addr < heap_lo || oop_addr >= heap_hi) continue;

                // Mark-word sanity. HotSpot mark word low bits encode the
                // object's lock state — values 00b/01b/10b/11b are valid,
                // but a mark word of all zeros indicates we're inside a
                // primitive array's payload rather than at a real header.
                // Scanning into a Long[] body or String's value[] yields
                // candidates whose +8 narrow happens to equal our target's
                // narrow_klass; filtering by mark != 0 culls these.
                uint64_t mark = 0;
                std::memcpy(&mark, buf.data() + pos, 8);
                if (mark == 0) continue;

                if (seen.insert(oop_addr).second) {
                    found.push_back(oop_addr);
                    if (limit && found.size() >= limit) return found;
                }
            }
        }
    }
    return found;
}

} // namespace marrow
