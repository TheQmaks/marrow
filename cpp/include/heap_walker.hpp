#pragma once
// Brute-force heap scanner: enumerate every committed writable page in
// the target process and test each 8-aligned qword for a valid object
// header whose narrow-klass slot matches a given Klass*.
//
// Layout-agnostic — works identically on every GC without needing
// region-walking exports. Slower than a native iterator but portable.

#include "oop_reader.hpp"
#include "vm_meta.hpp"
#include <cstdint>
#include <optional>
#include <vector>

namespace marrow {

// Return oop addresses whose narrow-klass slot resolves to `klass_ptr`.
// `limit == 0` means "all matches". Scans in `chunk_size`-byte reads.
std::vector<uint64_t>
find_instances_by_klass(VMMeta* vm, OopDecoder* decoder,
                        uint64_t klass_ptr,
                        size_t limit = 0,
                        size_t chunk_size = 4 * 1024 * 1024);

} // namespace marrow
