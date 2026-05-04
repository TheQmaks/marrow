#pragma once
// ConstantPoolCache introspection + extension. Two layouts:
//   Legacy (JDK 8-21): inline ConstantPoolCacheEntry array past the cache
//     header. `_indices` packs (cp_index, b1, b2) in the low 32 bits.
//   Modern (JDK 25): `Array<ResolvedMethodEntry>* _resolved_method_entries`.
//     `_cpool_index` is a u2 inside each entry.

#include "vm_meta.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace marrow {

struct CacheEntryInfo {
    int32_t  index;
    uint64_t indices_raw;
    uint16_t cp_index;
    uint64_t f1;
    uint8_t  b1;  // original bytecode opcode (invokestatic = 0xB8)
};

struct CacheTemplate {
    uint64_t source_klass;
    uint64_t source_cache;
    std::vector<uint8_t> entry_bytes;
};

// Return ConstantPoolCache* for a ConstantPool*. `_cache` is at offset 16
// on every JDK we support.
uint64_t find_cpcache(VMMeta* vm, uint64_t cp_ptr);

std::vector<CacheEntryInfo>
iterate_cpcache_entries_legacy(VMMeta* vm, uint64_t cpcache);

struct ExtendCPCacheResult {
    uint64_t old_cpcache;
    uint64_t new_cpcache;
    std::vector<int32_t> new_entry_indices;
};

// Parallel vectors: new_cp_indices[i] = (cp_index, b1). sigs/is_static/
// override_f1 may be empty; otherwise must be same length as the first.
struct NewEntrySpec {
    uint16_t cp_index;
    uint8_t  b1;
    std::optional<std::string> sig;       // if set, synth flags from descriptor
    bool     is_static = true;
    uint64_t override_f1 = 0;             // 0 = keep donor's
};

ExtendCPCacheResult clone_and_extend_cpcache_legacy(
    VMMeta* vm, uint64_t cp_ptr,
    const std::vector<NewEntrySpec>& new_entries);

struct ExtendRMEResult {
    uint64_t old_array;
    uint64_t new_array;
    std::vector<int32_t> new_entry_indices;
};

ExtendRMEResult clone_and_extend_cpcache_modern(
    VMMeta* vm, uint64_t cp_ptr,
    const std::vector<uint16_t>& new_cp_indices);

// Return cache index (legacy) or array index (modern) whose entry resolves
// CP[cp_index] for the given bytecode. nullopt when not found.
std::optional<int32_t>
cache_index_for_cp(VMMeta* vm, uint64_t cp_ptr, uint16_t cp_index,
                   uint8_t bytecode = 0xB8);

// Walk every loaded InstanceKlass and collect CPCache entries whose `_b1`
// matches `bytecode`. Used when the target class's own cache has no donor.
std::vector<CacheTemplate>
scan_all_caches_for_template(VMMeta* vm, uint8_t bytecode);

} // namespace marrow
