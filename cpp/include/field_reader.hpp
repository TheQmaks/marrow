#pragma once
// InstanceKlass field metadata reader. Handles both HotSpot layouts:
//   * Legacy Array<u2> (JDK 8-17): 6 u2 slots per FieldInfo, offset packed
//     in the last two slots.
//   * FieldInfoStream (JDK 18+): UNSIGNED5 variable-length encoding.
//
// Utf8 CP entries are resolved by reading the CP slot as Symbol* and
// decoding via walker::read_symbol.

#include "vm_meta.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace marrow {

struct FieldRecord {
    std::string name;
    std::string signature;
    int32_t     access_flags = 0;
    int32_t     offset = 0;
    bool        is_static = false;
};

std::vector<FieldRecord> read_fields(VMMeta* vm, uint64_t klass_ptr);
std::optional<FieldRecord> find_field(VMMeta* vm, uint64_t klass_ptr,
                                      const std::string& name);

} // namespace marrow
