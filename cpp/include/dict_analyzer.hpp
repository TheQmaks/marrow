#pragma once
// Dynamic layout discoverer for HotSpot's SystemDictionary tables.
//
// HotSpot stopped exporting Dictionary/DictionaryEntry instance fields
// to vmStructs around JDK 15, so we score every plausible offset
// combination against live target memory and pick the one whose entry
// chains validate as Klass*-bearing entries.
//
// Returns std::nullopt on JDK 21+ where the Dictionary type itself isn't
// exported anymore.

#include "vm_meta.hpp"
#include <cstdint>
#include <optional>

namespace marrow {

struct DictLayout {
    size_t table_size_off;
    size_t buckets_off;
    size_t entry_hash_off;     // ~always 0
    size_t entry_next_off;     // ~always 8
    size_t entry_literal_off;  // 16 or 24
    size_t entry_size;         // 32 or 40
};

// Score a candidate end-to-end by walking entry chains and counting
// how many resolve to a plausible Klass with a readable Symbol name.
int validate_layout(VMMeta* vm, uint64_t dict_ptr, const DictLayout& l);

// Find layout for one given Dictionary*. nullopt if no high-scoring
// combination exists.
std::optional<DictLayout>
find_dictionary_layout(VMMeta* vm, uint64_t dict_ptr);

// Walk every CLD's `_dictionary` and pick the first layout that scores
// well. Layouts are stable within a JVM, so reusing the boot loader's
// large dictionary works even when later operations target a thinner
// application dictionary.
std::optional<DictLayout> discover_dict_layout(VMMeta* vm);

} // namespace marrow
