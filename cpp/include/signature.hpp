#pragma once
// Java method-descriptor parser + CPCacheEntry._flags synthesizer.
// HotSpot's legacy inline CPCacheEntry stores param size at bits 0-7 and
// Top-Of-Stack state at bits 24-27. When extending the cache with a new
// entry for a method whose signature differs from our donor template,
// we must patch those fields so the interpreter dispatches correctly.

#include <cstdint>
#include <string>
#include <utility>

namespace marrow {

enum TosState : uint32_t {
    TOS_BTOS = 0, TOS_ZTOS = 1, TOS_CTOS = 2, TOS_STOS = 3,
    TOS_ITOS = 4, TOS_LTOS = 5, TOS_FTOS = 6, TOS_DTOS = 7,
    TOS_ATOS = 8, TOS_VTOS = 9,
};

// Return (parameter_size_in_slots, return_TosState).
// Slot counts: J/D = 2 slots, everything else 1. `this` receiver adds 1
// for non-static methods.
std::pair<uint32_t, TosState>
parse_descriptor(const std::string& sig, bool is_static = true);

// Splice param-size + TosState into `donor_flags`; preserve every other
// bit (is_vfinal, is_final, is_volatile, etc.).
uint32_t synth_flags_legacy(uint32_t donor_flags, const std::string& sig,
                            bool is_static = true);

} // namespace marrow
