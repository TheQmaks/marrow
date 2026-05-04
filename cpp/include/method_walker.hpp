#pragma once
// Method walker + bytecode patcher. Exposes enumeration of Java methods
// on an InstanceKlass plus in-place bytecode rewriting with JIT
// invalidation. Underpins our invoke hack: replace a method body and let
// the target invoke it naturally.

#include "vm_meta.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace marrow {

struct MethodSnapshot {
    uint64_t address;       // Method*
    uint64_t const_method;  // ConstMethod*
    std::string name;
    std::string signature;
    uint32_t code_size;
    uint64_t code_base;     // absolute address of first bytecode byte
};

std::vector<MethodSnapshot> methods_of(VMMeta* vm, uint64_t klass_ptr);
std::optional<MethodSnapshot>
find_method(VMMeta* vm, uint64_t klass_ptr,
            const std::string& name,
            const std::optional<std::string>& signature = std::nullopt);

// Overwrite a method's bytecode in-place and invalidate the JIT version.
// new_bytecode must be <= method.code_size; tail is padded with nops.
void rewrite_method_body(VMMeta* vm, const MethodSnapshot& method,
                          const std::vector<uint8_t>& new_bytecode);

// Return-void bytecode for V-type methods (single byte, 0xB1).
std::vector<uint8_t> make_nop_return();

} // namespace marrow
