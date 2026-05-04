#pragma once
// JDK 21/25 Level-3 strategy via hooking JVM_FindClassFromCaller.
//
// SystemDictionary's class-lookup data structures (ConcurrentHashTable)
// aren't exported to vmStructs on JDK 21+, so we can't modify them
// directly. Instead we inline-patch the exported JNI entry point
// `JVM_FindClassFromCaller(env, const char* name, init, loader, caller)`:
//
//   1. Copy the first N bytes of the original onto our trampoline page
//      (the "saved prologue" for fall-through).
//   2. Append a JMP to `original + N` so the trampoline behaves as the
//      un-hooked function.
//   3. Allocate our hook page with shellcode that:
//        a. Compares `RDX` (const char* name) to a fixed byte sequence
//           ("Target\0").
//        b. On match: `RAX = fake_handle_slot; RET` (returns a JNI handle
//           whose contents point at the clone's java.lang.Class oop).
//        c. On miss: executes the saved prologue in-place, then JMPs to
//           `original + N` to continue the un-hooked path.
//   4. Overwrite `original[0..5]` with a 5-byte `JMP REL32` that lands
//      on the hook page.
//
// Works per-JDK because `N` and the exact prologue bytes vary. We pick
// `N = 5` for JDKs whose first instruction is exactly 5 bytes long;
// otherwise we skip past the shortest set of whole instructions that
// total at least 5 bytes.

#include "vm_meta.hpp"
#include <cstdint>
#include <string>

namespace marrow {

struct SysDictHook {
    uint64_t original_fn;        // JVM_FindClassFromCaller start
    uint64_t hook_page;          // our shellcode
    uint64_t trampoline_page;    // saved-prologue + jmp-back
    uint64_t fake_handle_slot;   // 8-byte slot containing our mirror oop
    uint64_t clone_mirror;       // mirror oop we want Class.forName to return
    uint8_t  orig_prologue[16];  // copy of clobbered bytes
    size_t   prologue_len;       // N — how many bytes we clobbered
};

// Patch `JVM_FindClassFromCaller`. When called with `name == "<target_name>"`
// it returns a jclass backed by `mirror_oop` instead of delegating to
// SystemDictionary. Symbol/mirror setup (TLAB-allocate a java.lang.Class
// instance, populate it, pass `mirror_oop` here) is the caller's job —
// same pattern as `replace_class_in_sysdict`.
// Legacy: throws. Use install_sysdict_hook_full instead.
SysDictHook install_sysdict_hook(VMMeta* vm, const std::string& target_name,
                                  uint64_t mirror_oop);

// Diagnostic passthrough — always tail-jumps to trampoline (no compare,
// no swap). Tests the trampoline infrastructure alone.
SysDictHook install_sysdict_hook_passthrough(VMMeta* vm);

// Wrapper variant: matches on target_name, calls original to get a
// valid JNI local ref, swaps donor oop -> clone oop in the returned
// handle slot. Requires both mirrors because the swap is conditional.
SysDictHook install_sysdict_hook_full(VMMeta* vm, const std::string& target_name,
                                       uint64_t donor_mirror_oop,
                                       uint64_t clone_mirror_oop);

void uninstall_sysdict_hook(VMMeta* vm, const SysDictHook& h);

} // namespace marrow
