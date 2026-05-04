#pragma once
// Native method-entry hook via `_from_interpreted_entry` patching. We
// VirtualAllocEx a 52-byte x64 trampoline, point the method's entries
// at it, and the trampoline `lock inc`s a shared counter then tail-calls
// the original entry. Polling the counter from our process gives a
// pre-invocation hook without touching the method's bytecode.

#include "method_walker.hpp"
#include "vm_meta.hpp"
#include <cstdint>

namespace marrow {

struct MethodHook {
    VMMeta* vm;
    MethodSnapshot method;
    uint64_t counter_addr;
    uint64_t trampoline_addr;
    uint64_t original_interpreted_entry;
    uint64_t original_compiled_entry;
    uint64_t original_code;
    // Second trampoline used by install_callback_hook_full so JIT'd
    // callers don't lose register-args on the way to the interpreter.
    // Zero when only one trampoline is installed.
    uint64_t secondary_trampoline_addr = 0;

    // Inline-detour id for the nmethod's verified_entry_point (set by
    // install_callback_hook_full when the method was JIT'd at hook-install
    // time). -1 means no JIT detour was installed. JIT-resolved callers
    // jump straight into the nmethod's entry; patching `_from_compiled_entry`
    // on the Method* doesn't affect them, so we ALSO detour the verified
    // entry of the existing nmethod to catch already-resolved call sites.
    int jit_detour_id = -1;
    // VA of nmethod's verified_entry_point at hook time — kept for diagnostics
    // only. Zero when no JIT detour is in place.
    uint64_t jit_detour_va = 0;
    // Diagnostic: which VMMeta type yielded _verified_entry_point.
    // 0=none, 1=nmethod, 2=CompiledMethod.
    int jit_detour_vep_src = 0;

    uint64_t read_count() const;
    void uninstall();
};

// Plant a per-call counter in front of `method`. Works even if the method
// has been JIT-compiled: we null `_code` and point both the interpreted-
// and compiled-entry slots at our trampoline.
MethodHook install_counting_hook(VMMeta* vm, const MethodSnapshot& method);

// Callback hook context — passed to user function on each method entry.
// Keep POD (no constructors) so it's easy to fill via raw memory writes
// from shellcode.
//
// `regs` snapshot: indexed by AMD64 register number (RAX=0, RCX=1, RDX=2,
// RBX=3, RSP=4, RBP=5, RSI=6, RDI=7, R8..R15=8..15). Captured by the
// trampoline RIGHT AT entry (before any of our save/align scratch).
// `stack` snapshot: 16 qwords starting at the return address. stack[0]
// is the return-to-caller pointer; stack[1..] are caller-pushed args
// for stack-arg conventions or interpreter expression-stack values.
struct HookContext {
    uint64_t method;       // Method* we hooked                        (+0)
    uint64_t userdata;     // opaque cookie                            (+8)
    uint64_t fire_count;   // dispatch-bumped counter                  (+16)
    uint64_t cb_ptr;       // HookCallback function pointer            (+24)
    uint64_t via;          // 0 = via _fie, 1 = via _fce               (+32)
    uint8_t  skip_orig;    // dispatch sets to 1 → trampoline RET     (+40)
                           //    instead of tail-jmp to orig
    uint8_t  pad[7];       //                                          (+41..47)
    uint64_t replace_rax;  // value loaded into rax when skip_orig=1   (+48)
    uint64_t regs[16];     // RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8..R15  (+56)
    uint64_t stack[16];    // 16 qwords starting at original RSP       (+184)
};
// Trampoline ASM hardcodes the offsets below — keep struct field layout
// in sync with these constants:
//   skip_orig    @ +40
//   replace_rax  @ +48

using HookCallback = void (*)(HookContext* ctx);

// Plant a callback hook in front of `method`. On each entry the trampoline
// saves volatile regs, aligns the stack, calls `cb(ctx)`, restores state,
// and tail-jumps to the original entry. Windows x64 calling convention.
//
// Caller is responsible for ensuring `cb` stays alive as long as the hook
// is installed. Use `MethodHook::uninstall` to remove.
MethodHook install_callback_hook(VMMeta* vm, const MethodSnapshot& method,
                                  HookCallback cb, uint64_t userdata = 0);

// Same as install_callback_hook but the trampoline ALSO snapshots all 14
// GPRs (RAX, RCX, RDX, RBP, RSI, RDI, R8..R15) plus a small slice of the
// caller's stack into ctx->regs[]/ctx->stack[] before invoking `cb`.
// Slightly larger (~128 bytes) but enables argument inspection from JS.
//
// When the method is already JIT-compiled at install time, ALSO detours
// `nmethod._verified_entry_point` via the inline-hook engine so existing
// JIT'd callers (whose call sites are already resolved to the old entry)
// keep firing the hook. Requires the agent to have registered the engine
// via `register_jit_detour_hooks` — silently disabled in core-only builds.
MethodHook install_callback_hook_full(VMMeta* vm, const MethodSnapshot& method,
                                       HookCallback cb, uint64_t userdata = 0);

// Registration hook: the agent DLL calls this at startup to inject its
// inline-hook engine entry points. Until called, JIT detours are no-ops.
using InstallJitDetourFn   = int  (*)(void* target, uint64_t ctx, uint64_t dispatch, uint32_t via);
using UninstallJitDetourFn = bool (*)(int id);
void register_jit_detour_hooks(InstallJitDetourFn inst, UninstallJitDetourFn uninst);

} // namespace marrow
