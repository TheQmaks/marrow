// agent_invoke.cpp — Marrow._invokeStatic / _invokeInstance bindings.
//
// Allocates a small ASM thunk (lazily, once per process) that bridges Win x64
// calling convention to HotSpot's Java ABI (verified empirically on JDK 17):
//
//   Win x64 entry:  rcx = Method*, rdx = this_oop, r8 = uint64_t arg[4]
//   Java ABI:       rcx = this,  r8/r9/rdi/rsi = args[0..3], rbx = Method*
//
// The thunk is written as a hand-assembled byte template with a 4-byte
// placeholder for the _from_compiled_entry offset, patched at install time.
//
// JS surface:
//   Marrow._invokeInstance(mlo,mhi, tlo,thi, a0lo,a0hi, a1lo,a1hi,
//                                               a2lo,a2hi, a3lo,a3hi) -> hexstr
//   Marrow._invokeStatic  (mlo,mhi, a0lo,a0hi, a1lo,a1hi,
//                                     a2lo,a2hi, a3lo,a3hi)           -> hexstr
//
// All 64-bit values are split into (lo:uint32, hi:uint32) pairs because
// Duktape's duk_uint is 32-bit.

#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "duktape.h"

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <mutex>

#include <windows.h>   // VirtualAlloc / VirtualProtect in-process fallback

namespace marrow {

// ---------------------------------------------------------------------------
// Thunk template (hand-assembled x86-64, 64 bytes)
//
// Entry convention (Win x64):
//   rcx = Method*
//   rdx = this_oop   (0 for static)
//   r8  = &args[4]   (uint64_t array, may be nullptr only if caller passes 0)
//
// The 4-byte field at THUNK_FCE_OFF is the offset of _from_compiled_entry
// within Method*, stored little-endian, patched before the page is made exec.
// ---------------------------------------------------------------------------
static constexpr size_t THUNK_SIZE    = 64;
static constexpr size_t THUNK_FCE_OFF = 10; // byte offset of the imm32 in MOV RAX,[RCX+imm32]

// clang-format off
static const uint8_t THUNK_TEMPLATE[THUNK_SIZE] = {
    // ---- save callee-saved regs and make room for shadow space ----
    0x53,                               // 00: push rbx
    0x57,                               // 01: push rdi
    0x56,                               // 02: push rsi
    0x48, 0x83, 0xEC, 0x28,             // 03: sub rsp, 0x28  (shadow 0x20 + 8 re-align)

    // ---- rbx = Method* ----
    0x48, 0x89, 0xCB,                   // 07: mov rbx, rcx

    // ---- rax = Method->_from_compiled_entry ----
    // 48 8B 81 [imm32]  — offset patched at THUNK_FCE_OFF (byte 10)
    0x48, 0x8B, 0x81, 0x00, 0x00, 0x00, 0x00,  // 10: mov rax, [rcx + fce_offset]

    // ---- rcx = this_oop (was rdx) ----
    0x48, 0x89, 0xD1,                   // 17: mov rcx, rdx

    // ---- load args from r8-based buffer BEFORE clobbering r8 ----
    // Java args: r8=args[0], r9=args[1], rdi=args[2], rsi=args[3]
    0x4D, 0x8B, 0x48, 0x08,             // 20: mov r9,  [r8+8]
    0x49, 0x8B, 0x78, 0x10,             // 24: mov rdi, [r8+16]
    0x49, 0x8B, 0x70, 0x18,             // 28: mov rsi, [r8+24]
    0x4D, 0x8B, 0x00,                   // 32: mov r8,  [r8]      ; last — clobbers r8

    // ---- call the compiled entry ----
    0xFF, 0xD0,                         // 35: call rax

    // ---- epilogue ----
    0x48, 0x83, 0xC4, 0x28,             // 37: add rsp, 0x28
    0x5E,                               // 41: pop rsi
    0x5F,                               // 42: pop rdi
    0x5B,                               // 43: pop rbx
    0xC3,                               // 44: ret

    // ---- padding to reach THUNK_SIZE ----
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
};
// clang-format on

// ---------------------------------------------------------------------------
// Thunk page — lazy singleton
// ---------------------------------------------------------------------------
struct ThunkPage {
    using JavaThunk = uint64_t (*)(uint64_t method_ptr,
                                   uint64_t this_oop,
                                   uint64_t* args) noexcept;
    JavaThunk fn    = nullptr;
    uint64_t  thunk_addr = 0; // remote address (for RemoteReader::alloc path)
    bool      remote = false; // true if allocated via vm->reader()->alloc
};

static std::mutex g_thunk_mu;
static ThunkPage  g_thunk;
static bool       g_thunk_ready = false;

// Allocate and install the thunk. Returns false on failure.
// Must be called with g_thunk_mu held only by the caller after checking
// g_thunk_ready (double-checked under lock).
static bool install_thunk(VMMeta* vm) {
    // Resolve _from_compiled_entry offset
    const TypeInfo* mt = vm->type("Method");
    if (!mt) return false;
    const FieldInfo* fce_fi = mt->field("_from_compiled_entry");
    if (!fce_fi) return false;
    uint32_t fce_off = static_cast<uint32_t>(fce_fi->offset);

    // Patch the template
    uint8_t buf[THUNK_SIZE];
    std::memcpy(buf, THUNK_TEMPLATE, THUNK_SIZE);
    std::memcpy(buf + THUNK_FCE_OFF, &fce_off, 4);

    // Try in-process VirtualAlloc first (agent runs inside the JVM process).
    // RemoteReader::alloc would also work but requires cross-process write.
    void* page = VirtualAlloc(nullptr, THUNK_SIZE,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!page) return false;
    std::memcpy(page, buf, THUNK_SIZE);
    // Harden: downgrade to RX
    DWORD old;
    VirtualProtect(page, THUNK_SIZE, PAGE_EXECUTE_READ, &old);

    g_thunk.fn     = reinterpret_cast<ThunkPage::JavaThunk>(page);
    g_thunk.remote = false;
    return true;
}

static ThunkPage::JavaThunk get_thunk(VMMeta* vm) {
    if (g_thunk_ready) return g_thunk.fn;
    std::lock_guard<std::mutex> lk(g_thunk_mu);
    if (g_thunk_ready) return g_thunk.fn;
    if (install_thunk(vm)) g_thunk_ready = true;
    return g_thunk.fn;
}

// ---------------------------------------------------------------------------
// Helper: reconstruct a uint64_t from two consecutive duk_uint stack args
// ---------------------------------------------------------------------------
static uint64_t pop_u64_from(duk_context* ctx, duk_idx_t lo_idx) {
    uint64_t lo = static_cast<uint64_t>(duk_require_uint(ctx, lo_idx));
    uint64_t hi = static_cast<uint64_t>(duk_require_uint(ctx, lo_idx + 1));
    return lo | (hi << 32);
}

// ---------------------------------------------------------------------------
// JIT guard — reads Method::_code from in-process memory.
// Returns 0 if the field is absent from vmStructs (treat as unknown = allow).
// Returns the _code pointer value otherwise.
// Kept in a separate function so do_invoke's __try block has no live dtors.
// ---------------------------------------------------------------------------
static uint64_t read_method_code_ptr(VMMeta* vm, uint64_t method_ptr) {
    const TypeInfo* mt = vm->type("Method");
    if (!mt) return static_cast<uint64_t>(-1); // unknown → let caller proceed
    const FieldInfo* code_fi = mt->field("_code");
    if (!code_fi) return static_cast<uint64_t>(-1); // unknown → let caller proceed
    uint64_t code_ptr = 0;
    std::memcpy(&code_ptr,
                reinterpret_cast<const void*>(
                    static_cast<uintptr_t>(method_ptr) + code_fi->offset),
                sizeof(code_ptr));
    return code_ptr;
}

// ---------------------------------------------------------------------------
// SEH wrapper — no local dtors in scope, so MSVC accepts __try.
// ---------------------------------------------------------------------------
static uint64_t call_thunk_seh(ThunkPage::JavaThunk thunk,
                                uint64_t method_ptr,
                                uint64_t this_oop,
                                uint64_t* args,
                                bool* threw) noexcept {
    uint64_t result = 0;
    *threw = false;
    __try {
        result = thunk(method_ptr, this_oop, args);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *threw = true;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Common invoke core — used by both _invokeStatic and _invokeInstance
// ---------------------------------------------------------------------------
static duk_ret_t do_invoke(duk_context* ctx,
                            uint64_t method_ptr,
                            uint64_t this_oop,
                            uint64_t* args /*[4]*/) {
    VMMeta* vm = current_vm(ctx);
    if (!vm) {
        duk_push_string(ctx, "no vm");
        return 1;
    }

    // Guard: _from_compiled_entry only reaches the nmethod verified-entry when
    // the method is JIT-compiled.  Otherwise it points to the c2i adapter, which
    // requires a proper Java frame chain we cannot supply from native code.
    // Refuse early so callers get a clear diagnostic instead of an SEH catch.
    uint64_t code_ptr = read_method_code_ptr(vm, method_ptr);
    if (code_ptr == 0) {
        // _code is null → method is interpreted-only.  The caller must trigger
        // JIT compilation first (e.g. via Java.forceCompile(method)) before
        // invoking through this API.
        duk_push_string(ctx, "not_jit_compiled");
        return 1;
    }

    auto thunk = get_thunk(vm);
    if (!thunk) {
        duk_push_string(ctx, "thunk_alloc_failed");
        return 1;
    }

    bool threw = false;
    uint64_t result = call_thunk_seh(thunk, method_ptr, this_oop, args, &threw);
    if (threw) {
        duk_push_string(ctx, "java_exception");
        return 1;
    }

    char buf[32];
    snprintf(buf, sizeof(buf), "0x%016llX",
             static_cast<unsigned long long>(result));
    duk_push_string(ctx, buf);
    return 1;
}

// ---------------------------------------------------------------------------
// Marrow._invokeInstance(mlo,mhi, tlo,thi, a0lo,a0hi, a1lo,a1hi,
//                                             a2lo,a2hi, a3lo,a3hi) -> hexstr
// Argument count: 12 (all required; pass 0,0 for unused args)
// ---------------------------------------------------------------------------
static duk_ret_t js_invokeInstance(duk_context* ctx) {
    // Stack: [mlo=0, mhi=1, tlo=2, thi=3, a0lo=4, a0hi=5, a1lo=6, a1hi=7,
    //         a2lo=8, a2hi=9, a3lo=10, a3hi=11]
    uint64_t method_ptr = pop_u64_from(ctx, 0);
    uint64_t this_oop   = pop_u64_from(ctx, 2);
    uint64_t args[4] = {
        pop_u64_from(ctx, 4),
        pop_u64_from(ctx, 6),
        pop_u64_from(ctx, 8),
        pop_u64_from(ctx, 10),
    };
    return do_invoke(ctx, method_ptr, this_oop, args);
}

// ---------------------------------------------------------------------------
// Marrow._invokeStatic(mlo,mhi, a0lo,a0hi, a1lo,a1hi,
//                                  a2lo,a2hi, a3lo,a3hi) -> hexstr
// Argument count: 10 (pass 0,0 for unused args)
// ---------------------------------------------------------------------------
static duk_ret_t js_invokeStatic(duk_context* ctx) {
    // Stack: [mlo=0, mhi=1, a0lo=2, a0hi=3, a1lo=4, a1hi=5,
    //         a2lo=6, a2hi=7, a3lo=8, a3hi=9]
    uint64_t method_ptr = pop_u64_from(ctx, 0);
    uint64_t args[4] = {
        pop_u64_from(ctx, 2),
        pop_u64_from(ctx, 4),
        pop_u64_from(ctx, 6),
        pop_u64_from(ctx, 8),
    };
    return do_invoke(ctx, method_ptr, 0, args);
}

// ---------------------------------------------------------------------------
// Registrar — called from agent_js.cpp's install_bindings()
// ---------------------------------------------------------------------------
void register_invoke_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);

    // _invokeInstance(mlo,mhi, tlo,thi, a0lo,a0hi, a1lo,a1hi, a2lo,a2hi, a3lo,a3hi)
    duk_push_c_function(ctx, js_invokeInstance, 12);
    duk_put_prop_string(ctx, ns_idx, "_invokeInstance");

    // _invokeStatic(mlo,mhi, a0lo,a0hi, a1lo,a1hi, a2lo,a2hi, a3lo,a3hi)
    duk_push_c_function(ctx, js_invokeStatic, 10);
    duk_put_prop_string(ctx, ns_idx, "_invokeStatic");
}

} // namespace marrow
