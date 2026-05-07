// agent_inlhook.cpp — inline x64 hook engine (hand-rolled, no MinHook/Detours).
// Exposes:
//   Marrow._inlineHook(targetVaHex)              -> hookId (int) or -1
//   Marrow._inlineHookCount(hookId)              -> count (number)
//   Marrow._inlineUnhook(hookId)                 -> true/false
//   Marrow._inlineHookV2(targetVaHex)            -> hookId (int) or -1
//   Marrow._inlineHookSnap(hookId[, eventIdx])   -> {rcx,rdx,r8,r9,stack0..3,ts} or null
//   Marrow._inlineHookHead(hookId)               -> total snap count (number)

#include "agent_modules.hpp"
#include "hooks.hpp"
#include "duktape.h"
#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <vector>

// Forward decls in global scope for the extern-"C" exports defined further
// down inside namespace marrow::anonymous. Lets the static registrar refer
// to them via ::name without dragging them out of the namespace block.
extern "C" int  marrow_install_user_inline_detour(
    void* target_va, uint64_t ctx_ptr, uint64_t dispatch_ptr, uint32_t via);
extern "C" bool marrow_uninstall_user_inline_detour(int id);

namespace marrow {
namespace {

// ---------------------------------------------------------------------------
// Minimal x64 Length Disassembler
// ---------------------------------------------------------------------------
// Returns byte-length of the instruction at p[0..avail-1], or -1 if unknown.
// Covers common prologue patterns from HotSpot / MSVC / GCC on Win64.

static int modrm_extra(uint8_t modrm) {
    // Returns bytes consumed by [ModRM + optional SIB + optional disp],
    // NOT counting the ModRM byte itself.
    int mod = (modrm >> 6) & 3;
    int rm  = modrm & 7;

    if (mod == 3) return 0;           // register operand, no memory

    int sib_present = (rm == 4) ? 1 : 0;   // SIB byte follows if rm=100b
    int disp = 0;

    if (mod == 0) {
        if (rm == 5) disp = 4;        // disp32 (RIP-relative or absolute)
        // else: no disp (but SIB with base=101 needs disp32 — handle below)
    } else if (mod == 1) {
        disp = 1;                     // disp8
    } else { // mod == 2
        disp = 4;                     // disp32
    }

    // Special: SIB with mod=0 and base=101 means disp32 with no base reg
    if (sib_present && mod == 0) {
        // We'd need to read the SIB byte to know if base==101.
        // For safety, assume disp32 when mod=0+SIB (common in prologues).
        disp = 4;
    }

    return sib_present + disp;
}

// Returns instruction length, or -1 on unknown/unsupported opcode.
static int x64_insn_len(const uint8_t* p, size_t avail) {
    if (avail == 0) return -1;

    size_t off = 0;

    // --- Gather prefixes ---
    bool has_rex   = false;
    bool rex_w     = false;   // 64-bit operand
    bool has_66    = false;   // 16-bit operand override
    // bool has_f2f3 = false; // REP/REPNE — not used below but consumed

    while (off < avail) {
        uint8_t b = p[off];
        if (b >= 0x40 && b <= 0x4F) {      // REX prefix
            has_rex = true;
            rex_w   = (b & 0x08) != 0;
            ++off;
        } else if (b == 0x66) {             // operand-size override
            has_66 = true;
            ++off;
        } else if (b == 0xF0 || b == 0xF2 || b == 0xF3) { // LOCK/REP
            ++off;
        } else {
            break;
        }
    }

    if (off >= avail) return -1;
    uint8_t op = p[off++];

    // --- 1-byte opcodes (no ModRM, no imm) ---
    // push reg (no REX)
    if (op >= 0x50 && op <= 0x57) return static_cast<int>(off);
    // pop  reg (no REX)  — with REX prefix, already consumed above
    if (op >= 0x58 && op <= 0x5F) return static_cast<int>(off);
    if (op == 0x90) return static_cast<int>(off);   // NOP
    if (op == 0xC3) return static_cast<int>(off);   // RET near
    if (op == 0xCB) return static_cast<int>(off);   // RET far (uncommon, but 1 byte)
    if (op == 0x9C) return static_cast<int>(off);   // PUSHFQ
    if (op == 0x9D) return static_cast<int>(off);   // POPFQ

    // PUSH imm8
    if (op == 0x6A) {
        if (off >= avail) return -1;
        return static_cast<int>(off) + 1;
    }
    // PUSH imm32
    if (op == 0x68) {
        if (off + 4 > avail) return -1;
        return static_cast<int>(off) + 4;
    }

    // JMP short (rel8)  — refuse (RIP-relative, can't relocate)
    if (op == 0xEB) return -2;
    // JMP near  (rel32) — refuse
    if (op == 0xE9) return -2;
    // CALL rel32        — refuse
    if (op == 0xE8) return -2;
    // Jcc rel8          — refuse
    if (op >= 0x70 && op <= 0x7F) return -2;
    // Jcc rel32 (0F 8x) handled below

    // --- Two-byte escape 0x0F ---
    if (op == 0x0F) {
        if (off >= avail) return -1;
        uint8_t op2 = p[off++];
        // Jcc rel32 (0F 80..0F 8F) — refuse to relocate
        if (op2 >= 0x80 && op2 <= 0x8F) return -2;
        // NOP with ModRM: 0F 1F /0
        if (op2 == 0x1F) {
            if (off >= avail) return -1;
            uint8_t modrm = p[off++];
            int extra = modrm_extra(modrm);
            if (static_cast<int>(off) + extra > static_cast<int>(avail)) return -1;
            return static_cast<int>(off) + extra;
        }
        // MOVZX: 0F B6 /r (movzx reg, r/m8) and 0F B7 /r (movzx reg, r/m16)
        if (op2 == 0xB6 || op2 == 0xB7) {
            if (off >= avail) return -1;
            uint8_t modrm = p[off++];
            int extra = modrm_extra(modrm);
            if (static_cast<int>(off) + extra > static_cast<int>(avail)) return -1;
            return static_cast<int>(off) + extra;
        }
        // MOVSX: 0F BE /r, 0F BF /r
        if (op2 == 0xBE || op2 == 0xBF) {
            if (off >= avail) return -1;
            uint8_t modrm = p[off++];
            int extra = modrm_extra(modrm);
            if (static_cast<int>(off) + extra > static_cast<int>(avail)) return -1;
            return static_cast<int>(off) + extra;
        }
        return -1;  // unknown 0F xx
    }

    // --- Opcodes with ModRM ---
    // MOV r/m, r  (88/89) or MOV r, r/m (8A/8B)
    // 89 /r : MOV r/m64, r64 (with REX.W)  => 3 bytes for reg-to-reg
    // 8B /r : MOV r64, r/m64
    // 88 /r : MOV r/m8, r8
    // 8A /r : MOV r8, r/m8
    if (op == 0x88 || op == 0x89 || op == 0x8A || op == 0x8B) {
        if (off >= avail) return -1;
        uint8_t modrm = p[off++];
        int extra = modrm_extra(modrm);
        if (static_cast<int>(off) + extra > static_cast<int>(avail)) return -1;
        return static_cast<int>(off) + extra;
    }

    // SUB r/m, imm8  (83 /5 ib)  e.g. sub rsp, 0x28 => 48 83 EC 28
    // ADD r/m, imm8  (83 /0 ib)
    // AND r/m, imm8  (83 /4 ib)
    // CMP r/m, imm8  (83 /7 ib)
    if (op == 0x83) {
        if (off + 1 >= avail) return -1;
        uint8_t modrm = p[off++];
        int extra = modrm_extra(modrm);
        if (static_cast<int>(off) + extra + 1 > static_cast<int>(avail)) return -1;
        return static_cast<int>(off) + extra + 1;  // +1 for imm8
    }

    // SUB r/m, imm32  (81 /5 id)
    // ADD r/m, imm32  (81 /0 id)
    // AND r/m, imm32  (81 /4 id)
    // CMP r/m, imm32  (81 /7 id)
    if (op == 0x81) {
        if (off >= avail) return -1;
        uint8_t modrm = p[off++];
        int extra = modrm_extra(modrm);
        if (static_cast<int>(off) + extra + 4 > static_cast<int>(avail)) return -1;
        return static_cast<int>(off) + extra + 4;
    }

    // LEA r64, m  (8D /r)
    if (op == 0x8D) {
        if (off >= avail) return -1;
        uint8_t modrm = p[off++];
        int extra = modrm_extra(modrm);
        if (static_cast<int>(off) + extra > static_cast<int>(avail)) return -1;
        return static_cast<int>(off) + extra;
    }

    // TEST r/m, r  (85 /r)
    // CMP  r/m, r  (39 /r)
    // OR   r/m, r  (09 /r)
    // XOR  r/m, r  (31 /r)
    // AND  r/m, r  (21 /r)
    if (op == 0x85 || op == 0x84 ||
        op == 0x39 || op == 0x3B ||
        op == 0x09 || op == 0x0B ||
        op == 0x31 || op == 0x33 ||
        op == 0x21 || op == 0x23) {
        if (off >= avail) return -1;
        uint8_t modrm = p[off++];
        int extra = modrm_extra(modrm);
        if (static_cast<int>(off) + extra > static_cast<int>(avail)) return -1;
        return static_cast<int>(off) + extra;
    }

    // MOV r, imm (B8+rd id for 32-bit, or REX.W B8+rd iq for 64-bit)
    // B8..BF: MOV r32, imm32  (without REX.W)
    // with REX.W: MOV r64, imm64
    if (op >= 0xB8 && op <= 0xBF) {
        int imm_size = (rex_w || has_rex) ? 8 : 4;
        if (static_cast<int>(off) + imm_size > static_cast<int>(avail)) return -1;
        return static_cast<int>(off) + imm_size;
    }
    // B0..B7: MOV r8, imm8
    if (op >= 0xB0 && op <= 0xB7) {
        if (off >= avail) return -1;
        return static_cast<int>(off) + 1;
    }

    // MOV r/m, imm  (C7 /0 id)
    if (op == 0xC7) {
        if (off >= avail) return -1;
        uint8_t modrm = p[off++];
        int extra = modrm_extra(modrm);
        // imm size: 32-bit (sign-extended to 64 with REX.W)
        if (static_cast<int>(off) + extra + 4 > static_cast<int>(avail)) return -1;
        return static_cast<int>(off) + extra + 4;
    }

    // JMP indirect  (FF /4) — absolute indirect JMP [rip+0] pattern
    if (op == 0xFF) {
        if (off >= avail) return -1;
        uint8_t modrm = p[off++];
        int extra = modrm_extra(modrm);
        if (static_cast<int>(off) + extra > static_cast<int>(avail)) return -1;
        return static_cast<int>(off) + extra;
    }

    // XCHG  (87 /r)
    if (op == 0x87) {
        if (off >= avail) return -1;
        uint8_t modrm = p[off++];
        int extra = modrm_extra(modrm);
        if (static_cast<int>(off) + extra > static_cast<int>(avail)) return -1;
        return static_cast<int>(off) + extra;
    }

    // CMP al, imm8  (3C ib)
    if (op == 0x3C) {
        if (off >= avail) return -1;
        return static_cast<int>(off) + 1;
    }
    // CMP rAX, imm32 (3D id)
    if (op == 0x3D) {
        if (static_cast<int>(off) + 4 > static_cast<int>(avail)) return -1;
        return static_cast<int>(off) + 4;
    }

    (void)has_66;
    return -1;  // unrecognised
}

// ---------------------------------------------------------------------------
// V2 per-hook context — ring buffer of argument snapshots (onEnter) and
// return-value snapshots (onLeave).
// ---------------------------------------------------------------------------
struct InlineHookCtx {
    std::atomic<uint64_t> fire_count{0};
    static constexpr size_t RING = 64;
    struct Snap {
        uint64_t args[4];   // rcx, rdx, r8, r9
        uint64_t stack[4];  // [entry_rsp+0x28+i*8] for i=0..3
        uint64_t ts_ms;
    };
    Snap     ring[RING];
    std::atomic<uint64_t> head{0};

    // Leave-side ring. Only RAX is captured (XMM0 for floats deferred —
    // hook target signatures are usually integer/pointer-returning).
    struct LeaveSnap {
        uint64_t rax;
        uint64_t ts_ms;
    };
    LeaveSnap leave_ring[RING];
    std::atomic<uint64_t> leave_head{0};

    std::mutex mu;
};

// ---------------------------------------------------------------------------
// TLS retaddr stack — shared across all V2 hooks.
//
// The enter dispatcher swaps the function's return address with our global
// leave_shim. Before the swap we push (ctx, real_retaddr) onto a per-thread
// stack; the leave_shim pops it and tail-jumps to the saved retaddr.
// LIFO ordering naturally handles recursion and nested hooked calls.
//
// Bounded at 64 frames per thread — deeper hooked recursion silently skips
// the swap (function still runs, no leave snap recorded). Tradeoff for
// avoiding heap allocation on the hot path.
// ---------------------------------------------------------------------------
struct TlsRetStack {
    static constexpr size_t MAX = 64;
    uint64_t       retaddrs[MAX];
    InlineHookCtx* ctxs[MAX];
    int            top = 0;
};

static DWORD g_tls_idx = TLS_OUT_OF_INDEXES;
static std::once_flag g_tls_once;

static void tls_init() {
    std::call_once(g_tls_once, []{
        g_tls_idx = TlsAlloc();
    });
}

static TlsRetStack* tls_stack_or_null() {
    if (g_tls_idx == TLS_OUT_OF_INDEXES) return nullptr;
    return static_cast<TlsRetStack*>(TlsGetValue(g_tls_idx));
}

static TlsRetStack* tls_stack_get_or_create() {
    if (g_tls_idx == TLS_OUT_OF_INDEXES) return nullptr;
    auto* s = static_cast<TlsRetStack*>(TlsGetValue(g_tls_idx));
    if (!s) {
        s = new TlsRetStack();
        TlsSetValue(g_tls_idx, s);
    }
    return s;
}

// SEH helper: safely read 4 stack qwords into dst[]. MSVC forbids __try in
// functions with C++ object unwinding (std::lock_guard etc.), so this lives
// in its own plain function with no destructors. Force `noinline` so MSVC
// can't merge it into the dispatcher's scope (which DOES have lock_guard).
__declspec(noinline) static void read_stack_args_seh(uint64_t* src, uint64_t* dst) {
    __try {
        for (int i = 0; i < 4; ++i)
            dst[i] = src[i];
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        for (int i = 0; i < 4; ++i)
            dst[i] = 0;
    }
}

// Forward decl — defined further below. Pre-declared so leave_shim's
// emit_leave_shim can encode its address.
extern "C" uint64_t marrow_inline_hook_leave_dispatch(uint64_t rax_value);

// Set during install of the leave_shim (one global page). Used by enter
// dispatch to know what retaddr to write into entry_rsp[0].
static std::atomic<uint64_t> g_leave_shim_va{0};

// Dispatcher called from the V2 shim (Win x64 calling convention).
//   rcx  = ctx
//   rdx  = ptr to saved regs on shim stack (lea rdx,[rsp+0x20] after sub rsp,0x20):
//          [0]=r9 [1]=r8 [2]=rdx [3]=rcx [4]=rax
//   r8   = rbx value saved by shim = entry_RSP - 16
//          r8[0]=orig_rbx, r8[1]=rflags, r8[2..]=entry RSP onwards
extern "C" void marrow_inline_hook_dispatch(
    InlineHookCtx* ctx,
    uint64_t*      saved_regs,
    uint64_t*      saved_rbx_ptr)
{
    if (!ctx) return;

    // Recover Win x64 register args from the shim's push sequence.
    uint64_t a_rcx = saved_regs[3];
    uint64_t a_rdx = saved_regs[2];
    uint64_t a_r8  = saved_regs[1];
    uint64_t a_r9  = saved_regs[0];

    // saved_rbx_ptr == rbx == entry_RSP - 16.
    // entry_RSP == saved_rbx_ptr + 2  (as uint64_t*, i.e. +16 bytes).
    // Stack layout at function entry (Win x64):
    //   [entry_RSP + 0x00] = retaddr
    //   [entry_RSP + 0x08..0x20] = 32-byte shadow space (4 home slots)
    //   [entry_RSP + 0x28] = arg4, [+0x30] = arg5, ...
    uint64_t* entry_rsp = saved_rbx_ptr + 2;  // points to retaddr
    // entry_rsp[5] == arg4 (= [rsp+0x28] from the callee's perspective)
    uint64_t stack_snap[4];
    read_stack_args_seh(entry_rsp + 5, stack_snap);

    {
        std::lock_guard<std::mutex> g(ctx->mu);
        uint64_t h = ctx->head.load(std::memory_order_relaxed);
        auto& slot = ctx->ring[h % InlineHookCtx::RING];
        slot.args[0] = a_rcx;
        slot.args[1] = a_rdx;
        slot.args[2] = a_r8;
        slot.args[3] = a_r9;
        for (int i = 0; i < 4; ++i)
            slot.stack[i] = stack_snap[i];
        slot.ts_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());

        ctx->head.store(h + 1, std::memory_order_relaxed);
        ctx->fire_count.fetch_add(1, std::memory_order_relaxed);
    }

    // Retaddr swap for onLeave capture. If the leave_shim isn't installed
    // (older path) or the per-thread TLS stack is full, skip the swap —
    // the function still returns to its real caller, just without a leave
    // snap. This keeps onEnter correctness independent of leave plumbing.
    uint64_t leave_va = g_leave_shim_va.load(std::memory_order_acquire);
    if (!leave_va) return;
    auto* ts = tls_stack_get_or_create();
    if (!ts || ts->top >= TlsRetStack::MAX) return;

    ts->retaddrs[ts->top] = entry_rsp[0];
    ts->ctxs[ts->top]     = ctx;
    ts->top++;
    entry_rsp[0] = leave_va;
}

// Leave-side dispatcher. Called by the global leave_shim with the original
// function's RAX in rcx (per Win x64 call convention). Returns the real
// retaddr in rax, which the shim then jumps to with rax restored.
extern "C" uint64_t marrow_inline_hook_leave_dispatch(uint64_t rax_value)
{
    auto* ts = tls_stack_or_null();
    if (!ts || ts->top == 0) {
        // Lost frame — should not happen if the enter side ran. Return 0
        // and let the JVM crash visibly; better than tail-jumping to a
        // wrong VA.
        return 0;
    }
    ts->top--;
    InlineHookCtx* ctx     = ts->ctxs[ts->top];
    uint64_t       retaddr = ts->retaddrs[ts->top];

    if (ctx) {
        std::lock_guard<std::mutex> g(ctx->mu);
        uint64_t h = ctx->leave_head.load(std::memory_order_relaxed);
        auto& slot = ctx->leave_ring[h % InlineHookCtx::RING];
        slot.rax   = rax_value;
        slot.ts_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        ctx->leave_head.store(h + 1, std::memory_order_relaxed);
    }
    return retaddr;
}

// ---------------------------------------------------------------------------
// Hook record
// ---------------------------------------------------------------------------
struct InlineHook {
    void*    target;          // original target VA
    uint8_t  saved_bytes[64]; // original prologue bytes (up to plen)
    size_t   plen;            // number of bytes we overwrote
    void*    shim_page;       // executable page: shim asm
    void*    tramp_page;      // executable page: relocated prologue + jmp-back
    std::atomic<uint64_t> counter{0};
    bool     active = false;
    bool     is_v2  = false;
    InlineHookCtx* v2ctx = nullptr;  // non-null for V2 hooks
};

static std::mutex            g_mu;
static std::vector<InlineHook*> g_hooks;

// ---------------------------------------------------------------------------
// Exec-page helpers
// ---------------------------------------------------------------------------
static void* alloc_exec(size_t sz) {
    return VirtualAlloc(nullptr, sz,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);
}
static void free_exec(void* p) {
    if (p) VirtualFree(p, 0, MEM_RELEASE);
}

// Write a 14-byte absolute JMP to dst at location src (src must be RWX or
// caller must have already VirtualProtect'd it).
static void write_abs_jmp14(uint8_t* src, uint64_t dst) {
    // FF 25 00 00 00 00  jmp [rip+0]
    // <8 bytes of dst>
    src[0] = 0xFF; src[1] = 0x25;
    src[2] = 0x00; src[3] = 0x00; src[4] = 0x00; src[5] = 0x00;
    std::memcpy(src + 6, &dst, 8);
}

// ---------------------------------------------------------------------------
// install_inline_hook — core engine
// ---------------------------------------------------------------------------
// Returns hook ID (index into g_hooks) or -1 on failure.
static int install_inline_hook(void* target_va) {
    auto* target = static_cast<uint8_t*>(target_va);

    // --- Compute prologue length (>= 14 bytes of whole instructions) ---
    constexpr size_t SCAN = 64;
    size_t plen = 0;
    while (plen < 14) {
        int n = x64_insn_len(target + plen, SCAN - plen);
        if (n == -2) {
            // Relative branch in prologue — cannot safely relocate.
            return -1;
        }
        if (n <= 0) return -1;
        plen += static_cast<size_t>(n);
        if (plen > SCAN - 14) return -1;   // pathological
    }

    // --- Allocate trampoline page ---
    // Layout: [relocated prologue (plen)] [jmp [rip+0]] [imm64 = target+plen]
    size_t tramp_sz = plen + 6 + 8;
    void* tramp_page = alloc_exec(tramp_sz);
    if (!tramp_page) return -1;

    // Copy original prologue bytes into trampoline.
    std::memcpy(tramp_page, target, plen);
    // Append absolute jmp back to target+plen.
    write_abs_jmp14(static_cast<uint8_t*>(tramp_page) + plen,
                    reinterpret_cast<uint64_t>(target) + plen);

    // --- Allocate shim page ---
    // Shim layout (~88 bytes):
    //   9C                         pushfq
    //   50 51 52 41 50 41 51       push rax,rcx,rdx,r8,r9
    //   48 83 EC 28                sub rsp, 0x28   (shadow + align)
    //   48 B8 <counter_addr>       mov rax, &counter
    //   F0 48 FF 00                lock inc qword [rax]
    //   48 83 C4 28                add rsp, 0x28
    //   41 59 41 58 5A 59 58       pop r9,r8,rdx,rcx,rax
    //   9D                         popfq
    //   FF 25 00 00 00 00          jmp [rip+0]
    //   <tramp_addr_imm64>
    void* shim_page = alloc_exec(192);
    if (!shim_page) { free_exec(tramp_page); return -1; }

    // Allocate hook record NOW so we have a stable counter address.
    InlineHook* h = new InlineHook();
    h->target     = target;
    h->plen       = plen;
    h->shim_page  = shim_page;
    h->tramp_page = tramp_page;
    h->active     = true;
    std::memcpy(h->saved_bytes, target, plen);

    // Build shim machine code.
    uint8_t* s = static_cast<uint8_t*>(shim_page);
    size_t   si = 0;

    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        for (uint8_t b : bytes) s[si++] = b;
    };
    auto emit64 = [&](uint64_t v) {
        std::memcpy(s + si, &v, 8); si += 8;
    };

    emit({0x9C});                                   // pushfq
    emit({0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51}); // push rax,rcx,rdx,r8,r9
    emit({0x48, 0x83, 0xEC, 0x28});                 // sub rsp, 0x28
    emit({0x48, 0xB8});                             // mov rax, imm64
    emit64(reinterpret_cast<uint64_t>(&h->counter));
    emit({0xF0, 0x48, 0xFF, 0x00});                 // lock inc qword [rax]
    emit({0x48, 0x83, 0xC4, 0x28});                 // add rsp, 0x28
    emit({0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58}); // pop r9,r8,rdx,rcx,rax
    emit({0x9D});                                   // popfq
    emit({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});     // jmp [rip+0]
    emit64(reinterpret_cast<uint64_t>(tramp_page)); // -> trampoline

    // --- Patch target: overwrite first plen bytes with 14-byte JMP to shim ---
    DWORD old_prot = 0;
    if (!VirtualProtect(target, plen, PAGE_EXECUTE_READWRITE, &old_prot)) {
        free_exec(shim_page);
        free_exec(tramp_page);
        delete h;
        return -1;
    }
    write_abs_jmp14(target, reinterpret_cast<uint64_t>(shim_page));
    // Fill remainder of plen with NOPs so disassemblers stay tidy.
    for (size_t i = 14; i < plen; ++i) target[i] = 0x90;

    // Flush instruction cache (required on x64 too — Win32 does a cross-core
    // IPI when called, which is correct for code patching).
    FlushInstructionCache(GetCurrentProcess(), target, plen);

    VirtualProtect(target, plen, old_prot, &old_prot);

    // Register the hook.
    std::lock_guard<std::mutex> lk(g_mu);
    int id = static_cast<int>(g_hooks.size());
    g_hooks.push_back(h);
    return id;
}

// ---------------------------------------------------------------------------
// install_inline_hook_v2 — capturing shim engine
// ---------------------------------------------------------------------------
// Mirrors the proven emit_full_trampoline design from hooks.cpp.
// Saves rbx + rflags, aligns stack, saves 5 Win x64 arg regs, calls
// marrow_inline_hook_dispatch(ctx, saved_regs_ptr, saved_rbx_ptr),
// then restores everything and tail-jumps to the trampoline.
// See emit_v2_shim byte-layout comment below.

// Byte layout of emit_v2_shim output (80 bytes total):
//   00: 9C                        pushfq
//   01: 53                        push rbx
//   02: 48 89 E3                  mov rbx, rsp
//   05: 48 83 E4 F0               and rsp, -16
//   09: 50 51 52 41 50 41 51      push rax,rcx,rdx,r8,r9
//   16: 48 83 EC 20               sub rsp, 0x20
//   20: 48 B9 <ctx_ptr:8>         mov rcx, ctx_ptr
//   30: 48 8D 54 24 20            lea rdx, [rsp+0x20]    ; rdx->[r9,r8,rdx,rcx,rax]
//   35: 49 89 D8                  mov r8, rbx            ; r8 = saved_rbx_ptr
//   38: 48 B8 <dispatch_ptr:8>    mov rax, dispatch_ptr
//   48: FF D0                     call rax
//   50: 48 83 C4 20               add rsp, 0x20
//   54: 41 59 41 58 5A 59 58      pop r9,r8,rdx,rcx,rax
//   61: 48 89 DC                  mov rsp, rbx
//   64: 5B                        pop rbx
//   65: 9D                        popfq
//   66: FF 25 00 00 00 00         jmp [rip+0]
//   72: <tramp_ptr:8>
//   80: (end)

static void emit_v2_shim(uint8_t* s, uint64_t ctx_ptr,
                          uint64_t dispatch_ptr, uint64_t tramp_ptr) {
    size_t i = 0;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        for (uint8_t b : bytes) s[i++] = b;
    };
    auto emit64 = [&](uint64_t v) {
        std::memcpy(s + i, &v, 8); i += 8;
    };

    emit({0x9C});                                      // 00: pushfq
    emit({0x53});                                      // 01: push rbx
    emit({0x48, 0x89, 0xE3});                          // 02: mov rbx, rsp
    emit({0x48, 0x83, 0xE4, 0xF0});                    // 05: and rsp, -16
    emit({0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51}); // 09: push rax,rcx,rdx,r8,r9
    emit({0x48, 0x83, 0xEC, 0x20});                    // 16: sub rsp, 0x20
    emit({0x48, 0xB9});                                // 20: mov rcx, imm64 (arg1 = ctx)
    emit64(ctx_ptr);                                   // 22..29
    emit({0x48, 0x8D, 0x54, 0x24, 0x20});              // 30: lea rdx,[rsp+0x20] (arg2 = saved regs)
    emit({0x49, 0x89, 0xD8});                          // 35: mov r8, rbx (arg3 = saved_rbx_ptr)
    emit({0x48, 0xB8});                                // 38: mov rax, imm64 (dispatch)
    emit64(dispatch_ptr);                              // 40..47
    emit({0xFF, 0xD0});                                // 48: call rax
    emit({0x48, 0x83, 0xC4, 0x20});                    // 50: add rsp, 0x20
    emit({0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58}); // 54: pop r9,r8,rdx,rcx,rax
    emit({0x48, 0x89, 0xDC});                          // 61: mov rsp, rbx
    emit({0x5B});                                      // 64: pop rbx
    emit({0x9D});                                      // 65: popfq
    emit({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});        // 66: jmp [rip+0]
    emit64(tramp_ptr);                                 // 72..79
    // Total: 80 bytes — fits in the 128-byte shim alloc.
}

// ---------------------------------------------------------------------------
// Global leave_shim — single page shared across all V2 hooks.
// Layout (47 bytes):
//   00: 50                             push rax              ; save retval
//   01: 48 83 EC 28                    sub rsp, 0x28
//   05: 48 8B 4C 24 30                 mov rcx, [rsp+0x30]   ; arg1 = retval
//   10: 48 B8 <leave_dispatch:8>       mov rax, leave_dispatch
//   20: FF D0                          call rax              ; rax = real retaddr
//   22: 49 89 C3                       mov r11, rax          ; preserve via volatile r11
//   25: 48 83 C4 28                    add rsp, 0x28
//   29: 58                             pop rax               ; restore retval
//   30: 41 FF E3                       jmp r11
//   33: end
//
// Stack alignment: at entry rsp is 16-aligned (the hooked fn's `ret` just
// fired). After `push rax`, rsp -= 8 → 8-aligned. `sub rsp, 0x28` (40
// bytes) brings alignment to (8 + 40) % 16 = 0 → 16-aligned for `call rax`.
static void emit_leave_shim(uint8_t* s, uint64_t leave_dispatch_ptr) {
    size_t i = 0;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        for (uint8_t b : bytes) s[i++] = b;
    };
    auto emit64 = [&](uint64_t v) {
        std::memcpy(s + i, &v, 8); i += 8;
    };

    emit({0x50});                                       // 00: push rax
    emit({0x48, 0x83, 0xEC, 0x28});                     // 01: sub rsp, 0x28
    emit({0x48, 0x8B, 0x4C, 0x24, 0x30});               // 05: mov rcx,[rsp+0x30]
    emit({0x48, 0xB8});                                 // 10: mov rax, imm64
    emit64(leave_dispatch_ptr);                         // 12..19
    emit({0xFF, 0xD0});                                 // 20: call rax
    emit({0x49, 0x89, 0xC3});                           // 22: mov r11, rax
    emit({0x48, 0x83, 0xC4, 0x28});                     // 25: add rsp, 0x28
    emit({0x58});                                       // 29: pop rax
    emit({0x41, 0xFF, 0xE3});                           // 30: jmp r11
    // 33 bytes total.
}

static void ensure_leave_shim_installed() {
    if (g_leave_shim_va.load(std::memory_order_acquire) != 0) return;
    static std::mutex install_mu;
    std::lock_guard<std::mutex> lk(install_mu);
    if (g_leave_shim_va.load(std::memory_order_acquire) != 0) return;

    void* page = alloc_exec(64);
    if (!page) return;
    emit_leave_shim(static_cast<uint8_t*>(page),
        reinterpret_cast<uint64_t>(&marrow_inline_hook_leave_dispatch));
    FlushInstructionCache(GetCurrentProcess(), page, 64);
    g_leave_shim_va.store(reinterpret_cast<uint64_t>(page),
                          std::memory_order_release);
}

static int install_inline_hook_v2(void* target_va) {
    auto* target = static_cast<uint8_t*>(target_va);

    // Initialise TLS index + global leave_shim on first V2 install.
    tls_init();
    ensure_leave_shim_installed();

    // Compute prologue length (>= 14 bytes).
    constexpr size_t SCAN = 64;
    size_t plen = 0;
    while (plen < 14) {
        int n = x64_insn_len(target + plen, SCAN - plen);
        if (n == -2 || n <= 0) return -1;
        plen += static_cast<size_t>(n);
        if (plen > SCAN - 14) return -1;
    }

    // Trampoline: relocated prologue + absolute jmp back.
    size_t tramp_sz = plen + 6 + 8;
    void* tramp_page = alloc_exec(tramp_sz);
    if (!tramp_page) return -1;
    std::memcpy(tramp_page, target, plen);
    write_abs_jmp14(static_cast<uint8_t*>(tramp_page) + plen,
                    reinterpret_cast<uint64_t>(target) + plen);

    // Shim page.
    void* shim_page = alloc_exec(192);
    if (!shim_page) { free_exec(tramp_page); return -1; }

    // Hook record + V2 context.
    InlineHook* h      = new InlineHook();
    InlineHookCtx* ctx = new InlineHookCtx();
    h->target     = target;
    h->plen       = plen;
    h->shim_page  = shim_page;
    h->tramp_page = tramp_page;
    h->active     = true;
    h->is_v2      = true;
    h->v2ctx      = ctx;
    std::memcpy(h->saved_bytes, target, plen);

    // Emit the capturing shim.
    emit_v2_shim(
        static_cast<uint8_t*>(shim_page),
        reinterpret_cast<uint64_t>(ctx),
        reinterpret_cast<uint64_t>(&marrow_inline_hook_dispatch),
        reinterpret_cast<uint64_t>(tramp_page));

    // Patch target with 14-byte jump to shim.
    DWORD old_prot = 0;
    if (!VirtualProtect(target, plen, PAGE_EXECUTE_READWRITE, &old_prot)) {
        free_exec(shim_page);
        free_exec(tramp_page);
        delete ctx;
        delete h;
        return -1;
    }
    write_abs_jmp14(target, reinterpret_cast<uint64_t>(shim_page));
    for (size_t i = 14; i < plen; ++i) target[i] = 0x90;
    FlushInstructionCache(GetCurrentProcess(), target, plen);
    VirtualProtect(target, plen, old_prot, &old_prot);

    std::lock_guard<std::mutex> lk(g_mu);
    int id = static_cast<int>(g_hooks.size());
    g_hooks.push_back(h);
    return id;
}

// ---------------------------------------------------------------------------
// emit_v2_shim_with_via — full 14-GPR snapshot shim, mirroring the layout
// expected by marrow_hook_dispatch (saved_regs[0..13] from r15..rax).
// Passes a 4th arg in r9d (via=0 for interpreter, 1 for compiled), so the
// dispatcher knows the calling convention of the trapped frame.
// ---------------------------------------------------------------------------
static void emit_v2_shim_with_via(uint8_t* s, uint64_t ctx_ptr,
                                   uint64_t dispatch_ptr,
                                   uint64_t tramp_ptr,
                                   uint32_t via)
{
    size_t i = 0;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        for (uint8_t b : bytes) s[i++] = b;
    };
    auto emit64 = [&](uint64_t v) {
        std::memcpy(s + i, &v, 8); i += 8;
    };
    auto emit32 = [&](uint32_t v) {
        std::memcpy(s + i, &v, 4); i += 4;
    };

    emit({0x9C});                                      // pushfq
    emit({0x53});                                      // push rbx
    emit({0x48, 0x89, 0xE3});                          // mov rbx, rsp
    emit({0x48, 0x83, 0xE4, 0xF0});                    // and rsp, -16
    // push rax,rcx,rdx,rbp,rsi,rdi  (6 single-byte opcodes)
    emit({0x50, 0x51, 0x52, 0x55, 0x56, 0x57});
    // push r8..r15  (8 two-byte opcodes)
    emit({0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
          0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57});
    // After all pushes, layout from low to high addr:
    //   r15, r14, r13, r12, r11, r10, r9, r8,
    //   rdi, rsi, rbp, rdx, rcx, rax  (= saved_regs[0..13])
    emit({0x48, 0xB9}); emit64(ctx_ptr);               // mov rcx, ctx_imm    (arg1)
    emit({0x48, 0x89, 0xE2});                          // mov rdx, rsp        (arg2 = saved_regs)
    emit({0x49, 0x89, 0xD8});                          // mov r8,  rbx        (arg3 = saved_rbx_ptr)
    emit({0x41, 0xB9}); emit32(via);                   // mov r9d, via_imm32  (arg4)
    emit({0x48, 0x83, 0xEC, 0x20});                    // sub rsp, 0x20  (shadow space)
    emit({0x48, 0xB8}); emit64(dispatch_ptr);          // mov rax, dispatch_imm
    emit({0xFF, 0xD0});                                // call rax
    emit({0x48, 0x83, 0xC4, 0x20});                    // add rsp, 0x20
    // v0.7: park dispatch's encoded skip+rax return into the saved-rax
    // slot at [rsp + 0x68] BEFORE the pop sequence. pop rax later
    // reloads our value. Mirrors the FULL_TRAMP fix from v0.6 — the
    // JIT-detour path now also supports `.implementation = fn`
    // skip-orig semantics on already-JIT'd nmethods, not just
    // observation.
    emit({0x48, 0x89, 0x44, 0x24, 0x68});              // mov [rsp+0x68], rax
    // pop r15..r8  (reverse of push order)
    emit({0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,
          0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58});
    // pop rdi,rsi,rbp,rdx,rcx,rax
    emit({0x5F, 0x5E, 0x5D, 0x5A, 0x59, 0x58});
    emit({0x48, 0x89, 0xDC});                          // mov rsp, rbx
    emit({0x5B});                                      // pop rbx
    // rax now holds dispatch's encoded skip+replace value. Bit 63
    // set => skip orig and return masked rax to caller. Bit 63
    // clear => fall through to original execution (jmp tramp_ptr).
    emit({0x48, 0x85, 0xC0});                          // test rax, rax
    emit({0x79, 0x07});                                // jns +7 → .orig
    emit({0x48, 0xD1, 0xE0});                          // shl rax, 1
    emit({0x48, 0xD1, 0xE8});                          // shr rax, 1
    emit({0x9D});                                      // popfq
    emit({0xC3});                                      // ret
    // .orig: continue executing original at tramp_page (which has the
    // first 14 bytes of the original method copied + an abs-jmp back
    // to method+14).
    emit({0x9D});                                      // popfq
    emit({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});        // jmp [rip+0]
    emit64(tramp_ptr);
    // Total: ~135 bytes. Fits in 128-byte alloc... wait, 128 was tight.
    // Bumped alloc to 192 in install_user_inline_detour.
}

// ---------------------------------------------------------------------------
// Public: install_user_inline_detour
// Mirrors install_inline_hook_v2 but with a caller-supplied dispatch+ctx
// and a `via` flag passed as 4th arg. Used by Method-hook engine to detour
// JIT'd nmethod entries while reusing the inline-hook LDE+reloc plumbing.
// Returns hook id (usable with uninstall_inline_hook below) or -1.
// ---------------------------------------------------------------------------
extern "C" int marrow_install_user_inline_detour(void*    target_va,
                                                    uint64_t ctx_ptr,
                                                    uint64_t dispatch_ptr,
                                                    uint32_t via)
{
    auto* target = static_cast<uint8_t*>(target_va);

    constexpr size_t SCAN = 64;
    size_t plen = 0;
    while (plen < 14) {
        int n = x64_insn_len(target + plen, SCAN - plen);
        if (n == -2 || n <= 0) return -1;
        plen += static_cast<size_t>(n);
        if (plen > SCAN - 14) return -1;
    }

    size_t tramp_sz = plen + 6 + 8;
    void* tramp_page = alloc_exec(tramp_sz);
    if (!tramp_page) return -1;
    std::memcpy(tramp_page, target, plen);
    write_abs_jmp14(static_cast<uint8_t*>(tramp_page) + plen,
                    reinterpret_cast<uint64_t>(target) + plen);

    void* shim_page = alloc_exec(192);
    if (!shim_page) { free_exec(tramp_page); return -1; }

    InlineHook* h = new InlineHook();
    h->target     = target;
    h->plen       = plen;
    h->shim_page  = shim_page;
    h->tramp_page = tramp_page;
    h->active     = true;
    h->is_v2      = false;          // bypass V2 ring/leave-shim machinery
    h->v2ctx      = nullptr;
    std::memcpy(h->saved_bytes, target, plen);

    emit_v2_shim_with_via(static_cast<uint8_t*>(shim_page),
                          ctx_ptr, dispatch_ptr,
                          reinterpret_cast<uint64_t>(tramp_page),
                          via);

    DWORD old_prot = 0;
    if (!VirtualProtect(target, plen, PAGE_EXECUTE_READWRITE, &old_prot)) {
        free_exec(shim_page);
        free_exec(tramp_page);
        delete h;
        return -1;
    }
    write_abs_jmp14(target, reinterpret_cast<uint64_t>(shim_page));
    for (size_t i = 14; i < plen; ++i) target[i] = 0x90;
    FlushInstructionCache(GetCurrentProcess(), target, plen);
    VirtualProtect(target, plen, old_prot, &old_prot);

    std::lock_guard<std::mutex> lk(g_mu);
    int id = static_cast<int>(g_hooks.size());
    g_hooks.push_back(h);
    return id;
}

// Public: restore original prologue bytes for a user-detour hook.
// Returns true on success.
extern "C" bool marrow_uninstall_user_inline_detour(int id) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (id < 0 || id >= (int)g_hooks.size()) return false;
    InlineHook* h = g_hooks[id];
    if (!h || !h->active) return false;

    DWORD old_prot = 0;
    if (!VirtualProtect(h->target, h->plen, PAGE_EXECUTE_READWRITE, &old_prot))
        return false;
    std::memcpy(h->target, h->saved_bytes, h->plen);
    FlushInstructionCache(GetCurrentProcess(), h->target, h->plen);
    VirtualProtect(h->target, h->plen, old_prot, &old_prot);

    h->active = false;
    return true;
}

// ---------------------------------------------------------------------------
// Duktape bindings
// ---------------------------------------------------------------------------

// Marrow._inlineHook("0x7ff...") -> hookId or -1
static duk_ret_t js_inline_hook(duk_context* ctx) {
    const char* va_str = duk_require_string(ctx, 0);
    unsigned long long va = 0;
    if (std::sscanf(va_str, "%llx", &va) != 1 &&
        std::sscanf(va_str, "0x%llx", &va) != 1) {
        duk_push_int(ctx, -1);
        return 1;
    }
    void* target = reinterpret_cast<void*>(static_cast<uintptr_t>(va));
    int id = install_inline_hook(target);
    duk_push_int(ctx, id);
    return 1;
}

// Marrow._inlineHookCount(hookId) -> number
static duk_ret_t js_inline_hook_count(duk_context* ctx) {
    int id = duk_require_int(ctx, 0);
    std::lock_guard<std::mutex> lk(g_mu);
    if (id < 0 || static_cast<size_t>(id) >= g_hooks.size() || !g_hooks[id]) {
        duk_push_number(ctx, 0.0);
        return 1;
    }
    uint64_t c = g_hooks[id]->counter.load(std::memory_order_relaxed);
    // Duktape's number is double; safe up to 2^53.
    duk_push_number(ctx, static_cast<double>(c));
    return 1;
}

// Marrow._inlineUnhook(hookId) -> boolean
static duk_ret_t js_inline_unhook(duk_context* ctx) {
    int id = duk_require_int(ctx, 0);
    std::lock_guard<std::mutex> lk(g_mu);
    if (id < 0 || static_cast<size_t>(id) >= g_hooks.size() || !g_hooks[id]) {
        duk_push_false(ctx);
        return 1;
    }
    InlineHook* h = g_hooks[id];
    if (!h->active) { duk_push_false(ctx); return 1; }

    // Restore original bytes.
    DWORD old_prot = 0;
    if (VirtualProtect(h->target, h->plen, PAGE_EXECUTE_READWRITE, &old_prot)) {
        std::memcpy(h->target, h->saved_bytes, h->plen);
        FlushInstructionCache(GetCurrentProcess(), h->target, h->plen);
        VirtualProtect(h->target, h->plen, old_prot, &old_prot);
    }

    free_exec(h->shim_page);
    free_exec(h->tramp_page);
    h->active    = false;
    h->shim_page  = nullptr;
    h->tramp_page = nullptr;
    if (h->v2ctx) {
        delete h->v2ctx;
        h->v2ctx = nullptr;
    }

    duk_push_true(ctx);
    return 1;
}

// Marrow._inlineHookV2("0x7ff...") -> hookId or -1
static duk_ret_t js_inline_hook_v2(duk_context* ctx) {
    const char* va_str = duk_require_string(ctx, 0);
    unsigned long long va = 0;
    if (std::sscanf(va_str, "%llx", &va) != 1 &&
        std::sscanf(va_str, "0x%llx", &va) != 1) {
        duk_push_int(ctx, -1);
        return 1;
    }
    void* target = reinterpret_cast<void*>(static_cast<uintptr_t>(va));
    int id = install_inline_hook_v2(target);
    duk_push_int(ctx, id);
    return 1;
}

// Marrow._inlineHookHead(hookId) -> total snapshot count (number)
static duk_ret_t js_inline_hook_head(duk_context* ctx) {
    int id = duk_require_int(ctx, 0);
    std::lock_guard<std::mutex> lk(g_mu);
    if (id < 0 || static_cast<size_t>(id) >= g_hooks.size() ||
        !g_hooks[id] || !g_hooks[id]->v2ctx) {
        duk_push_number(ctx, 0.0);
        return 1;
    }
    uint64_t h = g_hooks[id]->v2ctx->head.load(std::memory_order_relaxed);
    duk_push_number(ctx, static_cast<double>(h));
    return 1;
}

// Marrow._inlineHookSnap(hookId[, eventIdx]) -> object or null
// eventIdx defaults to head-1 (latest). Wraps modulo RING.
static duk_ret_t js_inline_hook_snap(duk_context* ctx) {
    int id = duk_require_int(ctx, 0);

    std::lock_guard<std::mutex> lk(g_mu);
    if (id < 0 || static_cast<size_t>(id) >= g_hooks.size() ||
        !g_hooks[id] || !g_hooks[id]->v2ctx) {
        duk_push_null(ctx);
        return 1;
    }
    InlineHookCtx* hctx = g_hooks[id]->v2ctx;
    uint64_t head = hctx->head.load(std::memory_order_relaxed);
    if (head == 0) {
        duk_push_null(ctx);
        return 1;
    }

    uint64_t event_idx;
    if (duk_get_top(ctx) >= 2 && !duk_is_undefined(ctx, 1)) {
        event_idx = static_cast<uint64_t>(duk_require_number(ctx, 1));
    } else {
        event_idx = head - 1;
    }

    const auto& slot = hctx->ring[event_idx % InlineHookCtx::RING];

    // Build result object.
    duk_push_object(ctx);

    // Push 64-bit values as hex strings (avoids double precision loss).
    char buf[32];
    auto push_u64_hex = [&](const char* key, uint64_t v) {
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(v));
        duk_push_string(ctx, buf);
        duk_put_prop_string(ctx, -2, key);
    };

    push_u64_hex("rcx",    slot.args[0]);
    push_u64_hex("rdx",    slot.args[1]);
    push_u64_hex("r8",     slot.args[2]);
    push_u64_hex("r9",     slot.args[3]);
    push_u64_hex("stack0", slot.stack[0]);
    push_u64_hex("stack1", slot.stack[1]);
    push_u64_hex("stack2", slot.stack[2]);
    push_u64_hex("stack3", slot.stack[3]);
    duk_push_number(ctx, static_cast<double>(slot.ts_ms));
    duk_put_prop_string(ctx, -2, "ts");

    return 1;
}

// Marrow._inlineHookLeaveHead(hookId) -> total leave-snap count.
static duk_ret_t js_inline_hook_leave_head(duk_context* ctx) {
    int id = duk_require_int(ctx, 0);
    std::lock_guard<std::mutex> lk(g_mu);
    if (id < 0 || static_cast<size_t>(id) >= g_hooks.size() ||
        !g_hooks[id] || !g_hooks[id]->v2ctx) {
        duk_push_number(ctx, 0.0);
        return 1;
    }
    uint64_t h = g_hooks[id]->v2ctx->leave_head.load(std::memory_order_relaxed);
    duk_push_number(ctx, static_cast<double>(h));
    return 1;
}

// Marrow._inlineHookLeaveSnap(hookId[, eventIdx]) -> {rax, ts} or null.
// eventIdx defaults to head-1 (latest). Wraps modulo RING.
static duk_ret_t js_inline_hook_leave_snap(duk_context* ctx) {
    int id = duk_require_int(ctx, 0);

    std::lock_guard<std::mutex> lk(g_mu);
    if (id < 0 || static_cast<size_t>(id) >= g_hooks.size() ||
        !g_hooks[id] || !g_hooks[id]->v2ctx) {
        duk_push_null(ctx);
        return 1;
    }
    InlineHookCtx* hctx = g_hooks[id]->v2ctx;
    uint64_t head = hctx->leave_head.load(std::memory_order_relaxed);
    if (head == 0) { duk_push_null(ctx); return 1; }

    uint64_t event_idx;
    if (duk_get_top(ctx) >= 2 && !duk_is_undefined(ctx, 1)) {
        event_idx = static_cast<uint64_t>(duk_require_number(ctx, 1));
    } else {
        event_idx = head - 1;
    }
    const auto& slot = hctx->leave_ring[event_idx % InlineHookCtx::RING];

    duk_push_object(ctx);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(slot.rax));
    duk_push_string(ctx, buf); duk_put_prop_string(ctx, -2, "rax");
    duk_push_number(ctx, static_cast<double>(slot.ts_ms));
    duk_put_prop_string(ctx, -2, "ts");
    return 1;
}

// Static registrar — runs at DLL load time (before any agent code).
// Plugs the inline-hook engine into the core Method-hook layer so
// install_callback_hook_full can detour JIT'd verified entries.
struct JitDetourRegistrar {
    JitDetourRegistrar() {
        marrow::register_jit_detour_hooks(
            reinterpret_cast<marrow::InstallJitDetourFn>(
                &::marrow_install_user_inline_detour),
            reinterpret_cast<marrow::UninstallJitDetourFn>(
                &::marrow_uninstall_user_inline_detour));
    }
};
static JitDetourRegistrar g_jit_detour_registrar;

} // anonymous namespace

void register_inlhook_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);

    duk_push_c_function(ctx, js_inline_hook, 1);
    duk_put_prop_string(ctx, ns_idx, "_inlineHook");

    duk_push_c_function(ctx, js_inline_hook_count, 1);
    duk_put_prop_string(ctx, ns_idx, "_inlineHookCount");

    duk_push_c_function(ctx, js_inline_unhook, 1);
    duk_put_prop_string(ctx, ns_idx, "_inlineUnhook");

    duk_push_c_function(ctx, js_inline_hook_v2, 1);
    duk_put_prop_string(ctx, ns_idx, "_inlineHookV2");

    duk_push_c_function(ctx, js_inline_hook_head, 1);
    duk_put_prop_string(ctx, ns_idx, "_inlineHookHead");

    // eventIdx is optional, declare DUK_VARARGS so Duktape doesn't reject a
    // two-argument call to a function declared with nargs=1.
    duk_push_c_function(ctx, js_inline_hook_snap, DUK_VARARGS);
    duk_put_prop_string(ctx, ns_idx, "_inlineHookSnap");

    duk_push_c_function(ctx, js_inline_hook_leave_head, 1);
    duk_put_prop_string(ctx, ns_idx, "_inlineHookLeaveHead");

    duk_push_c_function(ctx, js_inline_hook_leave_snap, DUK_VARARGS);
    duk_put_prop_string(ctx, ns_idx, "_inlineHookLeaveSnap");
}

} // namespace marrow
