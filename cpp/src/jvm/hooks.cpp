#include "hooks.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include <windows.h>
#include <tlhelp32.h>

namespace marrow {

// Forward declarations for JIT-survival worker (defined later in TU).
static void register_jit_watch(uint64_t method_addr, size_t code_off,
                                size_t fie_off, size_t fce_off,
                                size_t vep_off_nm, size_t vep_off_cm,
                                size_t state_off_nm,
                                uint64_t ctx_addr,
                                uint64_t tramp_addr,
                                uint64_t initial_code);
static void unregister_jit_watch(uint64_t method_addr);
extern "C" void marrow_hook_dispatch(HookContext* ctx,
                                       uint64_t* saved_regs,
                                       uint64_t* saved_rbx_ptr,
                                       uint64_t via);

// Function-pointer indirection so marrow_core.lib doesn't link-time
// require symbols that only exist in marrow_agent.dll (the inline-hook
// engine lives in the agent). The agent registers these at startup via
// register_jit_detour_hooks(). When unset (e.g. CLI build), the JIT
// detour silently no-ops — _fie/_fce patches still cover everything except
// already-resolved JIT'd call sites.
static InstallJitDetourFn   g_install_jit_detour   = nullptr;
static UninstallJitDetourFn g_uninstall_jit_detour = nullptr;

void register_jit_detour_hooks(InstallJitDetourFn inst, UninstallJitDetourFn uninst) {
    g_install_jit_detour   = inst;
    g_uninstall_jit_detour = uninst;
}

// RAII suspend-all-other-threads. Used during Method::_from_*_entry
// patching so we don't tear the entry pointer mid-dispatch. Without
// this, hooking a method called at >700 Hz crashes the JVM when a
// dispatcher reads a half-written entry slot.
struct HookScopedSuspend {
    std::vector<HANDLE> handles;
    HookScopedSuspend() {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return;
        const DWORD our_pid = GetCurrentProcessId();
        const DWORD our_tid = GetCurrentThreadId();
        THREADENTRY32 te{}; te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != our_pid) continue;
                if (te.th32ThreadID == our_tid) continue;
                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE,
                                       te.th32ThreadID);
                if (h && SuspendThread(h) != DWORD(-1)) handles.push_back(h);
                else if (h) CloseHandle(h);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    ~HookScopedSuspend() {
        for (HANDLE h : handles) { ResumeThread(h); CloseHandle(h); }
    }
    HookScopedSuspend(const HookScopedSuspend&) = delete;
    HookScopedSuspend& operator=(const HookScopedSuspend&) = delete;
};

// 52-byte x64 trampoline, see jvm-probe/hooks.py comment block for layout.
// Two absolute addresses are patched in at offsets 14 and 44.
static constexpr std::array<uint8_t, 52> TRAMPOLINE_TEMPLATE = {
    0x9C,                                                           // pushfq
    0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
                                                                    // push rax,rcx,rdx,r8,r9,r10,r11
    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,                             // mov rax, imm64
    0xF0, 0x48, 0xFF, 0x00,                                         // lock inc qword [rax]
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,
                                                                    // pop r11,r10,r9,r8,rdx,rcx,rax
    0x9D,                                                           // popfq
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,                             // jmp qword [rip+0]
    0, 0, 0, 0, 0, 0, 0, 0,                                         // orig_entry imm64
};
static constexpr size_t COUNTER_PATCH_OFFSET = 14;
static constexpr size_t ORIG_ENTRY_PATCH_OFFSET = 44;

uint64_t MethodHook::read_count() const {
    return vm->reader()->read_u64(counter_addr);
}

void MethodHook::uninstall() {
    Reader* r = vm->reader();
    const TypeInfo* mt = vm->type("Method");
    // Pull this method out of the JIT-survival watcher's polling list
    // BEFORE we revert dispatch slots. Otherwise the worker thread
    // could re-zero _code while our restore is in flight.
    unregister_jit_watch(method.address);
    // Tear down the JIT detour FIRST so the verified entry stops sending
    // events into ctx — otherwise an in-flight JIT'd caller could fire after
    // we've nulled _code and reverted the Method dispatch slots.
    if (jit_detour_id >= 0) {
        if (g_uninstall_jit_detour) g_uninstall_jit_detour(jit_detour_id);
        jit_detour_id = -1;
    }
    r->write(method.address + mt->field("_from_interpreted_entry")->offset,
             &original_interpreted_entry, 8);
    r->write(method.address + mt->field("_from_compiled_entry")->offset,
             &original_compiled_entry, 8);
    r->write(method.address + mt->field("_code")->offset,
             &original_code, 8);
    r->free(trampoline_addr);
    if (secondary_trampoline_addr) r->free(secondary_trampoline_addr);
    r->free(counter_addr);
}

// Simple callback trampoline: saves volatile regs + flags, aligns stack,
// calls cb(ctx). Register snapshot deferred to a future revision — this
// version is the proven-working one from earlier sessions.

// Trampoline asm bytes. Saves regs into a stack frame, computes original
// RSP, calls hook_dispatch(ctx, saved_ptr=rsp_after_pushes, cb), then
// unwinds and tail-jumps to orig.
//
// Bytes (hand-assembled, position-independent):
//   9C                      pushfq                  ; save rflags
//   50                      push rax
//   51                      push rcx
//   52                      push rdx
//   53                      push rbx
//   55                      push rbp
//   56                      push rsi
//   57                      push rdi
//   41 50                   push r8
//   41 51                   push r9
//   41 52                   push r10
//   41 53                   push r11
//   41 54                   push r12
//   41 55                   push r13
//   41 56                   push r14
//   41 57                   push r15
//   ; Stack now holds 17 qwords: r15..rax (15 regs) + rflags + retaddr
//   ; Compute original RSP = current RSP + 17*8 = + 0x88, push it
//   48 8D 84 24 88 00 00 00 lea rax, [rsp + 0x88]
//   50                      push rax                ; saved_state[16] = orig rsp
//   ; Now stack pointer is the saved_state_ptr (saved[0] = r15, etc.)
//   ; Setup args for hook_dispatch(rcx=ctx, rdx=saved, r8=cb)
//   48 B9 <ctx_imm64>       mov rcx, <ctx>
//   48 89 E2                mov rdx, rsp
//   49 B8 <cb_imm64>        mov r8, <cb>
//   ; Align rsp for call (RSP should be 0 mod 16 at call). We pushed
//   ; pushfq(8) + 15 regs(120) + rax(8) = 136 bytes from caller-RSP-8
//   ; (caller RSP after their CALL pushed retaddr). Caller RSP at entry
//   ; was X; after our pushes, RSP = X - 8 (rflags) - 15*8 (regs) - 8 (lea
//   ; pushed) = X - 0x88. X mod 16 was either 0 or 8. After 0x88 (= 8 mod
//   ; 16), RSP mod 16 = X mod 16 - 8 = either -8 (=8) or 0. Call demands
//   ; 0 mod 16 BEFORE call. So conditionally align via test+sub if needed.
//   ; Simplest: always sub rsp, 0x28 (40) → mod 16 is preserved-shifted.
//   ; Actually: 40 mod 16 = 8, so total shift becomes (X mod 16 - 8 - 8) mod
//   ; 16. If X=0 → -16 → 0 (good). If X=8 → -8 → 8 (bad). Fail.
//   ; Use: pushfq(8) + 15regs(120) + saved_rsp_push(8) + sub rsp 0x20(32)
//   ; total mod 16 = (8 + 120 + 8 + 32) mod 16 = 168 mod 16 = 8.
//   ; Plus retaddr at function entry was at X-mod-16=0 (callee enters with
//   ; RSP mod 16 = 8 due to caller's CALL). So at call: rsp = X-8-168 mod 16
//   ; = -176 mod 16 = 0.
//   48 83 EC 20             sub rsp, 0x20            ; shadow space
//   FF D0                   call r8                   ; call hook_dispatch
//   48 83 C4 20             add rsp, 0x20
//   58                      pop rax                   ; pop saved_state[16]
//   ; Pop regs in reverse order
//   41 5F                   pop r15
//   41 5E                   pop r14
//   41 5D                   pop r13
//   41 5C                   pop r12
//   41 5B                   pop r11
//   41 5A                   pop r10
//   41 59                   pop r9
//   41 58                   pop r8
//   5F                      pop rdi
//   5E                      pop rsi
//   5D                      pop rbp
//   5B                      pop rbx
//   5A                      pop rdx
//   59                      pop rcx
//   58                      pop rax
//   9D                      popfq
//   FF 25 00 00 00 00       jmp qword ptr [rip+0]
//   <orig_entry_imm64>

// Restored simple working trampoline (~80 bytes).
static constexpr size_t CB_TRAMP_SIZE = 80;

static size_t emit_callback_trampoline(uint8_t* buf, uint64_t ctx_ptr,
                                        uint64_t cb_ptr, uint64_t orig_entry)
{
    size_t i = 0;
    auto put = [&](std::initializer_list<uint8_t> bs) {
        for (uint8_t b : bs) buf[i++] = b;
    };
    auto put_imm64 = [&](uint64_t v) {
        for (int k = 0; k < 8; ++k) buf[i++] = uint8_t((v >> (k * 8)) & 0xFF);
    };
    put({0x9C});                                            // pushfq
    put({0x53});                                            // push rbx
    put({0x48, 0x89, 0xE3});                                // mov rbx, rsp
    put({0x48, 0x83, 0xE4, 0xF0});                          // and rsp, -16
    put({0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41,
         0x52, 0x41, 0x53});                                // push rax,rcx,rdx,r8..r11
    put({0x48, 0x83, 0xEC, 0x20});                          // sub rsp, 0x20
    put({0x48, 0xB9}); put_imm64(ctx_ptr);                  // mov rcx, ctx
    put({0x48, 0xB8}); put_imm64(cb_ptr);                   // mov rax, cb
    put({0xFF, 0xD0});                                      // call rax
    put({0x48, 0x83, 0xC4, 0x20});                          // add rsp, 0x20
    put({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,
         0x5A, 0x59, 0x58});                                 // pop r11..rax reverse
    put({0x48, 0x89, 0xDC});                                // mov rsp, rbx
    put({0x5B});                                            // pop rbx
    put({0x9D});                                            // popfq
    put({0xFF, 0x25, 0, 0, 0, 0});                          // jmp qword [rip+0]
    put_imm64(orig_entry);
    return i;
}

MethodHook install_callback_hook(VMMeta* vm, const MethodSnapshot& method,
                                  HookCallback cb, uint64_t userdata)
{
    Reader* r = vm->reader();
    const TypeInfo* mt = vm->type("Method");

    // Allocate context struct (persistent, embedded into trampoline via ptr).
    uint64_t ctx_addr = r->alloc(sizeof(HookContext), /*exec*/false);
    HookContext ctx{};
    ctx.method = method.address;
    ctx.userdata = userdata;
    ctx.cb_ptr = reinterpret_cast<uint64_t>(cb);
    r->write(ctx_addr, &ctx, sizeof(ctx));

    // Allocate executable trampoline.
    uint64_t tramp = r->alloc(CB_TRAMP_SIZE, /*exec*/true);

    size_t fie_off = mt->field("_from_interpreted_entry")->offset;
    size_t fce_off = mt->field("_from_compiled_entry")->offset;
    size_t code_off = mt->field("_code")->offset;
    uint64_t orig_fie = r->read_u64(method.address + fie_off);
    uint64_t orig_fce = r->read_u64(method.address + fce_off);
    uint64_t orig_code = r->read_u64(method.address + code_off);

    uint8_t body[CB_TRAMP_SIZE];
    emit_callback_trampoline(body, ctx_addr,
                              reinterpret_cast<uint64_t>(cb), orig_fie);
    r->write(tramp, body, CB_TRAMP_SIZE);

    uint64_t null_code = 0;
    r->write(method.address + code_off, &null_code, 8);
    r->write(method.address + fie_off, &tramp, 8);
    r->write(method.address + fce_off, &tramp, 8);

    return MethodHook{vm, method, ctx_addr /*reuse slot for ctx*/,
                      tramp, orig_fie, orig_fce, orig_code};
}

// ---- Register-capturing trampoline ----------------------------------
// Saves all 14 GPRs (skipping RSP/RBX which are restored separately) into
// a contiguous stack frame, then calls a C dispatcher with:
//   rcx = ctx
//   rdx = ptr to saved regs (14 qwords; r15 lowest, rax highest)
//   r8  = ptr to saved-rbx slot (also gives us rflags + retaddr nearby)
// The dispatcher copies registers into ctx->regs[] using AMD64 reg-number
// indexing, snapshots 16 stack qwords, then invokes ctx->cb_ptr(ctx).

// ---------------------------------------------------------------------------
// JIT-survival worker. HotSpot's tiered compiler installs a fresh nmethod
// after a few hundred invocations of a hooked method; the new nmethod's
// verified_entry_point is what JIT'd callers will jump to. Without this
// worker, the original install_callback_hook_full's vep-patch only
// covers the nmethod that existed at install time. Any later
// recompilation produces a fresh nmethod we never patched.
//
// The worker runs at 5ms tick, walks every registered hook, and on
// detecting a *new* Method::_code (i.e., last_seen_code != current),
// patches the new vep via the inline-hook engine and zeros _code so
// subsequent dispatch falls back to the interpreter path (also hooked
// via _from_interpreted_entry).
// ---------------------------------------------------------------------------
struct JitWatchEntry {
    uint64_t method_addr;
    size_t   code_off;          // Method::_code byte offset
    size_t   fie_off;            // Method::_from_interpreted_entry byte offset
    size_t   fce_off;            // Method::_from_compiled_entry byte offset
    size_t   vep_off_nmethod;   // nmethod::_verified_entry_point (or 0)
    size_t   vep_off_cmethod;   // CompiledMethod::_verified_entry_point (or 0)
    size_t   state_off_nmethod; // nmethod::_state byte offset (or 0)
    uint64_t ctx_addr;
    uint64_t tramp_addr;        // FULL_TRAMP_SIZE trampoline (skip_orig-aware)
    uint64_t last_seen_code;
};
static std::mutex g_jit_watch_mu;
static std::vector<JitWatchEntry> g_jit_watch;
static std::atomic<bool> g_jit_thread_started{false};

__declspec(noinline)
static uint64_t seh_read_u64(uint64_t addr) {
    __try { return *reinterpret_cast<volatile uint64_t*>(addr); }
    __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
__declspec(noinline)
static bool seh_write_zero(uint64_t addr) {
    __try {
        *reinterpret_cast<volatile uint64_t*>(addr) = 0;
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
__declspec(noinline)
static bool seh_write_u64(uint64_t addr, uint64_t val) {
    __try {
        *reinterpret_cast<volatile uint64_t*>(addr) = val;
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
__declspec(noinline)
static bool seh_write_u32(uint64_t addr, uint32_t val) {
    __try {
        *reinterpret_cast<volatile uint32_t*>(addr) = val;
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Write a 14-byte absolute-jmp at `at` that jumps to `target`. Used to
// detour a freshly JIT-compiled nmethod's verified_entry_point straight
// into our FULL_TRAMP-style trampoline (which already honors
// skip_orig / replace_rax). Requires `at` to be in writable+executable
// page — the JVM allocates nmethods in RWX code cache, so this works
// without VirtualProtect dance.
//   mov rax, imm64    ; 48 b8 .. .. .. .. .. .. .. ..   (10 bytes)
//   jmp rax           ; ff e0                            ( 2 bytes)
// Total 12 bytes; we pad to 14 to match HotSpot's nmethod prolog scratch.
__declspec(noinline)
static bool seh_write_abs_jmp(uint64_t at, uint64_t target) {
    uint8_t bytes[14];
    bytes[0] = 0x48;  // REX.W
    bytes[1] = 0xB8;  // mov rax, imm64
    std::memcpy(&bytes[2], &target, 8);
    bytes[10] = 0xFF;
    bytes[11] = 0xE0; // jmp rax
    bytes[12] = 0x90; // nop pad
    bytes[13] = 0x90;
    __try {
        std::memcpy(reinterpret_cast<void*>(at), bytes, sizeof(bytes));
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void jit_watch_loop() {
    using namespace std::chrono_literals;
    while (true) {
        // 1ms poll — fast enough to catch HotSpot's multi-tier
        // recompilations (C1 → C2 transition typically takes a few ms).
        // Cost is trivial: ~N pointer reads per tick where N is the
        // hook count. Empty watchlist → continue immediately, no poll.
        std::this_thread::sleep_for(1ms);
        std::vector<JitWatchEntry> snapshot;
        {
            std::lock_guard<std::mutex> lk(g_jit_watch_mu);
            snapshot = g_jit_watch;
            if (snapshot.empty()) continue;
        }
        for (auto& entry : snapshot) {
            uint64_t code = seh_read_u64(entry.method_addr + entry.code_off);
            if (!code || code == entry.last_seen_code) continue;
            // New nmethod observed.  Three things go stale on tier-up:
            //   1. Method::_code now points at the new nmethod.
            //   2. Method::_from_compiled_entry now points at nmethod's
            //      verified entry — bypassing our trampoline.
            //   3. Method::_from_interpreted_entry may be re-set to a
            //      fresh c2i adapter — bypassing our trampoline too.
            //   4. Inside the new nmethod itself, the verified_entry_point
            //      stub is a direct compiled prologue. Existing JIT'd
            //      callers may have inlined the call site to jump there
            //      directly.
            // Re-apply ALL four patches: re-write _fie & _fce back to
            // our trampoline (so dispatch comes through us), zero _code
            // (so the interpreter path stays preferred), and write a
            // 14-byte abs-jmp at the nmethod's verified_entry_point so
            // already-resolved JIT'd callers also land in our trampoline.
            seh_write_u64(entry.method_addr + entry.fie_off, entry.tramp_addr);
            seh_write_u64(entry.method_addr + entry.fce_off, entry.tramp_addr);
            uint64_t vep = 0;
            if (entry.vep_off_nmethod)
                vep = seh_read_u64(code + entry.vep_off_nmethod);
            if (!vep && entry.vep_off_cmethod)
                vep = seh_read_u64(code + entry.vep_off_cmethod);
            if (vep && entry.tramp_addr) {
                seh_write_abs_jmp(vep, entry.tramp_addr);
            }
            // Mark the new nmethod as `not_entrant` (state=1) to force
            // any inline-cached call site that resolved to its vep
            // BEFORE our patch to re-resolve through Method::_from_
            // compiled_entry on next call. Since fce is patched to our
            // trampoline, that re-resolve lands in the hook. This is
            // what closes the IC-already-cached-old-vep gap that
            // limited callOriginal hit-rate to ~7% in v0.2.2.
            if (entry.state_off_nmethod) {
                seh_write_u32(code + entry.state_off_nmethod, /*not_entrant*/1);
            }
            seh_write_zero(entry.method_addr + entry.code_off);
            {
                std::lock_guard<std::mutex> lk(g_jit_watch_mu);
                for (auto& e : g_jit_watch) {
                    if (e.method_addr == entry.method_addr) {
                        e.last_seen_code = code;
                        break;
                    }
                }
            }
        }
    }
}

static void start_jit_watch_once() {
    bool expected = false;
    if (!g_jit_thread_started.compare_exchange_strong(expected, true)) return;
    std::thread(jit_watch_loop).detach();
}

static void register_jit_watch(uint64_t method_addr, size_t code_off,
                                size_t fie_off, size_t fce_off,
                                size_t vep_off_nm, size_t vep_off_cm,
                                size_t state_off_nm,
                                uint64_t ctx_addr,
                                uint64_t tramp_addr,
                                uint64_t initial_code) {
    {
        std::lock_guard<std::mutex> lk(g_jit_watch_mu);
        g_jit_watch.push_back({method_addr, code_off, fie_off, fce_off,
                                vep_off_nm, vep_off_cm, state_off_nm,
                                ctx_addr, tramp_addr, initial_code});
    }
    start_jit_watch_once();
}

static void unregister_jit_watch(uint64_t method_addr) {
    std::lock_guard<std::mutex> lk(g_jit_watch_mu);
    g_jit_watch.erase(
        std::remove_if(g_jit_watch.begin(), g_jit_watch.end(),
            [&](const JitWatchEntry& e){ return e.method_addr == method_addr; }),
        g_jit_watch.end());
}

// Per-thread, per-cookie reentry guard. Lets a JS handler invoke the
// original method without recursing into itself: handler sets the flag,
// calls the method (which goes through the trampoline again), and the
// trampoline sees the flag set, skips dispatch, and tail-jumps to the
// original entry — running the unmodified method body. Handler clears
// the flag after the call returns.
//
// Indexed by `cookie` (HookContext::userdata). Storage is thread_local
// so concurrent threads don't interfere with each other. Bounded array
// for cheap lookup; if a user installs >32 hooks per thread they fall
// back to handler-fired-on-reentry behavior (correct, just less useful).
constexpr size_t REENTRY_SLOTS = 32;
struct ReentrySlot { uint64_t cookie; int depth; };
static thread_local ReentrySlot tls_reentry[REENTRY_SLOTS] = {};

static int* find_reentry_slot(uint64_t cookie, bool create) {
    for (size_t i = 0; i < REENTRY_SLOTS; ++i) {
        if (tls_reentry[i].cookie == cookie && tls_reentry[i].depth >= 0)
            return &tls_reentry[i].depth;
    }
    if (!create) return nullptr;
    for (size_t i = 0; i < REENTRY_SLOTS; ++i) {
        if (tls_reentry[i].cookie == 0 && tls_reentry[i].depth == 0) {
            tls_reentry[i].cookie = cookie;
            return &tls_reentry[i].depth;
        }
    }
    return nullptr;
}

// JS-facing: bump (delta=+1) / drop (delta=-1) the per-thread guard for
// `cookie`. Returns the new depth, or -1 if the slot table is full.
extern "C" int marrow_hook_set_reentry(uint64_t cookie, int delta) {
    int* slot = find_reentry_slot(cookie, /*create=*/delta > 0);
    if (!slot) return delta > 0 ? -1 : 0;
    *slot += delta;
    if (*slot < 0) *slot = 0;
    return *slot;
}

extern "C" void marrow_hook_dispatch(HookContext* ctx,
                                        uint64_t* saved_regs,
                                        uint64_t* saved_rbx_ptr,
                                        uint64_t via) {
    // saved_regs (low → high address):
    //   [0]=r15 [1]=r14 [2]=r13 [3]=r12 [4]=r11 [5]=r10 [6]=r9 [7]=r8
    //   [8]=rdi [9]=rsi [10]=rbp [11]=rdx [12]=rcx [13]=rax
    // `via` = 0 when reached through _from_interpreted_entry, 1 through
    // _from_compiled_entry. Lets the JS decoder pick operand-stack vs
    // register-arg conventions.

    // Always reset skip_orig at start: stale value from a previous fire
    // would otherwise cause this call to skip orig with a wrong rax.
    if (ctx) {
        ctx->skip_orig    = 0;
        ctx->replace_rax  = 0;
    }
    // Reentry-guard short-circuit. When the JS handler is mid-callOriginal,
    // a re-fire on the same thread+cookie skips dispatch entirely — the
    // trampoline's tail-jmp to orig_fie still runs the original body.
    if (ctx) {
        int* slot = find_reentry_slot(ctx->userdata, /*create=*/false);
        if (slot && *slot > 0) return;
    }

    if (ctx) {
        ctx->via = via;
        ctx->regs[0]  = saved_regs[13];   // RAX
        ctx->regs[1]  = saved_regs[12];   // RCX
        ctx->regs[2]  = saved_regs[11];   // RDX
        ctx->regs[3]  = saved_rbx_ptr[0]; // RBX (orig)
        ctx->regs[4]  = reinterpret_cast<uint64_t>(saved_rbx_ptr) + 16;
                                          // RSP at method-entry (= addr of retaddr)
        ctx->regs[5]  = saved_regs[10];   // RBP
        ctx->regs[6]  = saved_regs[9];    // RSI
        ctx->regs[7]  = saved_regs[8];    // RDI
        ctx->regs[8]  = saved_regs[7];    // R8
        ctx->regs[9]  = saved_regs[6];    // R9
        ctx->regs[10] = saved_regs[5];    // R10
        ctx->regs[11] = saved_regs[4];    // R11
        ctx->regs[12] = saved_regs[3];    // R12
        ctx->regs[13] = saved_regs[2];    // R13
        ctx->regs[14] = saved_regs[1];    // R14
        ctx->regs[15] = saved_regs[0];    // R15
        // Stack snapshot: [saved_rbx_ptr+16] is the original retaddr
        // pushed by caller's CALL. Beyond that lies caller's frame /
        // overflow args. Wrap in a SEH-style guard against bad reads.
        uint64_t* stk = saved_rbx_ptr + 2;
        __try {
            for (int i = 0; i < 16; ++i) ctx->stack[i] = stk[i];
        } __except(1 /*EXCEPTION_EXECUTE_HANDLER*/) {
            for (int i = 0; i < 16; ++i) ctx->stack[i] = 0;
        }
        auto cb = reinterpret_cast<HookCallback>(ctx->cb_ptr);
        if (cb) cb(ctx);
        ctx->fire_count++;
        // JIT-survival: HotSpot's tiered compiler installs a fresh
        // nmethod after a few hundred invocations of a hooked method,
        // bypassing our trampoline. Re-zero Method::_code on every
        // fire so subsequent dispatches stay on the interpreter path
        // (which still goes through _from_interpreted_entry, our
        // trampoline). _from_compiled_entry is intentionally NOT
        // rewritten: HotSpot may store an inline-cache stub there
        // and overwriting kills cache invalidation. Wrapped in SEH
        // so an unmapped Method (post-GC class-unloading) can't
        // crash the dispatch.
        if (ctx->method_code_addr) {
            __try {
                *reinterpret_cast<volatile uint64_t*>(ctx->method_code_addr) = 0;
            } __except(1 /*EXCEPTION_EXECUTE_HANDLER*/) { /* swallow */ }
        }
    }
}

// Trampoline now ~137 bytes (was 114) — added post-dispatch check of
// HookContext::skip_orig at offset 40. When the dispatch C function (or
// a sync handler invoked from there) sets that byte to 1, the trampoline
// loads HookContext::replace_rax (offset 48) into rax and RETs to caller
// instead of tail-jumping to orig_entry. This implements Frida-style
// `.implementation = fn` semantics where the handler's return value
// replaces the method's return.
static constexpr size_t FULL_TRAMP_SIZE       = 160;
static constexpr size_t FULL_CTX_PATCH        = 33;   // first mov rcx,ctx
static constexpr size_t FULL_VIA_PATCH        = 49;
static constexpr size_t FULL_DISPATCH_PATCH   = 59;
static constexpr size_t FULL_CTX2_PATCH       = 103;  // second mov r10,ctx
static constexpr size_t FULL_ORIG_PATCH       = 137;

static size_t emit_full_trampoline(uint8_t* buf, uint64_t ctx_ptr,
                                    uint32_t via,
                                    uint64_t dispatch_ptr,
                                    uint64_t orig_entry)
{
    // Layout (offsets in comments, byte index of patch slots match
    // the FULL_*_PATCH constants above):
    static const uint8_t TEMPLATE[145] = {
        0x9C,                                                    // 00 pushfq
        0x53,                                                    // 01 push rbx
        0x48, 0x89, 0xE3,                                        // 02 mov rbx,rsp
        0x48, 0x83, 0xE4, 0xF0,                                  // 05 and rsp,-16
        0x50, 0x51, 0x52, 0x55, 0x56, 0x57,                      // 09 push rax,rcx,rdx,rbp,rsi,rdi
        0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
        0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,          // 15 push r8..r15
        0x48, 0xB9, 0,0,0,0,0,0,0,0,                             // 31 mov rcx, ctx_imm  (imm @ 33)
        0x48, 0x89, 0xE2,                                        // 41 mov rdx, rsp
        0x49, 0x89, 0xD8,                                        // 44 mov r8, rbx
        0x41, 0xB9, 0,0,0,0,                                     // 47 mov r9d, via_imm32 (imm @ 49)
        0x48, 0x83, 0xEC, 0x20,                                  // 53 sub rsp, 0x20
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                             // 57 mov rax, dispatch_imm (imm @ 59)
        0xFF, 0xD0,                                              // 67 call rax
        0x48, 0x83, 0xC4, 0x20,                                  // 69 add rsp, 0x20
        0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C,
        0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,          // 73 pop r15..r8
        0x5F, 0x5E, 0x5D, 0x5A, 0x59, 0x58,                      // 89 pop rdi,rsi,rbp,rdx,rcx,rax
        0x48, 0x89, 0xDC,                                        // 95 mov rsp, rbx
        0x5B,                                                    // 98 pop rbx
        // skip_orig branch — preserves r10 for the c2i adapter on the
        // .orig path (HotSpot c2i uses r10 to carry Method* in some
        // builds). r10 is volatile per Win64, so the skip path can
        // discard the saved value and just `add rsp,8`.
        0x41, 0x52,                                              // 99  push r10
        0x49, 0xBA, 0,0,0,0,0,0,0,0,                             // 101 mov r10, ctx_imm (imm @ 103)
        0x41, 0xF6, 0x42, 0x28, 0x01,                            // 111 test byte [r10+0x28], 1
        0x74, 0x0A,                                              // 116 jz .orig (rel +10 → 128)
        0x49, 0x8B, 0x42, 0x30,                                  // 118 mov rax, [r10+0x30]
        0x48, 0x83, 0xC4, 0x08,                                  // 122 add rsp, 8 (drop saved r10)
        0x9D,                                                    // 126 popfq
        0xC3,                                                    // 127 ret
        // .orig:
        0x41, 0x5A,                                              // 128 pop r10  (restore caller r10)
        0x9D,                                                    // 130 popfq
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,                      // 131 jmp [rip+0]
        0,0,0,0,0,0,0,0,                                         // 137 orig_entry imm64
    };
    std::memcpy(buf, TEMPLATE, sizeof(TEMPLATE));
    std::memcpy(buf + FULL_CTX_PATCH,      &ctx_ptr,      8);
    std::memcpy(buf + FULL_VIA_PATCH,      &via,          4);
    std::memcpy(buf + FULL_DISPATCH_PATCH, &dispatch_ptr, 8);
    std::memcpy(buf + FULL_CTX2_PATCH,     &ctx_ptr,      8);
    std::memcpy(buf + FULL_ORIG_PATCH,     &orig_entry,   8);
    return sizeof(TEMPLATE);
}

MethodHook install_callback_hook_full(VMMeta* vm, const MethodSnapshot& method,
                                       HookCallback cb, uint64_t userdata)
{
    Reader* r = vm->reader();
    const TypeInfo* mt = vm->type("Method");

    uint64_t ctx_addr = r->alloc(sizeof(HookContext), /*exec*/false);
    HookContext ctx{};
    ctx.method = method.address;
    ctx.userdata = userdata;
    ctx.cb_ptr = reinterpret_cast<uint64_t>(cb);
    // tramp_addr filled in below once trampoline is allocated.

    size_t fie_off = mt->field("_from_interpreted_entry")->offset;
    size_t fce_off = mt->field("_from_compiled_entry")->offset;
    size_t code_off = mt->field("_code")->offset;
    uint64_t orig_fie = r->read_u64(method.address + fie_off);
    uint64_t orig_fce = r->read_u64(method.address + fce_off);
    uint64_t orig_code = r->read_u64(method.address + code_off);

    // JIT-survival: cache absolute addresses of Method::_code and
    // Method::_from_compiled_entry so marrow_hook_dispatch can re-zero
    // _code and re-write _from_compiled_entry on every fire. Without
    // this, HotSpot's tiered JIT compiles the method after a few
    // hundred invocations and the new nmethod bypasses our trampoline.
    ctx.method_code_addr = method.address + code_off;
    ctx.method_fce_addr  = method.address + fce_off;
    // tramp_addr set after trampoline alloc below.
    r->write(ctx_addr, &ctx, sizeof(ctx));

    uint64_t dispatch = reinterpret_cast<uint64_t>(&marrow_hook_dispatch);

    // ONE trampoline shared by both _fie and _fce. Empirically, JNI's
    // CallStatic*MethodA on never-JIT'd interpreter methods dispatches
    // through `_from_interpreted_entry` (NOT `_from_compiled_entry` as
    // the comment in the public source might suggest). Sharing one
    // trampoline tail-jumping to orig_fie is correct: the original _fie
    // is the c2i/interpreter entry that knows how to handle the args
    // (which arrive on the operand stack).
    uint64_t tramp = r->alloc(FULL_TRAMP_SIZE, /*exec*/true);
    uint8_t body[FULL_TRAMP_SIZE] = {};
    emit_full_trampoline(body, ctx_addr, /*via=*/0, dispatch, orig_fie);
    r->write(tramp, body, FULL_TRAMP_SIZE);

    // Now that tramp is allocated, write its address into ctx so
    // marrow_hook_dispatch can re-write Method::_from_compiled_entry
    // back to it after a JIT recompile clobbered the field.
    {
        uint64_t tramp_addr_in_ctx = ctx_addr +
            offsetof(HookContext, tramp_addr);
        r->write(tramp_addr_in_ctx, &tramp, sizeof(tramp));
    }

    // Read the nmethod's verified_entry_point BEFORE we null _code — that
    // address is what JIT'd callers have baked into their call sites, and
    // patching `_from_compiled_entry` afterwards doesn't relink them.
    // We detour the entry itself via the inline-hook engine so existing
    // JIT'd callers still land in our dispatcher.
    //
    // VMMeta exposes the `_verified_entry_point` slot on EITHER `nmethod`
    // (older HotSpot) or its parent `CompiledMethod` (JDK 13+ split). Try
    // both — some builds only register the field on one.
    uint64_t verified_entry = 0;
    int      vep_src = 0;   // 0=none, 1=nmethod, 2=CompiledMethod
    if (orig_code) {
        const TypeInfo* nmt = vm->type("nmethod");
        if (nmt) {
            if (auto* f = nmt->field("_verified_entry_point")) {
                verified_entry = r->read_u64(orig_code + f->offset);
                vep_src = 1;
            }
        }
        if (!verified_entry) {
            if (auto* cmt = vm->type("CompiledMethod")) {
                if (auto* f = cmt->field("_verified_entry_point")) {
                    verified_entry = r->read_u64(orig_code + f->offset);
                    vep_src = 2;
                }
            }
        }
    }
    (void)vep_src;

    // Freeze all other threads during the entry-pointer patch so a hot
    // dispatcher can't read a torn entry slot mid-write. The JIT-entry
    // detour is also installed under the same suspend window — the inline
    // engine performs a 14-byte abs-jmp write which is not torn-safe on
    // a hot core.
    int jit_id = -1;
    {
        HookScopedSuspend pause;
        uint64_t null_code = 0;
        r->write(method.address + code_off, &null_code, 8);
        r->write(method.address + fie_off, &tramp, 8);
        r->write(method.address + fce_off, &tramp, 8);

        if (verified_entry && g_install_jit_detour) {
            jit_id = g_install_jit_detour(
                reinterpret_cast<void*>(verified_entry),
                ctx_addr,
                reinterpret_cast<uint64_t>(&marrow_hook_dispatch),
                /*via=*/1);
            // Failure is non-fatal: the interpreter & c2i paths are still
            // hooked. JIT'd already-resolved callers just won't fire until
            // they get re-resolved (e.g. after a deopt cycle).
        } else if (verified_entry) {
            // Engine not registered — diagnostic surfaced as -2 so JS can
            // distinguish "engine missing" from "engine refused to detour".
            jit_id = -2;
        }
    }

    MethodHook hk{vm, method, ctx_addr, tramp,
                  orig_fie, orig_fce, orig_code,
                  /*secondary=*/0};
    hk.jit_detour_id = jit_id;
    hk.jit_detour_va = verified_entry;       // even if detour failed, useful for diag
    hk.jit_detour_vep_src = vep_src;

    // Spin up the JIT-survival watcher for this hook. Resolve the
    // verified_entry_point + _state offsets once (already-discovered
    // type carries them).
    size_t vep_off_nm = 0, vep_off_cm = 0, state_off_nm = 0;
    if (auto* nmt = vm->type("nmethod")) {
        if (auto* f = nmt->field("_verified_entry_point"))
            vep_off_nm = f->offset;
        if (auto* f = nmt->field("_state"))
            state_off_nm = f->offset;
    }
    if (auto* cmt = vm->type("CompiledMethod")) {
        if (auto* f = cmt->field("_verified_entry_point"))
            vep_off_cm = f->offset;
    }
    register_jit_watch(method.address, code_off, fie_off, fce_off,
                       vep_off_nm, vep_off_cm, state_off_nm,
                       ctx_addr, /*tramp_addr=*/tramp,
                       /*initial_code=*/orig_code);
    return hk;
}

MethodHook install_counting_hook(VMMeta* vm, const MethodSnapshot& method)
{
    Reader* r = vm->reader();
    const TypeInfo* mt = vm->type("Method");

    uint64_t counter_addr = r->alloc(8, /*exec*/false);
    uint64_t trampoline_addr = r->alloc(TRAMPOLINE_TEMPLATE.size(), /*exec*/true);
    uint64_t zero = 0;
    r->write(counter_addr, &zero, 8);

    size_t fie_off = mt->field("_from_interpreted_entry")->offset;
    size_t fce_off = mt->field("_from_compiled_entry")->offset;
    size_t code_off = mt->field("_code")->offset;
    uint64_t orig_fie = r->read_u64(method.address + fie_off);
    uint64_t orig_fce = r->read_u64(method.address + fce_off);
    uint64_t orig_code = r->read_u64(method.address + code_off);

    std::array<uint8_t, 52> body = TRAMPOLINE_TEMPLATE;
    std::memcpy(body.data() + COUNTER_PATCH_OFFSET, &counter_addr, 8);
    std::memcpy(body.data() + ORIG_ENTRY_PATCH_OFFSET, &orig_fie, 8);
    r->write(trampoline_addr, body.data(), body.size());

    uint64_t null_code = 0;
    r->write(method.address + code_off, &null_code, 8);
    r->write(method.address + fie_off, &trampoline_addr, 8);
    r->write(method.address + fce_off, &trampoline_addr, 8);

    return MethodHook{vm, method, counter_addr, trampoline_addr,
                      orig_fie, orig_fce, orig_code};
}

} // namespace marrow
