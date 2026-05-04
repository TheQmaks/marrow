// Hardware-watchpoint subsystem for the in-process agent. Builds on the
// DR0-DR3 plumbing in injector.cpp but runs entirely inside the target.
//
// API surface from JS:
//   Marrow.watchAddr(addr_lo, addr_hi, length=4, slot=0) -> cookie
//   Marrow.unwatch(cookie)
//   Marrow.drainWatches() -> [{cookie, addr, faultRip, count}, ...]
//
// Implementation: register a Vectored Exception Handler that catches
// EXCEPTION_SINGLE_STEP, checks DR6 against our active slots, and pushes
// an event into a ring buffer. The DR registers themselves are armed
// per-JavaThread via SuspendThread+SetThreadContext on every active
// thread. New threads spawned later are NOT auto-armed (TODO: rearm via
// CreateRemoteThread / load-time hook).

#include "vm_meta.hpp"
#include "walker.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

namespace marrow {

extern void agent_log(const char* fmt, ...);

struct WatchEntry {
    bool active = false;
    uint64_t addr = 0;
    int length = 4;
    uint32_t cookie = 0;
    std::atomic<uint64_t> hits{0};
    std::atomic<uint64_t> drained{0};
    std::atomic<uint64_t> last_fault_rip{0};
};

static WatchEntry g_slots[4];
static std::mutex g_slots_mu;
static PVOID g_veh = nullptr;
static std::atomic<uint32_t> g_cookie_seed{1};

static LONG CALLBACK watch_veh(PEXCEPTION_POINTERS info) {
    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    auto* ctx = info->ContextRecord;
    // DR6 bits 0..3 indicate which breakpoint fired.
    DWORD64 dr6 = ctx->Dr6;
    bool any = false;
    for (int i = 0; i < 4; ++i) {
        if (!(dr6 & (1ull << i))) continue;
        if (!g_slots[i].active) continue;
        g_slots[i].hits.fetch_add(1, std::memory_order_relaxed);
        g_slots[i].last_fault_rip.store(uint64_t(ctx->Rip),
                                          std::memory_order_relaxed);
        any = true;
    }
    if (!any) return EXCEPTION_CONTINUE_SEARCH;
    ctx->Dr6 = 0;
    // Set RF in EFlags so we re-execute the faulting instruction without
    // immediately re-faulting on the same DR.
    ctx->EFlags |= 0x10000;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void ensure_veh_installed() {
    static std::once_flag once;
    std::call_once(once, []{
        g_veh = AddVectoredExceptionHandler(/*first*/1, watch_veh);
        agent_log("watch: VEH installed @ %p", g_veh);
    });
}

// Encode DR7 bits for a slot. length: 1/2/4/8 → LEN code 00/01/11/10.
// Watch writes only.
static uint64_t dr7_slot_bits(int slot, int length) {
    int len_code;
    switch (length) {
        case 1: len_code = 0; break;
        case 2: len_code = 1; break;
        case 4: len_code = 3; break;
        case 8: len_code = 2; break;
        default: len_code = 3;
    }
    return (1ull << (slot * 2))                         // L<slot>=1
         | (1ull << (16 + slot * 4))                    // RW<slot>=01 (writes)
         | (uint64_t(len_code) << (18 + slot * 4));      // LEN
}

static uint64_t dr7_slot_mask(int slot) {
    return (0b11ull << (slot * 2))
         | (0b1111ull << (16 + slot * 4));
}

// Iterate every thread of the current process and apply `fn` to its
// CONTEXT (with DR fields). Skips our own thread to avoid self-deadlock.
template <class Fn>
static void update_threads(VMMeta* vm, Fn fn) {
    DWORD self_tid = GetCurrentThreadId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    DWORD self_pid = GetCurrentProcessId();
    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != self_pid) continue;
            if (te.th32ThreadID == self_tid) continue;
            HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT
                                   | THREAD_SUSPEND_RESUME, FALSE,
                                   te.th32ThreadID);
            if (!h) continue;
            SuspendThread(h);
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(h, &ctx)) {
                fn(ctx);
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                SetThreadContext(h, &ctx);
            }
            ResumeThread(h);
            CloseHandle(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    (void)vm;
}

// Public C entry points called from agent_js.cpp bindings.

uint32_t agent_watch_addr(VMMeta* vm, uint64_t addr, int length, int slot) {
    if (slot < 0 || slot > 3) return 0;
    if (length != 1 && length != 2 && length != 4 && length != 8) return 0;
    ensure_veh_installed();
    uint32_t cookie = g_cookie_seed.fetch_add(1);
    {
        std::lock_guard<std::mutex> g(g_slots_mu);
        g_slots[slot].active = true;
        g_slots[slot].addr = addr;
        g_slots[slot].length = length;
        g_slots[slot].cookie = cookie;
        g_slots[slot].hits.store(0);
        g_slots[slot].drained.store(0);
    }
    uint64_t bits = dr7_slot_bits(slot, length);
    uint64_t mask = dr7_slot_mask(slot);
    update_threads(vm, [&](CONTEXT& ctx) {
        switch (slot) {
            case 0: ctx.Dr0 = addr; break;
            case 1: ctx.Dr1 = addr; break;
            case 2: ctx.Dr2 = addr; break;
            case 3: ctx.Dr3 = addr; break;
        }
        ctx.Dr7 = (ctx.Dr7 & ~mask) | bits;
    });
    agent_log("watch: armed DR%d on %llx len=%d cookie=%u",
              slot, (unsigned long long)addr, length, cookie);
    return cookie;
}

bool agent_unwatch(VMMeta* vm, uint32_t cookie) {
    int slot = -1;
    {
        std::lock_guard<std::mutex> g(g_slots_mu);
        for (int i = 0; i < 4; ++i) {
            if (g_slots[i].active && g_slots[i].cookie == cookie) {
                slot = i;
                g_slots[i].active = false;
                break;
            }
        }
    }
    if (slot < 0) return false;
    uint64_t mask = dr7_slot_mask(slot);
    update_threads(vm, [&](CONTEXT& ctx) {
        ctx.Dr7 &= ~mask;
        switch (slot) {
            case 0: ctx.Dr0 = 0; break;
            case 1: ctx.Dr1 = 0; break;
            case 2: ctx.Dr2 = 0; break;
            case 3: ctx.Dr3 = 0; break;
        }
    });
    return true;
}

struct WatchEvent {
    uint32_t cookie;
    uint64_t addr;
    uint64_t fault_rip;
    uint64_t delta_count;
    uint64_t total_count;
};

void agent_watch_unwatch_all() {
    std::vector<uint32_t> cookies;
    {
        std::lock_guard<std::mutex> g(g_slots_mu);
        for (auto& s : g_slots)
            if (s.active) cookies.push_back(s.cookie);
    }
    for (uint32_t c : cookies)
        agent_unwatch(nullptr, c);
}

std::vector<WatchEvent> agent_drain_watches() {
    std::vector<WatchEvent> out;
    std::lock_guard<std::mutex> g(g_slots_mu);
    for (auto& s : g_slots) {
        if (!s.active) continue;
        uint64_t hits = s.hits.load(std::memory_order_relaxed);
        uint64_t drained = s.drained.load(std::memory_order_relaxed);
        if (hits == drained) continue;
        out.push_back({s.cookie, s.addr,
                        s.last_fault_rip.load(std::memory_order_relaxed),
                        hits - drained, hits});
        s.drained.store(hits, std::memory_order_relaxed);
    }
    return out;
}

} // namespace marrow
