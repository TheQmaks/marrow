// agent_xref_resolvers.cpp — fully-dynamic resolution of internal HotSpot
// symbols, no PDB and no user-supplied byte patterns required.
//
// Strategy: every interesting internal symbol is reached from at least one
// EXPORTED jvm.dll function (JNI_*, JVM_*) which we resolve via
// GetProcAddress. We then walk that exported function's body with
// xref_scan() and pick the right CALL target / RIP-relative load by
// position + simple validation against the surrounding module.
//
// This file owns the per-symbol heuristics. Each function is short and
// independently testable. Hooked into resolve_symbol() as the 4th
// fallback (PDB → GetProcAddress → patterns → here).

#include "agent_modules.hpp"
#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstring>
#include <vector>

namespace marrow {

// Forward decl from agent_xref.cpp. Layout MUST match agent_xref.cpp.
struct XrefScan {
    std::vector<uint64_t> calls;
    std::vector<uint64_t> jumps;
    std::vector<uint64_t> rip_refs;
    const char* stop_reason = "ok";
    size_t insns_walked = 0;
};
extern XrefScan xref_scan(uint64_t va, size_t max_insns);

namespace {

// Cached jvm.dll module range. Used to validate that resolved targets
// actually live inside jvm.dll's image (filters out dispatch into
// kernel32/ntdll thunks).
struct JvmRange { uintptr_t base = 0; size_t size = 0; };

static JvmRange jvm_range() {
    static JvmRange r;
    if (r.base) return r;
    HMODULE jvm = GetModuleHandleA("jvm.dll");
    if (!jvm) return r;
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), jvm, &mi, sizeof(mi))) return r;
    r.base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
    r.size = mi.SizeOfImage;
    return r;
}

static bool in_jvm(uint64_t va) {
    auto r = jvm_range();
    if (!r.base) return false;
    return va >= r.base && va < r.base + r.size;
}

// In-process safe read.
template <typename T>
static bool seh_read(uint64_t va, T* out) {
    __try {
        std::memcpy(out, reinterpret_cast<const void*>(va), sizeof(T));
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// SEH-protected read of a fixed prologue. Kept as a separate noinline
// function so the caller can hold C++ objects with destructors.
static bool seh_read_prologue3(uint64_t va, uint8_t out[3]) {
    __try {
        out[0] = ((uint8_t*)va)[0];
        out[1] = ((uint8_t*)va)[1];
        out[2] = ((uint8_t*)va)[2];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Look up an exported function on jvm.dll. Returns 0 if missing.
static uint64_t exp_addr(const char* name) {
    HMODULE jvm = GetModuleHandleA("jvm.dll");
    if (!jvm) return 0;
    auto p = GetProcAddress(jvm, name);
    return reinterpret_cast<uint64_t>(p);
}

// ---------------------------------------------------------------------
// Per-symbol resolvers
// ---------------------------------------------------------------------
// Each returns the symbol's runtime address (in jvm.dll) or 0 on failure.
// All resolvers must be safe to call from any thread at any time — they
// only read code memory and do not mutate state.
//
// Heuristic notes are embedded as comments above each resolver. When
// HotSpot internals shift (rare — these paths have been stable for years),
// adjust the per-symbol "expected position" tweaks below.

// main_vm — global JavaVM*. JNI_GetCreatedJavaVMs reads `vm_created` then
// dereferences `main_vm` to fill *vm_buf. Layout:
//   if (vm_created == 1) {
//     if (numVMs)  *numVMs  = 1;
//     if (bufsize) *vm_buf  = main_vm;
//   }
// First RIP-rel load = vm_created, second = main_vm. Validate that the
// pointer at ripRefs[1] is non-null when JVM is running (guarantees
// it's not the wrong slot).
static uint64_t resolve_main_vm() {
    uint64_t fn = exp_addr("JNI_GetCreatedJavaVMs");
    if (!fn) return 0;
    auto sc = xref_scan(fn, 32);
    if (sc.rip_refs.size() < 2) return 0;
    uint64_t cand = sc.rip_refs[1];
    // main_vm is itself a JavaVM** essentially — *cand should be a
    // pointer-sized value within process memory. Sanity-check.
    uint64_t deref = 0;
    if (!seh_read(cand, &deref)) return 0;
    if (deref == 0) return 0;
    return cand;
}

// Extract the JNIEnv→JavaThread offset by walking JVM_NewArray's prologue
// and matching `LEA reg, [rcx-disp32]`. HotSpot stores JNIEnv as a member
// of JavaThread, so every JVM_* function does this conversion right at
// the top:
//     mov eax, [rcx+0xB0]            ; touch JNIEnv field
//     lea rbx, [rcx-0x2b8]           ; rbx = JavaThread*
// The disp32 is per-build but stable across the JVM lifetime — extract it
// once from a known-good function and cache.
//
// Returns 0 if the LEA pattern can't be located (defensive: caller treats
// "0 offset" as "extraction failed", not "offset is literally zero" —
// JavaThread always lies BEFORE JNIEnv in memory so the real offset is
// negative and non-zero in practice).
static int32_t resolve_jnienv_to_thread_offset() {
    // Cache to avoid scanning every call.
    static int32_t cached = 0;
    static bool tried = false;
    if (tried) return cached;
    tried = true;

    HMODULE jvm = GetModuleHandleA("jvm.dll");
    if (!jvm) return 0;
    auto try_one = [&](const char* fn_name) -> int32_t {
        auto fn = (uint64_t)GetProcAddress(jvm, fn_name);
        if (!fn) return 0;
        // Read first 64 bytes; look for the canonical "LEA reg, [rcx-disp32]"
        // pattern. Encoding: REX.W (48 / 4C) + 8D + ModRM (mod=10b, rm=001b → 0x91/0x99/0xa9/...).
        uint8_t buf[64];
        __try { std::memcpy(buf, (void*)fn, sizeof(buf)); }
        __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
        for (int i = 0; i < 56; ++i) {
            // 48 8D ?1  with ?? = 0x91/0x99/0xa1/0xa9/0xb1/0xb9/0xb1...
            // mod=10b means top two bits set; rm=001b means low 3 bits = 001.
            // Valid bytes: 0x91, 0x99, 0xA1, 0xA9, 0xB1, 0xB9 (registers
            // RDX, RBX, RSP-skip, RBP, RSI, RDI). Plus REX.B variants 0x4C 8D.
            uint8_t prefix = buf[i];
            if (prefix != 0x48 && prefix != 0x4C) continue;
            if (buf[i+1] != 0x8D) continue;
            uint8_t modrm = buf[i+2];
            if ((modrm & 0xC7) != 0x81) continue;  // mod=10b, rm=001b
            int32_t disp = 0;
            std::memcpy(&disp, buf + i + 3, 4);
            // Sanity: must be negative (JavaThread sits before JNIEnv).
            // Range check: typical values are -1000..-200 (multiples of 8).
            if (disp >= 0 || disp < -16384) continue;
            return disp;
        }
        return 0;
    };
    int32_t v = try_one("JVM_NewArray");
    if (!v) v = try_one("JVM_DefineClass");
    if (!v) v = try_one("JVM_FindClassFromCaller");
    if (!v) v = try_one("JVM_GetClassDeclaredFields");
    cached = v;
    return v;
}

// Read the JavaVM vtable slot at `slot_offset` (in bytes from the start
// of struct JNIInvokeInterface_). Returns the function pointer or 0.
//
//  struct JavaVM_ { const JNIInvokeInterface_* functions; };
//  struct JNIInvokeInterface_ {
//    void* reserved0..2;             // +0,+8,+16
//    DestroyJavaVM        @ +24
//    AttachCurrentThread  @ +32
//    DetachCurrentThread  @ +40
//    GetEnv               @ +48
//    AttachCurrentThreadAsDaemon @ +56
//  };
static uint64_t javavm_vtable_slot(int slot_offset) {
    uint64_t main_vm_addr = resolve_main_vm();
    if (!main_vm_addr) return 0;
    uint64_t java_vm = 0;
    if (!seh_read(main_vm_addr, &java_vm) || !java_vm) return 0;
    uint64_t functions = 0;
    if (!seh_read(java_vm, &functions) || !functions) return 0;
    uint64_t slot = 0;
    if (!seh_read(functions + slot_offset, &slot) || !slot) return 0;
    return slot;
}

// JavaThread::current — every JNIEnv method begins by calling it to
// fetch the per-thread state. Inside the AttachCurrentThread thunk
// that's also true. To pick the right CALL target we cross-reference:
// any function whose CALL set is a *subset* of multiple Vtable entries'
// inner CALLs is more likely to be the shared accessor.
//
// Concrete strategy: walk the AttachCurrentThread thunk AND the
// GetEnv thunk; intersect their early CALL sets. JavaThread::current
// is in BOTH (used to find `Thread*` for the requested op).
static uint64_t resolve_javathread_current() {
    uint64_t attach = javavm_vtable_slot(32);   // AttachCurrentThread
    uint64_t getenv = javavm_vtable_slot(48);   // GetEnv
    if (!attach || !getenv) return 0;
    auto a = xref_scan(attach, 64);
    auto g = xref_scan(getenv, 64);
    // First few CALLs only — JavaThread::current is always near the top.
    size_t alim = a.calls.size() < 4 ? a.calls.size() : 4;
    size_t glim = g.calls.size() < 4 ? g.calls.size() : 4;
    for (size_t i = 0; i < alim; ++i) {
        if (!in_jvm(a.calls[i])) continue;
        for (size_t j = 0; j < glim; ++j) {
            if (a.calls[i] == g.calls[j]) return a.calls[i];
        }
    }
    return 0;
}

// attach_current_thread — internal helper called from
// AttachCurrentThread thunk in JavaVM vtable. Strategy: inside that
// thunk we look for a CALL target that is itself substantial (does
// real work, not a trivial wrapper). Heuristic: must contain >=4
// internal CALLs and at least one RIP-relative load (locks/state).
static uint64_t resolve_attach_current_thread() {
    uint64_t thunk = javavm_vtable_slot(32);
    if (!thunk) return 0;
    auto sc = xref_scan(thunk, 64);
    for (uint64_t t : sc.calls) {
        if (!in_jvm(t)) continue;
        auto inner = xref_scan(t, 64);
        if (inner.calls.size() >= 4 && !inner.rip_refs.empty())
            return t;
    }
    return 0;
}

// JNIHandles::make_local — every JNIEnv method that returns a reference
// calls make_local. Two overloads in HotSpot:
//   1-arg: make_local(oop)         — calls JavaThread::current() inside
//   2-arg: make_local(JavaThread*, oop[, AllocFailType]) — direct, takes thread
// We need the 2-arg form (we have JavaThread* from bootstrap). Its
// prologue distinguishes by the first instructions:
//   2-arg: `48 85 d2` (test rdx, rdx)  — checks the oop param in rdx
//   1-arg: typical save-regs + sub rsp prologue
//
// Walk JVM_NewArray (which calls 2-arg make_local internally), gather
// candidate small wrappers, then validate by prologue bytes.
static uint64_t resolve_jnihandles_make_local() {
    // BFS depth-2 from a set of exported anchors. Older JDKs (e.g. 11)
    // don't call make_local DIRECTLY from JVM_NewArray etc.; they go
    // through one helper hop. We accept the same `48 85 d2` (test rdx, rdx)
    // prologue regardless of distance.
    static const char* anchors[] = {
        "JVM_NewArray", "JVM_Clone", "JVM_GetClassConstantPool",
        "JVM_GetEnclosingMethodInfo", "JVM_DefineClass",
    };
    auto match_prologue = [](uint64_t va) -> bool {
        uint8_t pro[3] = {};
        if (!seh_read_prologue3(va, pro)) return false;
        return pro[0] == 0x48 && pro[1] == 0x85 && pro[2] == 0xD2;
    };

    for (const char* name : anchors) {
        uint64_t fn = exp_addr(name);
        if (!fn) continue;
        auto sc = xref_scan(fn, 256);
        // Depth-1 first.
        for (size_t i = sc.calls.size(); i-- > 0; ) {
            uint64_t t = sc.calls[i];
            if (!in_jvm(t)) continue;
            if (match_prologue(t)) return t;
        }
        // Depth-2: walk inside each callee.
        for (size_t i = sc.calls.size(); i-- > 0; ) {
            uint64_t t = sc.calls[i];
            if (!in_jvm(t)) continue;
            auto sc2 = xref_scan(t, 256);
            for (size_t j = sc2.calls.size(); j-- > 0; ) {
                uint64_t u = sc2.calls[j];
                if (!in_jvm(u)) continue;
                if (match_prologue(u)) return u;
            }
        }
    }

    // Final fallback: byte-pattern scan of jvm.dll's executable section
    // for the make_local 1-arg signature `48 85 d2 75 03 33 c0 c3` at a
    // 16-byte aligned address. JDK 11 release uses this exact 8-byte
    // body; the function isn't reached from any of our depth-2 anchors,
    // but it's bit-identical to the JDK 17 form.
    static const uint8_t needle[] = {
        0x48, 0x85, 0xD2, 0x75, 0x03, 0x33, 0xC0, 0xC3
    };
    JvmRange r = jvm_range();
    if (!r.base) return 0;
    auto* base = reinterpret_cast<const uint8_t*>(r.base);
    // Walk PE sections to find executable ranges. Only scan executable
    // memory so we don't false-match data sections.
    HMODULE jvm = GetModuleHandleA("jvm.dll");
    if (!jvm) return 0;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(const_cast<IMAGE_NT_HEADERS*>(nt));
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (sec->Misc.VirtualSize < sizeof(needle)) continue;
        const uint8_t* p   = base + sec->VirtualAddress;
        const uint8_t* end = p + sec->Misc.VirtualSize - sizeof(needle);
        // Step at 16-byte alignment to enforce function-start matches.
        // Round up start to 16-byte boundary.
        uintptr_t start_va = reinterpret_cast<uintptr_t>(p);
        uintptr_t aligned  = (start_va + 15) & ~uintptr_t(15);
        for (const uint8_t* q = reinterpret_cast<const uint8_t*>(aligned);
             q <= end; q += 16) {
            if (std::memcmp(q, needle, sizeof(needle)) == 0)
                return reinterpret_cast<uint64_t>(q);
        }
    }
    return 0;
}

// JavaCalls::call — invoked from JVM_InvokeMethod after argument setup.
// Walking shows TWO heavy unique callees in JVM_InvokeMethod:
//   - call_helper  (very deep, many inner calls)
//   - JavaCalls::call (medium, calls call_helper itself)
// We want the WRAPPER (JavaCalls::call), not the helper. Distinguishing
// signal: JavaCalls::call's body itself ends in a CALL to ANOTHER
// heavy function (= call_helper). call_helper's body has more inner
// calls but doesn't terminate in another heavy CALL.
//
// Strategy: collect heavy unique candidates (>=6 inner calls,
// appearing once in JVM_InvokeMethod). If multiple, pick the one
// whose own body contains a heavy callee (call_helper). That's the
// public JavaCalls::call.
static uint64_t resolve_javacalls_call() {
    uint64_t fn = exp_addr("JVM_InvokeMethod");
    if (!fn) return 0;
    auto sc = xref_scan(fn, 1024);

    // Count appearances; collect unique heavy candidates.
    struct Cand { uint64_t va; size_t inner_calls; };
    std::vector<Cand> cands;
    for (size_t i = 3; i < sc.calls.size(); ++i) {
        uint64_t t = sc.calls[i];
        if (!in_jvm(t)) continue;
        // Skip duplicates (boilerplate helpers appear multiple times).
        size_t cnt = 0;
        for (uint64_t s : sc.calls) if (s == t) ++cnt;
        if (cnt > 1) continue;
        auto inner = xref_scan(t, 256);
        if (inner.calls.size() >= 6) {
            cands.push_back({t, inner.calls.size()});
        }
    }
    if (cands.empty()) return 0;
    if (cands.size() == 1) return cands[0].va;

    // Multiple candidates: pick the SMALLER one (likely JavaCalls::call,
    // which delegates to the larger call_helper). Validate by checking
    // its body contains a CALL to ANOTHER candidate.
    for (size_t i = 0; i < cands.size(); ++i) {
        auto inner = xref_scan(cands[i].va, 256);
        for (uint64_t c : inner.calls) {
            for (size_t j = 0; j < cands.size(); ++j) {
                if (i != j && c == cands[j].va) {
                    // cands[i] calls cands[j]. cands[i] is the wrapper.
                    return cands[i].va;
                }
            }
        }
    }
    // Fallback: smallest by inner-call count.
    size_t pick = 0;
    for (size_t i = 1; i < cands.size(); ++i) {
        if (cands[i].inner_calls < cands[pick].inner_calls) pick = i;
    }
    return cands[pick].va;
}

// InstanceKlass::initialize — drives class init. Reached from
// JVM_FindClassFromCaller (after lookup) AND JVM_DefineClass (when the
// class needs init). Heuristic: walk JVM_FindClassFromCaller, take the
// LAST in-jvm CALL whose callee triggers JavaCalls::call somewhere in
// its body (initialize ultimately invokes the <clinit> via JavaCalls).
static uint64_t resolve_instanceklass_initialize() {
    uint64_t jcc = resolve_javacalls_call();
    uint64_t fn = exp_addr("JVM_FindClassFromCaller");
    if (!fn) fn = exp_addr("JVM_FindClassFromBootLoader");
    if (!fn) return 0;
    auto sc = xref_scan(fn, 256);
    if (!jcc) {
        // Without a valid JavaCalls::call we fall back to "last in-jvm
        // CALL" heuristic — initialize() is invoked late in the function.
        for (size_t i = sc.calls.size(); i-- > 0; ) {
            if (in_jvm(sc.calls[i])) return sc.calls[i];
        }
        return 0;
    }
    // Walk callees from late to early; pick the first whose body
    // transitively calls JavaCalls::call.
    for (size_t i = sc.calls.size(); i-- > 0; ) {
        uint64_t t = sc.calls[i];
        if (!in_jvm(t)) continue;
        auto inner = xref_scan(t, 256);
        for (uint64_t c : inner.calls) {
            if (c == jcc) return t;
        }
    }
    return 0;
}

} // anon

// Public entry. Returns 0 if no dynamic resolver matches `name` or the
// resolver itself fails. Called from agent_javacall.cpp::resolve_symbol
// after PDB and GetProcAddress fallbacks.
uint64_t dynamic_xref_resolve(const char* name) {
    if (!name) return 0;
    if (std::strcmp(name, "main_vm") == 0)
        return resolve_main_vm();
    if (std::strcmp(name, "JavaThread::current") == 0)
        return resolve_javathread_current();
    if (std::strcmp(name, "JavaCalls::call") == 0)
        return resolve_javacalls_call();
    if (std::strcmp(name, "JNIHandles::make_local") == 0)
        return resolve_jnihandles_make_local();
    if (std::strcmp(name, "attach_current_thread") == 0)
        return resolve_attach_current_thread();
    if (std::strcmp(name, "InstanceKlass::initialize") == 0)
        return resolve_instanceklass_initialize();
    // Synthetic name: structural offset extracted from JVM_NewArray
    // prologue. Lets JavaCalls bootstrap convert JNIEnv* → JavaThread*
    // arithmetically, no TLS lookup required.
    if (std::strcmp(name, "__jnienv_to_thread_offset") == 0)
        return (uint64_t)(int64_t)resolve_jnienv_to_thread_offset();
    return 0;
}

} // namespace marrow
