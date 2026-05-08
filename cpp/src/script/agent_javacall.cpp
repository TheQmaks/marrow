// agent_javacall.cpp — JavaCalls::call dispatch for the agent.
//
// Solves the c2i adapter problem (partially): the existing _invokeStatic in
// agent_invoke.cpp only works on JIT-compiled methods because it routes
// through _from_compiled_entry, and that VA points at the c2i adapter for
// interpreted methods, requiring a proper compiled-Java caller frame we
// cannot supply from raw native code.
//
// JavaCalls::call (in jvm.dll) handles both paths internally — it sets up
// thread state, builds the proper interpreter or compiled call, catches
// exceptions. It requires the calling thread to be a JavaThread, so we
// call attach_current_thread first if needed.
//
// All addresses are resolved via PDB at first use. Without a debug image
// alongside jvm.dll the binding returns "no_pdb" and callers fall back to
// the legacy _invokeStatic path.
//
// STATUS (JDK 21, jdk-21.0.10+7 with debug-image PDB):
//   - PDB symbol resolution         : working
//   - attach_current_thread         : working (JavaThread::current() != 0)
//   - JavaCalls::call zero-arg void : working
//   - JavaCalls::call zero-arg int  : working
//   - JavaCalls::call zero-arg long : working
//   - Multi-arg primitive (I/J/D/F/Z/B/S/C) : working
//   - Object/array args (L, [)      : working — wrap raw oop in jobject
//                                      via JNIHandles::make_local (2-arg
//                                      overload, picked by prologue
//                                      pattern test rdx,rdx).
//   - Instance methods              : working — push receiver via
//                                      set_receiver-equivalent path:
//                                      shift _value/_value_state back
//                                      one slot, mark slot 0 as
//                                      value_state_handle, store the
//                                      JNIHandles slot pointer (which
//                                      itself points at the oop), set
//                                      _start_at_zero=true, _size=1.
//
// REQUIREMENTS for the call to succeed:
//   1. Method's class must be FULLY LINKED (Method::_i2i_entry != 0). If
//      the class has only been loaded (e.g. via class literal, reflection
//      load) but not initialized, link_method has not run. Trigger init
//      by either calling any method of the class, accessing a static
//      non-constant field, or Class.forName(name, true, loader).
//   2. result->_type must be pre-populated with the JVM signature return
//      letter (V/I/J/Z/...) — call_helper invokes runtime_type_from(result)
//      which switches on result->get_type(); a zeroed buffer crashes there.
//   3. methodHandle must be allocated as 32 bytes minimum (NOT just 8) —
//      its copy ctor reads [+8] (a Thread/HandleArea slot); the byte at
//      [+8] must be 0 to take the "lookup current thread" fast path.
//   4. JavaCallArguments has _alternative_target at offset 0x78 (JVMCI
//      builds); zero it explicitly along with the rest of the struct.
//
// JDK-VERSION HARDCODE: layouts of JavaValue / JavaCallArguments are not
// in vmStructs and vary across HotSpot versions. We use the JDK 21 layout
// here; other versions need their own probe pass.

#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "walker.hpp"
#include "method_walker.hpp"
#include "oop_reader.hpp"
#include "duktape.h"

namespace marrow {
    extern OopDecoder* g_dec;
    extern void agent_log(const char* fmt, ...);
}

// SEH-protected helpers used by js_invokeJNI. Kept here so the caller
// can use them without holding any C++ destructors in scope.
static uint64_t seh_deref_oop_handle(uint64_t slot) {
    __try { return marrow::g_dec->deref_oop_handle(slot); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
static void* seh_jni_new_local(void* fn_va, void* env, void* obj) {
    typedef void* (*Fn)(void*, void*);
    auto fn = reinterpret_cast<Fn>(fn_va);
    __try { return fn(env, obj); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
// Wrap a raw HotSpot oop into a jobject (JNIHandle slot pointer) by
// calling the internal JNIHandles::make_local(thread, oop). Used for
// object args + receiver in _invokeJNI. SEH-isolated so the caller
// can hold C++ destructible objects.
static void* seh_make_local(void* fn_va, void* thread, void* oop) {
    typedef void* (*Fn)(void*, void*);
    auto fn = reinterpret_cast<Fn>(fn_va);
    __try { return fn(thread, oop); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
// Cached offset of JavaThread._thread_state. Cached once because MSVC bans
// std::string temporaries (used for vmStructs lookup) in functions that
// contain __try blocks.
__declspec(noinline)
static size_t lookup_thread_state_offset(marrow::VMMeta* vm) {
    static size_t cached = (size_t)-1;
    if (cached != (size_t)-1) return cached;
    cached = 0;
    if (!vm) return 0;
    auto* jt = vm->type("JavaThread");
    if (jt && jt->has_field("_thread_state"))
        cached = jt->field("_thread_state")->offset;
    return cached;
}

// Read+swap thread state field. Returns previous value or -1 on AV.
static int32_t seh_swap_thread_state(void* thread, size_t off, int32_t newv) {
    auto* p = reinterpret_cast<int32_t*>(
        reinterpret_cast<char*>(thread) + off);
    __try { int32_t prev = *p; *p = newv; return prev; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}
static void seh_set_thread_state(void* thread, size_t off, int32_t v) {
    auto* p = reinterpret_cast<int32_t*>(
        reinterpret_cast<char*>(thread) + off);
    __try { *p = v; } __except (EXCEPTION_EXECUTE_HANDLER) {}
}
typedef void (*JcCallFn4)(void*, void*, void*, void*);
static bool seh_jc_call(void* fn_va, void* result, void* mh, void* args, void* thread) {
    auto fn = reinterpret_cast<JcCallFn4>(fn_va);
    __try { fn(result, mh, args, thread); return false; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return true; }
}
static void** seh_read_vtable(void* env) {
    __try { return *reinterpret_cast<void***>(env); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
static void* seh_jni_get_static_method(void* fn_va, void* env, void* clazz,
                                        const char* name, const char* sig) {
    typedef void* (*Fn)(void*, void*, const char*, const char*);
    auto fn = reinterpret_cast<Fn>(fn_va);
    __try { return fn(env, clazz, name, sig); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
struct JniCallResult {
    bool      threw = false;
    int32_t   i_val = 0;
    int64_t   l_val = 0;
    void*     o_val = nullptr;
};
static JniCallResult seh_jni_call(void* fn_va, char ret_c, void* env,
                                   void* clazz, void* mid, const void* args) {
    JniCallResult out;
    __try {
        switch (ret_c) {
            case 'V': {
                typedef void (*Fn)(void*, void*, void*, const void*);
                reinterpret_cast<Fn>(fn_va)(env, clazz, mid, args);
                break;
            }
            case 'I': case 'B': case 'S': case 'C':
            case 'Z': {
                typedef int32_t (*Fn)(void*, void*, void*, const void*);
                out.i_val = reinterpret_cast<Fn>(fn_va)(env, clazz, mid, args);
                break;
            }
            case 'J': {
                typedef int64_t (*Fn)(void*, void*, void*, const void*);
                out.l_val = reinterpret_cast<Fn>(fn_va)(env, clazz, mid, args);
                break;
            }
            case 'L': case '[': {
                typedef void* (*Fn)(void*, void*, void*, const void*);
                out.o_val = reinterpret_cast<Fn>(fn_va)(env, clazz, mid, args);
                break;
            }
            default:
                out.threw = true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { out.threw = true; }
    return out;
}

#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

// JNI return codes — pulled in by value to avoid <jni.h> dependency.
#ifndef JNI_OK
#define JNI_OK   0
#endif
#ifndef JNI_ERR
#define JNI_ERR (-1)
#endif

namespace marrow {
namespace {

// Forward decls — implementations live further down. js_invokeJC uses
// jc_pending_exception_via_jni at its main path; without forward-decl
// C++ wouldn't see it.
static bool jc_check_pending_exception(uint64_t pe_addr);
static bool jc_pending_exception_via_jni();

// ---------------------------------------------------------------------------
// Symbol cache. Resolved once via DbgHelp from jvm.dll on first invokeJC().
// ---------------------------------------------------------------------------
struct Symbols {
    bool      ready{false};
    // bootstrap_failed: set when resolve_all couldn't establish the
    // fundamental attach + JNIEnv-derivation path (e.g., main_vm not
    // findable, attach call SEH'd). Acts as a do-not-retry marker.
    // Should stay false on supported JDKs; if true, all JNI/JC paths
    // will refuse to run.
    bool      bootstrap_failed{false};
    void*     attach_current_thread{nullptr};
    void*     javathread_current{nullptr};
    void*     javacalls_call{nullptr};            // JavaCalls::call(JavaValue*, methodHandle, JavaCallArguments*, Thread*)
    void*     javacallargs_ctor{nullptr};         // JavaCallArguments::JavaCallArguments()
    void*     jnihandles_make_local{nullptr};     // JNIHandles::make_local(oop) -> jobject
    uint64_t  main_vm_addr{0};                    // address of the global JavaVM
    int       bootstrap_step{0};                  // diagnostic: how far try_xref_bootstrap got
    int       bootstrap_attach_rc{0};             // last attach return code
    std::mutex mu;
};
static Symbols g_sym;

}  // close anonymous namespace so resolve_symbol gets external linkage
   // and can be called from agent_pattern_registry.cpp.

// init_dbghelp / g_dbg_ok kept as no-op stubs for callers that haven't
// been migrated yet. v1.0.2 removed the PDB resolution path entirely
// — it required dbghelp.dll + a .pdb sidecar file and went through
// HotSpot's symbol table, which is one level above the project's
// "vmStructs + memory walking" surface. Symbol resolution now goes
// through PE export table (GetProcAddress on jvm.dll) for exported
// names, then dynamic_xref_resolve for internal HotSpot functions
// addressable via structural xref from exports, then user-registered
// byte patterns as a manual override.
void init_dbghelp() {
    /* no-op since v1.0.2 — PDB tier removed */
}

uint64_t resolve_symbol(const char* name) {
    // Primary: PE export table on jvm.dll. Catches every exported
    // symbol (JNI invocation API, JVM_GC, JVM_DefineClass when present,
    // etc.) without any debug info. Mangling-free names only.
    if (HMODULE jvm = GetModuleHandleA("jvm.dll")) {
        if (auto p = GetProcAddress(jvm, name))
            return reinterpret_cast<uint64_t>(p);
    }
    // Fallback A: dynamic xref resolver — walks exported functions and
    // pulls internal targets out of CALL/RIP-rel sites. Works without
    // any debug info. See agent_xref_resolvers.cpp.
    if (uint64_t v = dynamic_xref_resolve(name)) return v;
    // Fallback B: user-registered byte patterns. Last-resort; covers
    // internal symbols that xref heuristics can't reach yet.
    return pattern_registry_resolve(name);
}

namespace {  // reopen anonymous namespace for the rest of the file

// --- PDB-less bootstrap helpers ---------------------------------------
// JavaThread::current is per-thread, so a const shim only works on the
// thread that called AttachCurrentThread. The agent has multiple threads
// (worker_loop, IPC handler, etc.) — each must derive its own thread*.
// Solution: a real C function that calls AttachCurrentThread (idempotent
// per JNI spec) on every invocation, derives JavaThread* arithmetically.
static std::atomic<uint64_t> g_xref_attach_thunk{0};
static std::atomic<int32_t>  g_xref_env_offset{0};
static std::atomic<uint64_t> g_xref_main_vm_addr{0};

static thread_local void*    s_cached_thread = nullptr;

extern "C" __declspec(dllexport) void* xref_javathread_current() {
    if (s_cached_thread) return s_cached_thread;   // hot path
    uint64_t thunk_va = g_xref_attach_thunk.load(std::memory_order_relaxed);
    uint64_t main_vm  = g_xref_main_vm_addr.load(std::memory_order_relaxed);
    int32_t  off      = g_xref_env_offset.load(std::memory_order_relaxed);
    if (!thunk_va || !main_vm || off == 0) return nullptr;
    typedef int (*Att)(void*, void**, void*);
    auto attach = reinterpret_cast<Att>(thunk_va);
    void* env = nullptr;
    int rc = JNI_ERR;
    __try {
        rc = attach(reinterpret_cast<void*>(main_vm), &env, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
    if (rc != JNI_OK || !env) return nullptr;
    s_cached_thread = reinterpret_cast<char*>(env) + (intptr_t)off;
    return s_cached_thread;
}

// Build a 4-arg → 3-arg trampoline. JavaVM->AttachCurrentThread thunk
// takes (JavaVM*, void**, void*) but ensure_attached() calls a function
// of signature (vm, &env, args, daemon). Drop r9 (daemon) and tail-jmp
// to the thunk.
static uint64_t build_attach_wrapper_shim(uint64_t thunk_va) {
    void* page = VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!page) return 0;
    auto* p = static_cast<uint8_t*>(page);
    // FF 25 00 00 00 00          jmp [rip+0]
    // <thunk_va:8>
    p[0] = 0xFF; p[1] = 0x25;
    p[2] = 0x00; p[3] = 0x00; p[4] = 0x00; p[5] = 0x00;
    std::memcpy(p + 6, &thunk_va, 8);
    FlushInstructionCache(GetCurrentProcess(), page, 32);
    return reinterpret_cast<uint64_t>(page);
}

// PDB-less bootstrap. Resolves every required symbol via xref + GetProcAddress
// and ATTACHES the agent thread to the JVM via the JavaVM->AttachCurrentThread
// thunk (idempotent — JNI_OK if already attached). After attach we know the
// agent's JavaThread* and bake a const shim for JavaThread::current.
//
// Returns true if all required symbols were resolved AND attach succeeded.
// On Win64 all calling conventions (cdecl/stdcall/JNICALL) collapse to
// the same Microsoft x64 ABI — drop the JNICALL annotation to keep this
// TU independent of jni.h.
typedef int (*JniAttachFn)(void* vm, void** penv, void* args);
static bool try_xref_bootstrap() {
    g_sym.bootstrap_step = 1;
    g_sym.main_vm_addr          = pattern_registry_resolve("main_vm");
    if (!g_sym.main_vm_addr)
        g_sym.main_vm_addr      = dynamic_xref_resolve("main_vm");
    // STAGE 1 (mandatory): main_vm + env_offset. These give us attach +
    // current JNIEnv -- the foundation for the JS-side resolvers.
    int32_t env_offset          = (int32_t)dynamic_xref_resolve("__jnienv_to_thread_offset");
    if (!g_sym.main_vm_addr || env_offset == 0)
        return false;

    // STAGE 2 (best-effort): JC::call + make_local. The JVM_InvokeMethod
    // heuristic for JC::call doesn't apply on JDK 8/11/25; the JNIHandles
    // prologue match for make_local fails on the same matrix. JS-side
    // recovery (Java.resolveJavaCallsCall + JNI vtable lookups) handles
    // both; leaving them null here is acceptable.
    g_sym.javacalls_call        = (void*)dynamic_xref_resolve("JavaCalls::call");
    g_sym.jnihandles_make_local = (void*)dynamic_xref_resolve("JNIHandles::make_local");

    // main_vm IS a `struct JavaVM_` instance (not a pointer to one).
    // Layout: { JNIInvokeInterface_* functions; }. So *main_vm == vtable.
    // The vtable's slot at +32 is AttachCurrentThread.
    g_sym.bootstrap_step = 2;
    uint64_t vtable = 0;
    __try {
        vtable = *reinterpret_cast<uint64_t*>(g_sym.main_vm_addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!vtable) return false;

    g_sym.bootstrap_step = 3;
    uint64_t attach_thunk = 0;
    __try {
        attach_thunk = *reinterpret_cast<uint64_t*>(vtable + 32);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    if (!attach_thunk) return false;

    g_sym.bootstrap_step = 4;
    auto attach_3arg = reinterpret_cast<JniAttachFn>(attach_thunk);
    void* env_out = nullptr;
    int rc = JNI_ERR;
    // The 3-arg JNI invocation API expects (JavaVM*, &env, attachArgs).
    // The first arg is the address OF main_vm (not its dereffed value).
    __try {
        rc = attach_3arg(reinterpret_cast<void*>(g_sym.main_vm_addr),
                          &env_out, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_sym.bootstrap_attach_rc = -999;
        return false;
    }
    g_sym.bootstrap_attach_rc = rc;
    if (rc != JNI_OK || !env_out) return false;

    g_sym.bootstrap_step = 6;
    // Cache state for the per-thread JavaThread::current shim. Each
    // thread that calls into JavaCalls will hit this and attach itself.
    g_xref_attach_thunk.store(attach_thunk,   std::memory_order_release);
    g_xref_main_vm_addr.store(g_sym.main_vm_addr, std::memory_order_release);
    g_xref_env_offset.store(env_offset,        std::memory_order_release);

    uint64_t att_shim = build_attach_wrapper_shim(attach_thunk);
    if (!att_shim) return false;

    g_sym.bootstrap_step = 7;
    g_sym.javathread_current    = reinterpret_cast<void*>(&xref_javathread_current);
    g_sym.attach_current_thread = reinterpret_cast<void*>(att_shim);
    g_sym.javacallargs_ctor     = reinterpret_cast<void*>(att_shim);  // sentinel
    return true;
}

// Resolve the full symbol set. Idempotent. Returns true if all required
// symbols were found.
//
// Path order:
//   1) DbgHelp/PDB lookup for each symbol (best results when debug image
//      is installed alongside jvm.dll).
//   2) For anything still missing: xref-based bootstrap, which also
//      ATTACHES the agent thread and bakes a const shim for
//      JavaThread::current. Works fully without PDB.
//   3) If the required set is still incomplete, mark bootstrap_failed and
//      let callers gracefully skip.
bool resolve_all() {
    std::lock_guard<std::mutex> lk(g_sym.mu);
    if (g_sym.ready) return true;
    if (g_sym.bootstrap_failed) return false;

    // Step 1: PE-export resolution. Catches symbols that jvm.dll
    // exports unconditionally (main_vm via xref, JNI invocation API,
    // a handful of debug-friendly entry points). Internal HotSpot
    // symbols like `JavaCalls::call` are NOT exported and require
    // step 2 (xref-driven structural matching).
    g_sym.attach_current_thread = (void*)resolve_symbol("attach_current_thread");
    g_sym.javathread_current    = (void*)resolve_symbol("JavaThread::current");
    g_sym.javacalls_call        = (void*)resolve_symbol("JavaCalls::call");
    g_sym.javacallargs_ctor     = (void*)resolve_symbol("JavaCallArguments::JavaCallArguments");
    g_sym.main_vm_addr          = resolve_symbol("main_vm");
    g_sym.jnihandles_make_local = (void*)resolve_symbol("JNIHandles::make_local");

    // Step 2: xref-based bootstrap for anything still missing. Performs
    // an attach call inside, so it both resolves symbols AND prepares the
    // agent thread for JavaCalls. Skip when the PDB path already filled
    // everything (no work to do).
    // env_offset is needed to derive JNIEnv* on the agent thread, which the
    // JS-side resolver uses for JNI vtable triangulation. PDB-resolved
    // builds (rare) won't have env_offset set, so explicitly include it.
    bool need_bootstrap =
        !g_sym.attach_current_thread || !g_sym.javathread_current ||
        !g_sym.javacallargs_ctor ||
        !g_sym.main_vm_addr || !g_sym.jnihandles_make_local ||
        g_xref_env_offset.load(std::memory_order_relaxed) == 0;
    if (need_bootstrap) {
        try_xref_bootstrap();
    }

    // JavaCalls::call may stay null on JDKs where the JVM_InvokeMethod-based
    // heuristic doesn't apply (8/11/25). The JS auto-bootstrap recovers it
    // via the JNI vtable triangulation when needed (Java.resolveJavaCallsCall).
    // We mark resolve_all as ready as long as the attach/JNIEnv path works.
    if (!g_sym.attach_current_thread || !g_sym.javathread_current ||
        !g_sym.javacallargs_ctor || !g_sym.main_vm_addr) {
        g_sym.bootstrap_failed = true;
        return false;
    }
    g_sym.ready = true;
    return true;
}

// ---------------------------------------------------------------------------
// Per-thread attach. Once attached, JavaThread::current() returns non-null
// for the agent's thread, so JavaCalls::call works without crashing.
// ---------------------------------------------------------------------------
typedef int  (*AttachFn)(void* vm, void** penv, void* args, int daemon);
typedef void* (*JtCurFn)();

bool ensure_attached() {
    if (!resolve_all()) return false;
    auto jt_cur = reinterpret_cast<JtCurFn>(g_sym.javathread_current);
    if (jt_cur()) return true;  // already attached

    void* penv_out = nullptr;
    auto attach = reinterpret_cast<AttachFn>(g_sym.attach_current_thread);
    int rc = JNI_ERR;
    __try {
        rc = attach(reinterpret_cast<void*>(g_sym.main_vm_addr),
                    &penv_out, nullptr, /*daemon=*/1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return rc == JNI_OK && jt_cur() != nullptr;
}

// ---------------------------------------------------------------------------
// JavaCalls::call(JavaValue* result, methodHandle method,
//                 JavaCallArguments* args, Thread* THREAD)
//
// methodHandle has a non-trivial destructor (PDB shows
// "methodHandle::~methodHandle"), so per Win x64 ABI it's passed BY
// POINTER, not by value. We allocate an 8-byte methodHandle on stack and
// pass its address.
//
// JavaCallArguments::JavaCallArguments(int max_size) — single PDB entry
// is for the size-taking overload. We must pass max_size in rdx. Passing
// 0 takes the default branch which sets _max_size = 8.
// ---------------------------------------------------------------------------
typedef void (*JcCallFn)(void* result, void* method_handle_ptr,
                          void* args, void* thread);
typedef void (*JcaCtorFn)(void* self, int max_size);

// Map a JVM signature return-type letter to a BasicType enum value.
// JVM 21 BasicType: T_BOOLEAN=4, T_CHAR=5, T_FLOAT=6, T_DOUBLE=7, T_BYTE=8,
// T_SHORT=9, T_INT=10, T_LONG=11, T_OBJECT=12, T_ARRAY=13, T_VOID=14.
static int basic_type_from_letter(char c) {
    switch (c) {
        case 'Z': return 4;   // boolean
        case 'C': return 5;   // char
        case 'F': return 6;   // float
        case 'D': return 7;   // double
        case 'B': return 8;   // byte
        case 'S': return 9;   // short
        case 'I': return 10;  // int
        case 'J': return 11;  // long
        case 'L': return 12;  // object
        case '[': return 13;  // array
        case 'V': return 14;  // void
        default:  return 0;
    }
}

// JavaCallArguments::value_state_primitive = 0 (per OpenJDK enum order).
constexpr uint8_t kStatePrimitive = 0;
constexpr uint8_t kStateHandle    = 2;   // for receiver of instance calls
constexpr uint8_t kStateJobject   = 3;   // for ordinary object args

// PDB shows two overloads of JNIHandles::make_local. We unconditionally
// route to the 2-arg form so we can pass our resolved JavaThread*; the
// 1-arg variant ultimately calls JavaThread::current() anyway.
typedef void* (*JniMakeLocalFn)(void* thread, void* oop);

// Push a primitive arg into JavaCallArguments. Mirrors HotSpot's inlined
// push_int / push_long / push_double / push_float helpers, which on x86_64
// use JNITypes:
//   put_int   : *(jint*) (to + pos++)     = from
//   put_long  : *(jlong*)(to + 1 + pos)   = from;   pos += 2
//   put_double: *(jdouble*)(to + 1 + pos) = from;   pos += 2
//
// Long/double quirk: stored at slot pos+1 (high-word position) — slot pos
// is an implicit pad. Both state-buffer entries are still marked primitive.
static void push_primitive_arg(uint8_t* args_buf, char type_letter,
                                uint64_t raw_value) {
    intptr_t* values  = *reinterpret_cast<intptr_t**>(args_buf + 0x58);
    uint8_t*  states  = *reinterpret_cast<uint8_t**>(args_buf + 0x60);
    int&      size    = *reinterpret_cast<int*>(args_buf + 0x68);

    bool is_double_word = (type_letter == 'J' || type_letter == 'D');

    states[size] = kStatePrimitive;
    if (is_double_word) {
        states[size + 1] = kStatePrimitive;
        // Long/double live at slot[size+1]; slot[size] is implicit padding.
        values[size + 1] = static_cast<intptr_t>(raw_value);
        size += 2;
    } else {
        values[size] = static_cast<intptr_t>(raw_value);
        size += 1;
    }
}

// Push an object reference. Wraps the raw oop into a jobject via
// JNIHandles::make_local (resolved from PDB), then stores the jobject
// with state value_state_jobject so the stub will resolve it correctly.
//
// Returns false if make_local isn't available or the wrap returns null —
// caller should signal "no_jnihandles" so the caller can fall back.
// NULL oop is allowed: pushed as state_jobject value=0.
static bool push_object_arg(uint8_t* args_buf, void* thread, uint64_t raw_oop) {
    intptr_t* values  = *reinterpret_cast<intptr_t**>(args_buf + 0x58);
    uint8_t*  states  = *reinterpret_cast<uint8_t**>(args_buf + 0x60);
    int&      size    = *reinterpret_cast<int*>(args_buf + 0x68);

    void* jobj = nullptr;
    if (raw_oop != 0) {
        if (!g_sym.jnihandles_make_local) return false;
        auto make_local = reinterpret_cast<JniMakeLocalFn>(
            g_sym.jnihandles_make_local);
        __try {
            jobj = make_local(thread, reinterpret_cast<void*>(raw_oop));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
        if (!jobj) return false;
    }
    states[size] = kStateJobject;
    values[size] = reinterpret_cast<intptr_t>(jobj);
    size += 1;
    return true;
}

duk_ret_t js_invokeJC(duk_context* ctx) {
    uint32_t lo = (uint32_t)duk_to_uint32(ctx, 0);
    uint32_t hi = (uint32_t)duk_to_uint32(ctx, 1);
    uint64_t method_ptr = ((uint64_t)hi << 32) | lo;
    // Third arg: return-type letter from JVM signature (e.g. 'I', 'J', 'V').
    // call_helper invokes runtime_type_from(result) which switches on
    // result->get_type(); without a valid pre-populated BasicType the
    // switch hits default → ShouldNotReachHere. The JavaValue layout has
    // _type as a u1 at offset 0.
    const char* rt_str = duk_get_string_default(ctx, 2, "V");
    int basic_type = basic_type_from_letter(rt_str[0]);
    if (basic_type == 0) basic_type = 14;  // default to void

    // Fourth arg: optional string of primitive-arg type letters in order
    // ("IJD" = int, long, double). Empty/missing → no args.
    const char* arg_types = duk_get_string_default(ctx, 3, "");
    // Fifth arg: optional array of arg values. Each element is read as a
    // hex string for J/D/L and as a number for I/F/Z/B/S/C. Length must
    // match arg_types. Missing or wrong length → call with 0 args.
    duk_idx_t arg_arr_idx = -1;
    if (duk_get_top(ctx) >= 5 && duk_is_array(ctx, 4)) arg_arr_idx = 4;
    // Sixth arg: optional receiver oop hex string. When provided, the
    // method is treated as an instance method and the receiver is pushed
    // first via the value_state_handle path (using a JNIHandles slot as
    // a stable Handle slot pointer).
    const char* recv_hex = duk_get_string_default(ctx, 5, "");
    // Seventh arg: methodHandle calling convention. JDK 12+ uses a
    // 16-byte methodHandle (Method* + Thread*) passed BY HIDDEN REFERENCE
    // (rdx = pointer to stack temp). JDK 8/11 use an 8-byte methodHandle
    // (Method* only) passed BY VALUE (rdx = Method*). Default = false
    // (16-byte by-ref) to keep existing JDK 17+ callers working.
    bool method_by_value = duk_get_boolean_default(ctx, 6, 0);

    if (!resolve_all())     { duk_push_string(ctx, "no_pdb");           return 1; }
    // Bail BEFORE ensure_attached when JC::call is unresolved -- attaching
    // the agent thread when we can't actually call into JavaCalls leaves
    // the IPC thread attached but unable to dispatch, which corrupts
    // subsequent allocations on JDK 11.
    if (!g_sym.javacalls_call) {
        duk_push_string(ctx, "no_jc");
        return 1;
    }
    if (!ensure_attached()) { duk_push_string(ctx, "attach_failed");    return 1; }

    auto jt_cur     = reinterpret_cast<JtCurFn>(g_sym.javathread_current);
    void* thread    = jt_cur();
    if (!thread) { duk_push_string(ctx, "no_jt"); return 1; }

    // Allocate buffers on stack — JavaValue ~16 bytes, JavaCallArguments
    // 0x80 bytes (default-size variant), methodHandle 32 bytes.
    // Disassembly of methodHandle::methodHandle (the copy ctor) shows
    // it reads [+0] (Method*) AND [+8] (Thread*/HandleArea — null-check
    // gated). With an 8-byte local of method_ptr alone, [+8] points at
    // adjacent stack data which may not be zero — passing such a stale
    // value into the call crashes for non-trivial return types. Thirty-
    // two bytes overshoots even a cautious modern methodHandle layout.
    alignas(8) uint8_t result_buf[64]    = {};
    alignas(8) uint8_t args_buf[256]     = {};
    alignas(8) uint8_t mh_buf[32]        = {};

    // _method at +0, _thread at +8. On JDK 17 release, _thread is read
    // unconditionally inside JC::call to anchor the Method* against
    // safepoints; leaving it null SEGVs deep in the call chain.
    std::memcpy(mh_buf, &method_ptr, sizeof(method_ptr));
    *reinterpret_cast<void**>(mh_buf + 8) = thread;
    // For JDK 8/11 (8-byte methodHandle by-value), pass the Method* itself
    // in rdx instead of the address of mh_buf.
    void* method_handle_storage = method_by_value
        ? reinterpret_cast<void*>((uintptr_t)method_ptr)
        : reinterpret_cast<void*>(mh_buf);

    // Manual JavaCallArguments init — derived from disassembly of the
    // size-taking constructor's default branch (max_size <= 8). Skipping
    // the ctor avoids any ambiguity over which overload PDB resolved to
    // and any side-effects in branches we don't take.
    //   [0x00 .. 0x47] _value_buffer[9]             (72 bytes)
    //   [0x48 .. 0x50] _value_state_buffer[9]       (9 bytes + padding)
    //   [0x58]          _value (intptr_t*)
    //   [0x60]          _value_state (u_char*)
    //   [0x68]          _size (int)         = 0
    //   [0x6c]          _max_size (int)     = 8
    //   [0x70]          _start_at_zero      = false
    //   [0x78]          _thread (set lazily by VM)
    *reinterpret_cast<intptr_t**>(args_buf + 0x58) =
        reinterpret_cast<intptr_t*>(args_buf + 8);
    *reinterpret_cast<uint8_t**>(args_buf + 0x60) =
        args_buf + 0x49;
    *reinterpret_cast<int*>(args_buf + 0x68) = 0;
    *reinterpret_cast<int*>(args_buf + 0x6c) = 8;

    // Receiver setup for instance methods. Mirrors set_receiver in
    // OpenJDK: shifts _value/_value_state pointers BACK to slot 0 (which
    // was reserved at +8/+0x49), writes the receiver's slot pointer, and
    // increments _size. The JNI handle returned by make_local is itself
    // an oop slot pointer (oop* in JNIHandleBlock), so it works as a
    // Handle directly via state_handle.
    bool has_receiver = recv_hex && recv_hex[0] != 0;
    if (has_receiver) {
        uint64_t recv_oop = std::strtoull(recv_hex, nullptr, 0);
        if (!g_sym.jnihandles_make_local) {
            duk_push_string(ctx, "no_jnihandles");
            return 1;
        }
        auto make_local = reinterpret_cast<JniMakeLocalFn>(
            g_sym.jnihandles_make_local);
        void* slot = nullptr;
        if (recv_oop) {
            __try {
                slot = make_local(thread,
                                   reinterpret_cast<void*>(recv_oop));
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                duk_push_string(ctx, "make_local_threw");
                return 1;
            }
        }
        // Shift buffer pointers backward by one slot (set_receiver does
        // _value-- and _value_state--, so pointers now address the
        // previously-implicit-pad slot 0).
        *reinterpret_cast<intptr_t**>(args_buf + 0x58) =
            reinterpret_cast<intptr_t*>(args_buf);
        *reinterpret_cast<uint8_t**>(args_buf + 0x60) =
            args_buf + 0x48;
        *reinterpret_cast<int*>(args_buf + 0x68)   = 1;     // _size
        *reinterpret_cast<bool*>(args_buf + 0x70)  = true;  // _start_at_zero
        // Write receiver into slot 0.
        intptr_t* values = *reinterpret_cast<intptr_t**>(args_buf + 0x58);
        uint8_t*  states = *reinterpret_cast<uint8_t**>(args_buf + 0x60);
        states[0] = kStateHandle;
        values[0] = reinterpret_cast<intptr_t>(slot);
    }

    // Push args from the (arg_types, arg_arr) inputs. Letter 'L' marks an
    // object reference (raw oop hex string); we wrap it in a jobject.
    if (arg_types[0] != 0 && arg_arr_idx >= 0) {
        size_t n_types = std::strlen(arg_types);
        size_t n_arr   = duk_get_length(ctx, arg_arr_idx);
        size_t n       = (n_types < n_arr) ? n_types : n_arr;
        for (size_t i = 0; i < n; ++i) {
            char letter = arg_types[i];
            duk_get_prop_index(ctx, arg_arr_idx, (duk_uarridx_t)i);
            uint64_t v = 0;
            if (letter == 'J' || letter == 'D') {
                if (duk_is_string(ctx, -1)) {
                    v = std::strtoull(duk_get_string(ctx, -1), nullptr, 0);
                } else if (duk_is_number(ctx, -1)) {
                    if (letter == 'D') {
                        double d = duk_get_number(ctx, -1);
                        std::memcpy(&v, &d, 8);
                    } else {
                        v = (uint64_t)(int64_t)duk_get_number(ctx, -1);
                    }
                }
                duk_pop(ctx);
                push_primitive_arg(args_buf, letter, v);
            } else if (letter == 'F') {
                float f = (float)duk_get_number_default(ctx, -1, 0.0);
                uint32_t bits = 0;
                std::memcpy(&bits, &f, 4);
                duk_pop(ctx);
                push_primitive_arg(args_buf, letter, bits);
            } else if (letter == 'L') {
                // Object reference. Expect hex string of the wide oop.
                uint64_t oop_va = 0;
                if (duk_is_string(ctx, -1)) {
                    oop_va = std::strtoull(duk_get_string(ctx, -1), nullptr, 0);
                }
                duk_pop(ctx);
                if (!push_object_arg(args_buf, thread, oop_va)) {
                    duk_push_string(ctx, "no_jnihandles");
                    return 1;
                }
            } else {
                // I/Z/B/S/C: 32-bit zero-extended. JS Number → int32.
                v = (uint64_t)(uint32_t)(int32_t)duk_get_number_default(
                    ctx, -1, 0.0);
                duk_pop(ctx);
                push_primitive_arg(args_buf, letter, v);
            }
        }
    }

    // Pre-populate result->_type so runtime_type_from() (called inside
    // call_helper) finds a valid BasicType in the switch.
    result_buf[0] = static_cast<uint8_t>(basic_type);

    if (!g_sym.javacalls_call) {
        // Resolver hasn't found JC::call (e.g. JDK 11 structural mismatch).
        // Calling NULL is unsafe -- on some HotSpot builds the AV bypasses
        // our SEH and tears down the JVM. Surface the unresolved state
        // explicitly so callers don't go further.
        duk_push_string(ctx, "no_jc");
        return 1;
    }
    auto call = reinterpret_cast<JcCallFn>(g_sym.javacalls_call);

    // Transition agent thread to _thread_in_vm (=6) before calling JC::call.
    // After AttachCurrentThread the thread is in _thread_in_native (=4); JC::call
    // and its callees may assert/hang on the wrong state. Restore _thread_in_native
    // afterward so subsequent JNI work continues to function. The _thread_state
    // offset comes from vmStructs (JavaThread._thread_state) which differs per JDK.
    int32_t orig_state = -1;
    size_t state_off = lookup_thread_state_offset(current_vm(ctx));
    if (state_off && thread)
        orig_state = seh_swap_thread_state(thread, state_off, 6 /*in_vm*/);

    bool threw = seh_jc_call(call, result_buf, method_handle_storage, args_buf, thread);

    if (state_off && thread && orig_state >= 0)
        seh_set_thread_state(thread, state_off, orig_state);

    if (threw) { duk_push_string(ctx, "java_exception"); return 1; }

    // Java exceptions (NumberFormatException etc.) survive seh_jc_call
    // without raising an SEH exception. JNI's ExceptionCheck on the
    // current JNIEnv detects them — same path js_invokeJNI uses. On
    // hit we surface "java_exception" so _unwrap turns it into a
    // JS-side throw.
    if (jc_pending_exception_via_jni()) {
        duk_push_string(ctx, "java_exception");
        return 1;
    }

    // Decode JavaValue. Layout (verified for JDK 21):
    //   [0..3]  = BasicType (int enum). T_VOID=0/14, T_INT=10, T_LONG=11, etc
    //   [8..15] = union { jint i; jlong l; jdouble d; ... }
    int32_t  bt = 0;
    uint64_t v  = 0;
    std::memcpy(&bt, result_buf,     sizeof(bt));
    std::memcpy(&v,  result_buf + 8, sizeof(v));

    char out[96];
    std::snprintf(out, sizeof(out), "{type:%d, value:0x%llx}",
                  bt, static_cast<unsigned long long>(v));
    duk_push_string(ctx, out);
    return 1;
}

// Marrow._defineClassNative(nameStr|null, bytesArray, loaderOopHex|null)
//   -> Class oop hex string (or null on failure).
//
// Resolves HotSpot's `JVM_DefineClass` dynamically: it's exported from
// jvm.dll, so `resolve_symbol` finds it via `GetProcAddress` without
// any PDB / DbgHelp dependency. The agent gets a JNIEnv* through the
// JNI Invocation API (`JavaVM->GetEnv` slot 6) — the Invocation API
// is the bootstrap contract for JVM embedders and is NOT the JNI
// Function API surface (FindClass / Call*Method) that v1.0.1's
// honesty pass flagged. Calling JVM_DefineClass directly bypasses
// JNI's vtable-dispatched DefineClass while still going through
// HotSpot's blessed class-loading path (parsing, verification,
// SystemDictionary registration), so subsequent Class.forName(name)
// finds the class on every JDK.
//
// Returns the wide oop of the resulting Class<?> mirror, or null on
// failure (parse error, name collision, OOM, symbol not exported).
typedef void* (*DefineClassFn)(void* env, const char* name, void* loader,
                                const int8_t* buf, int len, void* pd);
__declspec(noinline)
static void* call_make_local_seh(JniMakeLocalFn fn, void* thread, void* oop) {
    __try { return fn(thread, oop); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
__declspec(noinline)
static void* call_define_class_seh(DefineClassFn fn, void* env,
                                    const char* name, void* loader,
                                    const int8_t* buf, int len) {
    __try { return fn(env, name, loader, buf, len, nullptr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

duk_ret_t js_defineClassNative(duk_context* ctx) {
    const char* name = nullptr;
    if (duk_is_string(ctx, 0)) name = duk_get_string(ctx, 0);

    if (!duk_is_array(ctx, 1)) {
        duk_push_null(ctx);
        return 1;
    }
    duk_size_t n = duk_get_length(ctx, 1);
    std::vector<int8_t> buf(n);
    for (duk_size_t i = 0; i < n; ++i) {
        duk_get_prop_index(ctx, 1, (duk_uarridx_t)i);
        buf[i] = static_cast<int8_t>(duk_get_uint(ctx, -1));
        duk_pop(ctx);
    }

    const char* loader_hex = nullptr;
    if (duk_is_string(ctx, 2)) loader_hex = duk_get_string(ctx, 2);

    if (!ensure_attached()) { duk_push_null(ctx); return 1; }
    if (!resolve_all()) { duk_push_null(ctx); return 1; }

    // Get JNIEnv via JavaVM->functions->GetEnv. main_vm is a JavaVM_
    // (just a pointer to a JNIInvokeInterface_ table). Slot [6] holds
    // GetEnv(JavaVM*, void**, jint version). main_vm is xref-resolved
    // (PDB-less safe).
    uint64_t* main_vm_ptr = reinterpret_cast<uint64_t*>(g_sym.main_vm_addr);
    if (!main_vm_ptr) { duk_push_null(ctx); return 1; }
    uint64_t* fns = reinterpret_cast<uint64_t*>(*main_vm_ptr);
    typedef int (*GetEnvFn)(void* vm, void** penv, int version);
    auto get_env = reinterpret_cast<GetEnvFn>(fns[6]);
    void* env = nullptr;
    if (get_env(main_vm_ptr, &env, 0x00010008 /*JNI_VERSION_1_8*/) != 0 || !env) {
        duk_push_null(ctx);
        return 1;
    }

    // Wrap loader oop into a JNI local handle if provided.
    void* loader_jobject = nullptr;
    if (loader_hex) {
        uint64_t loader_oop = std::strtoull(loader_hex, nullptr, 0);
        if (loader_oop) {
            auto make_local = reinterpret_cast<JniMakeLocalFn>(
                g_sym.jnihandles_make_local);
            if (!make_local) { duk_push_null(ctx); return 1; }
            auto jt_cur = reinterpret_cast<JtCurFn>(g_sym.javathread_current);
            loader_jobject = call_make_local_seh(
                make_local, jt_cur(),
                reinterpret_cast<void*>(loader_oop));
            if (!loader_jobject) { duk_push_null(ctx); return 1; }
        }
    }

    // JVM_DefineClass via PE export resolution (no PDB, no DbgHelp).
    uint64_t jvm_define_va = resolve_symbol("JVM_DefineClass");
    if (!jvm_define_va) { duk_push_null(ctx); return 1; }
    auto define_fn = reinterpret_cast<DefineClassFn>(jvm_define_va);
    void* jclass_handle = call_define_class_seh(
        define_fn, env, name, loader_jobject, buf.data(), int(n));
    if (!jclass_handle) { duk_push_null(ctx); return 1; }

    // jclass is a JNI local handle — pointer to a slot containing the oop.
    // Dereference to get the wide oop.
    uint64_t class_oop = *reinterpret_cast<uint64_t*>(jclass_handle);
    if (!class_oop) { duk_push_null(ctx); return 1; }

    char out[32];
    std::snprintf(out, sizeof(out), "0x%llx", (unsigned long long)class_oop);
    duk_push_string(ctx, out);
    return 1;
}

// Marrow._initializeKlass(klassObj) -> bool
// Drives HotSpot's `InstanceKlass::initialize(this, JavaThread*)` to
// force link_class + <clinit>, populating Method::_i2i_entry on every
// method so subsequent JavaCalls dispatch can route through them.
// Used by Java.openClassFile after defineClass since defineClass
// does not link.
//
// `InstanceKlass::initialize` and `JavaThread::current` are NOT
// exported, but the dynamic xref resolver (agent_xref_resolvers.cpp)
// finds them by structural matching against exported caller sites
// — no PDB needed.
duk_ret_t js_initializeKlass(duk_context* ctx) {
    uint64_t klass = obj_addr(ctx, 0);
    if (!klass) { duk_push_false(ctx); return 1; }

    // Both symbols xref-resolved (no PDB) — see agent_xref_resolvers.cpp
    // for the structural matchers.
    uint64_t init_va  = resolve_symbol("InstanceKlass::initialize");
    uint64_t jtcur_va = resolve_symbol("JavaThread::current");
    if (!init_va || !jtcur_va) { duk_push_false(ctx); return 1; }

    auto jt_cur = reinterpret_cast<JtCurFn>(jtcur_va);
    typedef void (*InitFn)(void* this_klass, void* thread);
    auto init_fn = reinterpret_cast<InitFn>(init_va);

    // Make sure agent thread is attached as a JavaThread first.
    if (!ensure_attached()) { duk_push_false(ctx); return 1; }
    void* thread = jt_cur();
    if (!thread) { duk_push_false(ctx); return 1; }

    bool ok = false;
    __try {
        init_fn(reinterpret_cast<void*>(klass), thread);
        ok = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    duk_push_boolean(ctx, ok);
    return 1;
}

// Marrow._deoptimizeAll() -> int (count of methods cleared)
// Walks every loaded class, zero's `Method::_code` on each method so the
// next dispatch routes through the interpreter rather than a stale
// JIT-compiled nmethod. Frida's Java.deoptimizeEverything-equivalent —
// safe to call before installing a fresh hook so JIT-cached entries
// can't bypass the patched _i2i_entry.
//
// Briefly suspends all JavaThreads via ScopedSuspend so a thread mid-
// dispatch won't read a half-cleared field. Cost: O(loaded methods),
// typically ~5-30ms on a freshly-started app.
duk_ret_t js_deoptimizeAll(duk_context* ctx) {
    auto* vm = current_vm(ctx);
    if (!vm) { duk_push_uint(ctx, 0); return 1; }
    const TypeInfo* mt = vm->type("Method");
    if (!mt) { duk_push_uint(ctx, 0); return 1; }
    const FieldInfo* code_f = mt->field("_code");
    if (!code_f) { duk_push_uint(ctx, 0); return 1; }
    size_t code_off = code_f->offset;

    uint32_t cleared = 0;
    {
        // Suspend all OTHER threads briefly to avoid racing with active
        // method dispatch. Our agent thread keeps running.
        std::vector<HANDLE> handles;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE) {
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

        try {
            ClassWalker cw(vm);
            for (auto& k : cw.list()) {
                std::vector<MethodSnapshot> methods;
                try { methods = methods_of(vm, k.address); }
                catch (...) { continue; }
                for (auto& m : methods) {
                    uint64_t slot = m.address + code_off;
                    uint64_t zero = 0;
                    try {
                        vm->reader()->write(slot, &zero, 8);
                        cleared++;
                    } catch (...) {}
                }
            }
        } catch (...) {}

        for (HANDLE h : handles) { ResumeThread(h); CloseHandle(h); }
    }
    duk_push_uint(ctx, cleared);
    return 1;
}

duk_ret_t js_javaCallStatus(duk_context* ctx) {
    bool ok = resolve_all();
    char buf[256];
    std::snprintf(buf, sizeof(buf),
        "{ready:%d, bootstrap_failed:%d, bs_step:%d, bs_rc:%d, "
        "attach=0x%llx, jt_current=0x%llx, "
        "jc_call=0x%llx, jca_ctor=0x%llx, main_vm=0x%llx, make_local=0x%llx}",
        ok ? 1 : 0, g_sym.bootstrap_failed ? 1 : 0,
        g_sym.bootstrap_step, g_sym.bootstrap_attach_rc,
        (unsigned long long)g_sym.attach_current_thread,
        (unsigned long long)g_sym.javathread_current,
        (unsigned long long)g_sym.javacalls_call,
        (unsigned long long)g_sym.javacallargs_ctor,
        (unsigned long long)g_sym.main_vm_addr,
        (unsigned long long)g_sym.jnihandles_make_local);
    duk_push_string(ctx, buf);
    return 1;
}

// JNIEnv vtable slot offsets (from jni.h JNINativeInterface_).
constexpr size_t JNI_FindClass                 =   6 * 8;
constexpr size_t JNI_GetStaticMethodID         = 113 * 8;
constexpr size_t JNI_CallStaticObjectMethodA   = 116 * 8;
constexpr size_t JNI_CallStaticVoidMethodA     = 143 * 8;
constexpr size_t JNI_CallStaticIntMethodA      = 131 * 8;
constexpr size_t JNI_CallStaticLongMethodA     = 134 * 8;
constexpr size_t JNI_CallStaticBooleanMethodA  = 119 * 8;
constexpr size_t JNI_NewLocalRef               =  25 * 8;
constexpr size_t JNI_DeleteLocalRef            =  23 * 8;
constexpr size_t JNI_ExceptionCheck            = 228 * 8;
constexpr size_t JNI_ExceptionClear            =  17 * 8;

typedef void*  (*JniNewLocalRefFn)(void* env, void* obj);
typedef void   (*JniDeleteLocalRefFn)(void* env, void* obj);
typedef int    (*JniExceptionCheckFn)(void* env);
typedef void   (*JniExceptionClearFn)(void* env);
typedef void*  (*JniGetStaticMethodIDFn)(void* env, void* clazz,
                                          const char* name, const char* sig);
typedef void   (*JniCallStaticVoidMethodAFn)(void* env, void* clazz,
                                              void* methodID,
                                              const void* args);
typedef int32_t (*JniCallStaticIntMethodAFn)(void* env, void* clazz,
                                              void* methodID,
                                              const void* args);
typedef int64_t (*JniCallStaticLongMethodAFn)(void* env, void* clazz,
                                               void* methodID,
                                               const void* args);
typedef void*  (*JniCallStaticObjectMethodAFn)(void* env, void* clazz,
                                                void* methodID,
                                                const void* args);

// JNIEnv* for current thread = JavaThread* + |env_offset|. We cached
// env_offset (negative) in g_xref_env_offset; JNIEnv address sits
// AFTER the JavaThread struct header by that distance.
static void* current_jnienv() {
    auto* jt_cur_fn = reinterpret_cast<JtCurFn>(g_sym.javathread_current);
    if (!jt_cur_fn) return nullptr;
    void* thread = jt_cur_fn();
    if (!thread) return nullptr;
    int32_t off = g_xref_env_offset.load(std::memory_order_relaxed);
    if (off == 0) return nullptr;
    // env = thread - off  (off is negative; -(-0x2b8) = +0x2b8)
    return reinterpret_cast<char*>(thread) - off;
}

// JS: Marrow._invokeJNI(klassOopHex, name, sig, ret, args)
// Routes Java method invocation through the JNIEnv vtable instead of
// internal JavaCalls::call. Works on JREs without PDB and avoids the
// methodHandle/HandleArea layout pitfalls. Static methods only for now.
//
// Args:
//   klassOopHex — class oop (Java.use(name).$klassOop)
//   name        — method simple name
//   sig         — JVM signature, e.g. "()I", "(I)V"
//   ret         — return-type letter (V/I/J/Z/L)
//   args        — array of values; primitives as numbers/hex strings,
//                 objects as oop hex strings
//
// Returns: hex string for L/J, number for I/Z, "ok" for V, or
//          "java_exception" / "skip_*" on failure.
// First arg interpretation: pass class NAME as string (e.g. "Callable" or
// "java/lang/String"). JNI's FindClass resolves both kinds. This avoids
// having to extract the mirror oop manually — JNI does it for us.
duk_ret_t js_invokeJNI(duk_context* ctx) {
    const char* class_name = duk_require_string(ctx, 0);
    const char* name       = duk_require_string(ctx, 1);
    const char* sig        = duk_require_string(ctx, 2);
    const char* ret_str    = duk_get_string_default(ctx, 3, "V");
    duk_idx_t   args_idx   = (duk_get_top(ctx) >= 5 && duk_is_array(ctx, 4)) ? 4 : -1;
    char ret_c = ret_str[0] ? ret_str[0] : 'V';

    if (!resolve_all())     { duk_push_string(ctx, "no_pdb");           return 1; }
    if (!ensure_attached()) { duk_push_string(ctx, "attach_failed");    return 1; }

    void* env = current_jnienv();
    if (!env) { duk_push_string(ctx, "no_env"); return 1; }
    // Pull thread* via the same global accessor sync hooks use. Needed
    // for JNIHandles::make_local on object args.
    void* thread = nullptr;
    {
        auto jt_cur = reinterpret_cast<JtCurFn>(g_sym.javathread_current);
        if (jt_cur) thread = jt_cur();
    }

    // Read JNIEnv vtable.
    void** vtable = seh_read_vtable(env);
    if (!vtable) { duk_push_string(ctx, "no_vtable"); return 1; }

    auto get_slot = [&](size_t off) -> void* {
        return *reinterpret_cast<void**>(reinterpret_cast<char*>(vtable) + off);
    };

    auto new_local_ref       = reinterpret_cast<JniNewLocalRefFn>      (get_slot(JNI_NewLocalRef));
    auto delete_local_ref    = reinterpret_cast<JniDeleteLocalRefFn>   (get_slot(JNI_DeleteLocalRef));
    auto exception_check     = reinterpret_cast<JniExceptionCheckFn>   (get_slot(JNI_ExceptionCheck));
    auto exception_clear     = reinterpret_cast<JniExceptionClearFn>   (get_slot(JNI_ExceptionClear));
    auto get_static_method   = reinterpret_cast<JniGetStaticMethodIDFn>(get_slot(JNI_GetStaticMethodID));

    // Use JNI's FindClass to resolve the class. Handles mirror oop
    // expansion + classloader scope automatically. Accepts both
    // dot-form ("java.lang.String") and JVM internal form
    // ("java/lang/String"); we normalize dots to slashes here.
    char fcname[256];
    {
        size_t i = 0;
        for (; class_name[i] && i < sizeof(fcname) - 1; ++i) {
            fcname[i] = (class_name[i] == '.') ? '/' : class_name[i];
        }
        fcname[i] = 0;
    }
    typedef void* (*JniFindClassFn)(void*, const char*);
    auto jclazz = reinterpret_cast<JniFindClassFn>(get_slot(JNI_FindClass))
                    (env, fcname);
    if (!jclazz) {
        if (exception_check && exception_check(env)) exception_clear(env);
        duk_push_string(ctx, "no_jclazz");
        return 1;
    }

    void* mid = seh_jni_get_static_method(get_slot(JNI_GetStaticMethodID),
                                           env, jclazz, name, sig);
    if (!mid) {
        if (exception_check && exception_check(env)) exception_clear(env);
        if (delete_local_ref) delete_local_ref(env, jclazz);
        duk_push_string(ctx, "no_mid");
        return 1;
    }

    // Build jvalue arg array. jvalue is an 8-byte union; for primitive
    // args we store the 64-bit raw value, JNI will read the relevant
    // half. For object args we store the jobject pointer.
    constexpr size_t MAX_ARGS = 16;
    uint64_t jvals[MAX_ARGS] = {};
    size_t   n_args = 0;
    if (args_idx >= 0) {
        size_t n = duk_get_length(ctx, args_idx);
        if (n > MAX_ARGS) n = MAX_ARGS;
        // Walk signature to know each arg's type; for now assume all
        // primitives encoded as numbers/hex strings (no objects).
        size_t sp = 1;   // skip leading '('
        for (size_t i = 0; i < n; ++i) {
            char letter = sig[sp];
            // skip array brackets and L<class>;
            if (letter == '[') { while (sig[sp] == '[') ++sp; }
            if (sig[sp] == 'L') {
                while (sig[sp] && sig[sp] != ';') ++sp;
                if (sig[sp]) ++sp;
                letter = 'L';
            } else {
                ++sp;
            }
            duk_get_prop_index(ctx, args_idx, (duk_uarridx_t)i);
            uint64_t v = 0;
            if (letter == 'L') {
                const char* oop_hex = duk_to_string(ctx, -1);
                uint64_t oop = std::strtoull(oop_hex, nullptr, 0);
                // On JDKs with UseCompressedOops, oop hex strings handed
                // around by the agent (readStaticRef/Java.toString/etc.)
                // are narrow when the heap fits in 32 bits. Expand to a
                // wide pointer before wrapping. When heap_base==0 and
                // shift==0 (typical for small heaps), decode is identity.
                if (oop && (oop >> 32) == 0 && g_dec) {
                    uint64_t wide = g_dec->decode_oop(oop);
                    if (wide && (wide >> 32) != 0) oop = wide;
                }
                // CORRECT abstraction: NewLocalRef expects an existing
                // jobject (a JNIHandle slot pointer), NOT a raw oop. To
                // wrap a raw oop into a jobject we use HotSpot's internal
                // JNIHandles::make_local(thread, oop) — same path the
                // _invokeJC code uses for receivers. NewLocalRef on a
                // raw oop just stores the bits and JVM crashes when the
                // method body dereferences "jobject" expecting a slot.
                void* slot = nullptr;
                if (oop && g_sym.jnihandles_make_local && thread) {
                    slot = seh_make_local(g_sym.jnihandles_make_local,
                                           thread,
                                           reinterpret_cast<void*>(oop));
                }
                v = reinterpret_cast<uint64_t>(slot);
            } else if (letter == 'J' || letter == 'D') {
                if (duk_is_string(ctx, -1)) {
                    v = std::strtoull(duk_get_string(ctx, -1), nullptr, 0);
                } else {
                    if (letter == 'D') {
                        double d = duk_get_number(ctx, -1);
                        std::memcpy(&v, &d, 8);
                    } else {
                        v = (uint64_t)(int64_t)duk_get_number(ctx, -1);
                    }
                }
            } else if (letter == 'F') {
                float f = (float)duk_get_number(ctx, -1);
                uint32_t bits; std::memcpy(&bits, &f, 4);
                v = bits;
            } else {
                v = (uint64_t)duk_get_int_default(ctx, -1, 0);
            }
            duk_pop(ctx);
            jvals[n_args++] = v;
        }
    }

    char retbuf[32] = {};
    bool threw = false;
    int64_t i_val = 0;
    int32_t int_val = 0;
    void* obj_val = nullptr;

    void* call_thunk = nullptr;
    switch (ret_c) {
        case 'V': call_thunk = get_slot(JNI_CallStaticVoidMethodA);    break;
        case 'I': case 'B': case 'S': case 'C':
                  call_thunk = get_slot(JNI_CallStaticIntMethodA);     break;
        case 'Z': call_thunk = get_slot(JNI_CallStaticBooleanMethodA); break;
        case 'J': call_thunk = get_slot(JNI_CallStaticLongMethodA);    break;
        case 'L': case '[':
                  call_thunk = get_slot(JNI_CallStaticObjectMethodA);  break;
        default:
            std::snprintf(retbuf, sizeof(retbuf), "bad_ret_%c", ret_c);
            threw = true;
    }
    if (call_thunk) {
        auto cr = seh_jni_call(call_thunk, ret_c, env, jclazz, mid, jvals);
        threw   = cr.threw;
        int_val = cr.i_val;
        i_val   = cr.l_val;
        obj_val = cr.o_val;
    }

    if (exception_check && exception_check(env)) {
        if (exception_clear) exception_clear(env);
        threw = true;
    }
    if (delete_local_ref) delete_local_ref(env, jclazz);

    if (threw) {
        duk_push_string(ctx, retbuf[0] ? retbuf : "java_exception");
        return 1;
    }
    switch (ret_c) {
        case 'V':
            duk_push_string(ctx, "ok");
            break;
        case 'I': case 'B': case 'S': case 'C':
            std::snprintf(retbuf, sizeof(retbuf), "value:0x%x",
                          (unsigned)(uint32_t)int_val);
            duk_push_string(ctx, retbuf);
            break;
        case 'Z':
            duk_push_string(ctx, int_val ? "value:true" : "value:false");
            break;
        case 'J':
            std::snprintf(retbuf, sizeof(retbuf), "value:0x%llx",
                          (unsigned long long)i_val);
            duk_push_string(ctx, retbuf);
            break;
        case 'L': case '[':
            std::snprintf(retbuf, sizeof(retbuf), "0x%llx",
                          (unsigned long long)reinterpret_cast<uintptr_t>(obj_val));
            duk_push_string(ctx, retbuf);
            break;
    }
    return 1;
}

// JS: Marrow._setReentryGuard(cookie, delta) -> new depth.
// Bumps the per-thread reentry counter for `cookie` by `delta`. Used by
// `<handle>.callOriginal` to skip the user handler when the original
// method is invoked from inside the hook — preventing infinite recursion.
extern "C" int marrow_hook_set_reentry(uint64_t cookie, int delta);
duk_ret_t js_setReentryGuard(duk_context* ctx) {
    double cookie_d = duk_to_number(ctx, 0);
    int    delta    = (int)duk_to_int(ctx, 1);
    int rc = marrow_hook_set_reentry((uint64_t)cookie_d, delta);
    duk_push_int(ctx, rc);
    return 1;
}

// Diagnostics for hot-loop tramp behavior. Three counters (read via
// strings since Duktape int is double): total dispatch fires, fires
// short-circuited by reentry guard, fires that ran cb.
//   marrow_hook_dbg_fire_total / dbg_skip_reentry / dbg_reset
// (No JS-side wrappers needed beyond the c-funcs; called as ints.)
extern "C" uint64_t marrow_hook_dbg_fire_total();
extern "C" uint64_t marrow_hook_dbg_skip_reentry();
extern "C" void     marrow_hook_dbg_reset();
duk_ret_t js_dbgFireTotal(duk_context* ctx) {
    uint64_t v = marrow_hook_dbg_fire_total();
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
    duk_push_string(ctx, buf);
    return 1;
}
duk_ret_t js_dbgSkipReentry(duk_context* ctx) {
    uint64_t v = marrow_hook_dbg_skip_reentry();
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
    duk_push_string(ctx, buf);
    return 1;
}
duk_ret_t js_dbgReset(duk_context* ctx) {
    marrow_hook_dbg_reset();
    duk_push_true(ctx);
    return 1;
}

// _diagJniNewLocal removed v1.0.2 — was a diagnostic that actively
// invoked JNIEnv->NewLocalRef. Pure JNI Function API surface, not
// load-bearing for any user-facing feature.

// Diagnostic: probe what decode_oop does with a candidate narrow value.
duk_ret_t js_diagOopDecode(duk_context* ctx) {
    const char* hex = duk_require_string(ctx, 0);
    uint64_t v = std::strtoull(
        hex[0]=='0' && (hex[1]=='x'||hex[1]=='X') ? hex+2 : hex, nullptr, 16);
    char buf[256];
    if (!g_dec) {
        std::snprintf(buf, sizeof(buf), "no_dec");
    } else {
        uint64_t base = g_dec->oop_params.base;
        int      shift = g_dec->oop_params.shift;
        uint64_t decoded = g_dec->decode_oop(v);
        std::snprintf(buf, sizeof(buf),
            "in=0x%llx base=0x%llx shift=%d decoded=0x%llx",
            (unsigned long long)v, (unsigned long long)base,
            shift, (unsigned long long)decoded);
    }
    duk_push_string(ctx, buf);
    return 1;
}

// Diagnostic: extract mirror oop from a Klass*. Returns
// "klass=0x..,handle=0x..,mirror=0x.." for inspection.
duk_ret_t js_diagMirror(duk_context* ctx) {
    const char* klass_hex = duk_require_string(ctx, 0);
    uint64_t klass = std::strtoull(
        klass_hex[0] == '0' && (klass_hex[1] == 'x' || klass_hex[1] == 'X')
            ? klass_hex + 2 : klass_hex,
        nullptr, 16);
    VMMeta* vm = current_vm(ctx);
    if (!vm) { duk_push_string(ctx, "no_vm"); return 1; }
    auto* kt = vm->type("Klass");
    auto* mf = kt ? kt->field("_java_mirror") : nullptr;
    char buf[256];
    if (!mf) {
        std::snprintf(buf, sizeof(buf), "no_mirror_field");
    } else {
        uint64_t wide_at_field = vm->reader()->read_u64(klass + mf->offset);
        uint32_t narrow_at_field = vm->reader()->read_u32(klass + mf->offset);
        uint64_t mirror_via_handle = (wide_at_field && g_dec)
            ? seh_deref_oop_handle(wide_at_field) : 0;
        // Try expanding narrow via OopDecoder.
        uint64_t mirror_decoded = (narrow_at_field && g_dec)
            ? g_dec->decode_oop(narrow_at_field) : 0;
        std::snprintf(buf, sizeof(buf),
            "klass=0x%llx,off=%d,wide=0x%llx,narrow=0x%x,via_handle=0x%llx,decoded=0x%llx",
            (unsigned long long)klass, (int)mf->offset,
            (unsigned long long)wide_at_field, narrow_at_field,
            (unsigned long long)mirror_via_handle, (unsigned long long)mirror_decoded);
    }
    duk_push_string(ctx, buf);
    return 1;
}

// JS: Marrow._jniVtableSlot(slotIndex) -> "0x..." VA of fn at vtable[slot].
// Allows triangulating from CallStatic*MethodA entries to find JC chain.
duk_ret_t js_jniVtableSlot(duk_context* ctx) {
    int slot = duk_require_int(ctx, 0);
    if (!resolve_all())     { duk_push_string(ctx, "no_pdb"); return 1; }
    if (!ensure_attached()) { duk_push_string(ctx, "attach_failed"); return 1; }
    void* env = current_jnienv();
    if (!env) { duk_push_string(ctx, "no_env"); return 1; }
    void** vtable = seh_read_vtable(env);
    if (!vtable) { duk_push_string(ctx, "no_vtable"); return 1; }
    void* fn = *reinterpret_cast<void**>(
        reinterpret_cast<char*>(vtable) + (size_t)slot * 8);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  (unsigned long long)reinterpret_cast<uintptr_t>(fn));
    duk_push_string(ctx, buf);
    return 1;
}

// Test-only: override g_sym.javacalls_call with an arbitrary VA. Used to
// experimentally validate xref-resolved candidates against actual
// invocation behavior on JREs without PDB. Returns the previous address.
duk_ret_t js_setJavaCallsCall(duk_context* ctx) {
    const char* va_str = duk_require_string(ctx, 0);
    unsigned long long va = 0;
    {
        const char* s = va_str;
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
        std::sscanf(s, "%llx", &va);
    }
    // Trigger normal resolve_all FIRST so the rest of g_sym (thread,
    // make_local, attach, etc.) is filled. Then override javacalls_call
    // and lock g_sym.ready=true so subsequent _invokeJC calls don't
    // re-bootstrap and overwrite our value with whatever xref returned.
    resolve_all();
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  (unsigned long long)g_sym.javacalls_call);
    g_sym.javacalls_call = reinterpret_cast<void*>((uintptr_t)va);
    {
        std::lock_guard<std::mutex> lk(g_sym.mu);
        g_sym.ready = true;
        g_sym.bootstrap_failed = false;
    }
    duk_push_string(ctx, buf);
    return 1;
}

// Cached offset of Method._from_interpreted_entry. JDK 8 = 0x50, JDK 11 = 0x48,
// JDK 17 = 0x50. Resolved via vmStructs.
__declspec(noinline)
static size_t lookup_method_entry_offset(marrow::VMMeta* vm) {
    static size_t cached = (size_t)-1;
    if (cached != (size_t)-1) return cached;
    cached = 0;
    if (!vm) return 0;
    auto* m = vm->type("Method");
    if (m && m->has_field("_from_interpreted_entry"))
        cached = m->field("_from_interpreted_entry")->offset;
    return cached;
}

// Call call_stub_entry directly. Bypasses JC::call entirely. Used as a
// JDK 8 fallback when JC::call is inlined or unfindable. The call_stub
// signature (Win64):
//   void (*CallStub)(void* link, intptr_t* result, int result_type,
//                    void* method, void* entry_point, intptr_t* parameters,
//                    int size_of_parameters, void* thread);
//
// Since call_stub takes 8 args and Win64 only passes 4 in regs, the last
// 4 go on the stack. Calling it from C++ with the right convention is
// straightforward via a typedef.
typedef void (*CallStubFn)(void* link, intptr_t* result, int result_type,
                           void* method, void* entry_point,
                           intptr_t* parameters, int size_of_parameters,
                           void* thread);

__declspec(noinline)
static bool seh_call_stub(void* fn_va, intptr_t* result, int rtype,
                          void* method, void* entry_point,
                          intptr_t* params, int psize, void* thread) {
    auto fn = reinterpret_cast<CallStubFn>(fn_va);
    __try {
        fn(/*link*/nullptr, result, rtype, method, entry_point,
           params, psize, thread);
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return true; }
}

// SEH-isolated read+clear of Thread::_pending_exception. Caller does
// the std::string-creating field lookup (which would force a destructor
// in this scope and prevent __try). We get a raw byte offset.
__declspec(noinline)
static bool jc_check_pending_exception(uint64_t pe_addr) {
    bool had_pending = false;
    __try {
        uint64_t pending = *reinterpret_cast<volatile uint64_t*>(pe_addr);
        if (pending) {
            *reinterpret_cast<volatile uint64_t*>(pe_addr) = 0;
            had_pending = true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { /* swallow */ }
    return had_pending;
}

// Combined: check whether Java has a pending exception via the JNIEnv
// vtable (same path js_invokeJNI uses). vmStructs doesn't expose
// Thread::_pending_exception on every JDK we care about (JDK 17 in
// particular omits it), so the direct field-read approach via Thread
// would silently no-op there. JNI's ExceptionCheck reads the same
// underlying field but goes through the JVM's blessed entry point.
__declspec(noinline)
static bool jc_pending_exception_via_jni() {
    void* env = current_jnienv();
    if (!env) return false;
    void** vtable = seh_read_vtable(env);
    if (!vtable) return false;
    auto exception_check = reinterpret_cast<JniExceptionCheckFn>(
        *reinterpret_cast<void**>(reinterpret_cast<char*>(vtable) + JNI_ExceptionCheck));
    auto exception_clear = reinterpret_cast<JniExceptionClearFn>(
        *reinterpret_cast<void**>(reinterpret_cast<char*>(vtable) + JNI_ExceptionClear));
    if (!exception_check) return false;
    bool had = false;
    __try {
        if (exception_check(env)) {
            if (exception_clear) exception_clear(env);
            had = true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { had = false; }
    return had;
}

// SEH-isolated read of `_from_interpreted_entry` from a Method*.
__declspec(noinline)
static void* seh_read_method_entry(uint64_t method_ptr, size_t off) {
    auto* p = reinterpret_cast<void**>(method_ptr + off);
    __try { return *p; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// JS: Marrow._callStubReturnAddress() -> hex VA inside call_stub right
// after the method dispatch instruction. Walk back from this to find the
// stub entry. Returns null if vmStructs lookup fails.
__declspec(noinline)
static uint64_t lookup_call_stub_return_slot(marrow::VMMeta* vm) {
    if (!vm || !vm->has_type("StubRoutines")) return 0;
    auto* sr = vm->type("StubRoutines");
    if (!sr->has_field("_call_stub_return_address")) return 0;
    return sr->field("_call_stub_return_address")->address;
}
__declspec(noinline)
static uint64_t seh_read_u64(uint64_t addr) {
    __try { return *reinterpret_cast<uint64_t*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
duk_ret_t js_callStubReturnAddress(duk_context* ctx) {
    uint64_t slot = lookup_call_stub_return_slot(current_vm(ctx));
    uint64_t v = slot ? seh_read_u64(slot) : 0;
    if (!v) { duk_push_null(ctx); return 1; }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
    duk_push_string(ctx, buf);
    return 1;
}

// JS: Marrow._invokeViaCallStub(stubVa, methodLo, methodHi, retLetter,
//                                  argTypes, argv, recvHex)
// Returns "{type:N, value:0x..}" or error string.
duk_ret_t js_invokeViaCallStub(duk_context* ctx) {
    const char* stub_va_str = duk_require_string(ctx, 0);
    uint64_t stub_va = std::strtoull(
        stub_va_str[0]=='0' && (stub_va_str[1]=='x'||stub_va_str[1]=='X')
            ? stub_va_str+2 : stub_va_str, nullptr, 16);
    if (!stub_va) { duk_push_string(ctx, "no_stub"); return 1; }

    uint32_t lo = (uint32_t)duk_to_uint32(ctx, 1);
    uint32_t hi = (uint32_t)duk_to_uint32(ctx, 2);
    uint64_t method_ptr = ((uint64_t)hi << 32) | lo;
    if (!method_ptr) { duk_push_string(ctx, "no_method"); return 1; }

    const char* rt_str = duk_get_string_default(ctx, 3, "V");
    int basic_type = basic_type_from_letter(rt_str[0]);
    if (basic_type == 0) basic_type = 14;

    const char* arg_types = duk_get_string_default(ctx, 4, "");
    duk_idx_t arg_arr_idx = -1;
    if (duk_get_top(ctx) >= 6 && duk_is_array(ctx, 5)) arg_arr_idx = 5;
    const char* recv_hex = duk_get_string_default(ctx, 6, "");

    if (!resolve_all())     { duk_push_string(ctx, "no_pdb"); return 1; }
    if (!ensure_attached()) { duk_push_string(ctx, "attach_failed"); return 1; }

    auto* vm = current_vm(ctx);
    size_t entry_off = lookup_method_entry_offset(vm);
    if (!entry_off) { duk_push_string(ctx, "no_method_entry_off"); return 1; }

    auto jt_cur = reinterpret_cast<JtCurFn>(g_sym.javathread_current);
    void* thread = jt_cur ? jt_cur() : nullptr;
    if (!thread) { duk_push_string(ctx, "no_jt"); return 1; }

    void* entry_point = seh_read_method_entry(method_ptr, entry_off);
    if (!entry_point) { duk_push_string(ctx, "no_entry_point"); return 1; }

    // Build params buffer. HotSpot interpreter expects args in reverse
    // declaration order on stack (the call_stub push loop reads slot 0
    // first and pushes it, then slot 1 etc., resulting in slot[size-1]
    // ending on top of stack). For HotSpot this means slot[0] should be
    // the LAST arg and slot[size-1] should be the FIRST arg ("this" for
    // instance methods).
    //
    // Reference: stubGenerator_x86_64.cpp::generate_call_stub builds the
    // loop and the interpreter convention expects args[0] at highest
    // stack address (which translates to last-pushed = slot[size-1]).
    //
    // Build a temporary array in declaration order, then reverse before
    // passing to the stub.
    alignas(8) intptr_t params_buf[16] = {};
    int psize = 0;
    // call_stub passes args directly to the interpreter entry which reads
    // them as raw oop pointers from the stack -- NO jobject wrapping.
    // (Unlike _invokeJNI which routes through JNIEnv's CallStaticXxxMethodA
    // and needs make_local to convert oop -> jobject.)
    bool has_receiver = recv_hex && recv_hex[0] != 0;
    if (has_receiver) {
        uint64_t recv_oop = std::strtoull(recv_hex, nullptr, 0);
        params_buf[psize++] = (intptr_t)(uintptr_t)recv_oop;
    }
    if (arg_types[0] != 0 && arg_arr_idx >= 0) {
        size_t n_types = std::strlen(arg_types);
        size_t n_arr   = duk_get_length(ctx, arg_arr_idx);
        size_t n       = (n_types < n_arr) ? n_types : n_arr;
        for (size_t i = 0; i < n; ++i) {
            char letter = arg_types[i];
            duk_get_prop_index(ctx, arg_arr_idx, (duk_uarridx_t)i);
            // J/D occupy TWO interpreter slots per JVM spec. Each 8-byte
            // slot holds half the 64-bit value. HotSpot's call_stub pushes
            // these in (high, low) order on x64.
            if (letter == 'J' || letter == 'D') {
                if (psize + 2 > 16) { duk_pop(ctx);
                    duk_push_string(ctx, "too_many_args"); return 1; }
                uint64_t v64 = 0;
                if (letter == 'J') {
                    if (duk_is_string(ctx, -1))
                        v64 = std::strtoull(duk_get_string(ctx, -1), nullptr, 0);
                    else
                        v64 = (uint64_t)(int64_t)duk_get_number(ctx, -1);
                } else {
                    double d = duk_get_number(ctx, -1);
                    std::memcpy(&v64, &d, 8);
                }
                // 2-slot encoding: slot[k] = HIGH 32 bits, slot[k+1] = LOW 32.
                // (HotSpot generates this via push/pop interpreter macros.)
                params_buf[psize++] = (intptr_t)(int32_t)(v64 >> 32);
                params_buf[psize++] = (intptr_t)(int32_t)(v64 & 0xFFFFFFFF);
            } else if (letter == 'F') {
                if (psize + 1 > 16) { duk_pop(ctx);
                    duk_push_string(ctx, "too_many_args"); return 1; }
                float f = (float)duk_get_number(ctx, -1);
                uint32_t bits = 0; std::memcpy(&bits, &f, 4);
                params_buf[psize++] = (intptr_t)(uint64_t)bits;
            } else if (letter == 'L' || letter == '[') {
                if (psize + 1 > 16) { duk_pop(ctx);
                    duk_push_string(ctx, "too_many_args"); return 1; }
                uint64_t oop = 0;
                if (duk_is_string(ctx, -1))
                    oop = std::strtoull(duk_get_string(ctx, -1), nullptr, 0);
                // Pass raw oop directly -- interpreter reads it as oop from stack.
                params_buf[psize++] = (intptr_t)(uintptr_t)oop;
            } else {
                if (psize + 1 > 16) { duk_pop(ctx);
                    duk_push_string(ctx, "too_many_args"); return 1; }
                params_buf[psize++] =
                    (intptr_t)(int32_t)duk_get_number_default(ctx, -1, 0.0);
            }
            duk_pop(ctx);
        }
    }

    // No reversal: HotSpot's call_stub push loop pushes params[0] FIRST
    // (to the LOWEST stack address after multiple pushes), so params[0]
    // ends up at the BOTTOM of the pushed area — which matches local[0]
    // (the highest local-frame address per interpreter convention).
    // For addInts(a, b): params=[a, b]. For mulLong(a, b): params=[a_hi,
    // a_lo, b_hi, b_lo] OR [a_lo, a_hi, b_lo, b_hi] depending on slot
    // packing — caller picks via arg-letter expansion.

    alignas(16) intptr_t result_buf[2] = {0, 0};

    bool threw = seh_call_stub(reinterpret_cast<void*>(stub_va),
                                result_buf, basic_type,
                                reinterpret_cast<void*>(method_ptr),
                                entry_point,
                                psize ? params_buf : nullptr, psize,
                                thread);
    if (threw) { duk_push_string(ctx, "java_exception"); return 1; }

    // Java exceptions are stored on Thread::_pending_exception without
    // raising an SEH exception in native code. After call_stub returns
    // "successfully", check the field to know whether the call really
    // completed or threw a Throwable. Resolve the offset HERE (where
    // it's safe to use std::string for the field lookup) and pass a
    // raw address into the SEH-protected helper.
    if (jc_pending_exception_via_jni()) {
        duk_push_string(ctx, "java_exception");
        return 1;
    }

    char out[96];
    std::snprintf(out, sizeof(out), "{type:%d, value:0x%llx}",
                  basic_type, static_cast<unsigned long long>(result_buf[0]));
    duk_push_string(ctx, out);
    return 1;
}

} // anon

void register_javacall_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_invokeJC, DUK_VARARGS);
    duk_put_prop_string(ctx, ns_idx, "_invokeJC");
    duk_push_c_function(ctx, js_javaCallStatus, 0);
    duk_put_prop_string(ctx, ns_idx, "_javaCallStatus");
    duk_push_c_function(ctx, js_deoptimizeAll, 0);
    duk_put_prop_string(ctx, ns_idx, "_deoptimizeAll");
    duk_push_c_function(ctx, js_initializeKlass, 1);
    duk_put_prop_string(ctx, ns_idx, "_initializeKlass");
    duk_push_c_function(ctx, js_setJavaCallsCall, 1);
    duk_put_prop_string(ctx, ns_idx, "_setJavaCallsCall");
    duk_push_c_function(ctx, js_jniVtableSlot, 1);
    duk_put_prop_string(ctx, ns_idx, "_jniVtableSlot");
    duk_push_c_function(ctx, js_invokeJNI, DUK_VARARGS);
    duk_put_prop_string(ctx, ns_idx, "_invokeJNI");
    duk_push_c_function(ctx, js_diagMirror, 1);
    duk_put_prop_string(ctx, ns_idx, "_diagMirror");
    duk_push_c_function(ctx, js_diagOopDecode, 1);
    duk_put_prop_string(ctx, ns_idx, "_diagOopDecode");
    duk_push_c_function(ctx, js_setReentryGuard, 2);
    duk_put_prop_string(ctx, ns_idx, "_setReentryGuard");
    duk_push_c_function(ctx, js_dbgFireTotal, 0);
    duk_put_prop_string(ctx, ns_idx, "_dbgFireTotal");
    duk_push_c_function(ctx, js_dbgSkipReentry, 0);
    duk_put_prop_string(ctx, ns_idx, "_dbgSkipReentry");
    duk_push_c_function(ctx, js_dbgReset, 0);
    duk_put_prop_string(ctx, ns_idx, "_dbgReset");
    duk_push_c_function(ctx, js_defineClassNative, 3);
    duk_put_prop_string(ctx, ns_idx, "_defineClassNative");
    duk_push_c_function(ctx, js_invokeViaCallStub, DUK_VARARGS);
    duk_put_prop_string(ctx, ns_idx, "_invokeViaCallStub");
    duk_push_c_function(ctx, js_callStubReturnAddress, 0);
    duk_put_prop_string(ctx, ns_idx, "_callStubReturnAddress");
}

} // namespace marrow
