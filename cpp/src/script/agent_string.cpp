#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "agent_js.hpp"
#include "string_reader.hpp"
#include "walker.hpp"
#include "oop_reader.hpp"
#include "zgc.hpp"
#include "tlab.hpp"
#include "duktape.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdio>

namespace marrow {

// ---------------------------------------------------------------------------
// RAII suspend: snapshot all non-self threads in this PID, suspend them in
// the constructor, resume + close handles in the destructor.
// ---------------------------------------------------------------------------
struct ScopedSuspend {
    std::vector<HANDLE> handles;

    ScopedSuspend() {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return;

        const DWORD our_pid = GetCurrentProcessId();
        const DWORD our_tid = GetCurrentThreadId();

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != our_pid) continue;
                if (te.th32ThreadID == our_tid)        continue;

                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (!h) continue;

                if (SuspendThread(h) == static_cast<DWORD>(-1)) {
                    CloseHandle(h);
                    continue;
                }
                handles.push_back(h);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    ~ScopedSuspend() {
        for (HANDLE h : handles) {
            ResumeThread(h);
            CloseHandle(h);
        }
    }

    // Non-copyable, non-movable — strictly RAII.
    ScopedSuspend(const ScopedSuspend&)            = delete;
    ScopedSuspend& operator=(const ScopedSuspend&) = delete;
};

// ---------------------------------------------------------------------------
// Retrieve the JsHost stored in the Duktape global stash.
// ---------------------------------------------------------------------------
static marrow::JsHost* current_host(duk_context* c) {
    duk_push_global_stash(c);
    duk_get_prop_string(c, -1, "host");
    auto* h = static_cast<marrow::JsHost*>(duk_to_pointer(c, -1));
    duk_pop_2(c);
    return h;
}

// ---------------------------------------------------------------------------
// Lazy-initialised StringReader.  std::once_flag guards construction; if
// construction throws we clear a separate "init attempted" flag so the next
// call can retry.
// ---------------------------------------------------------------------------
// States for g_sr_state:
//   0 = not yet attempted
//   1 = successfully constructed (g_sr is valid)
//   2 = construction failed — caller may reset to 0 to allow retry
static std::atomic<int>  g_sr_state{0};
static StringReader*     g_sr = nullptr;
static std::mutex        g_sr_mutex; // serialises construction / retry reset


static duk_ret_t js_toString(duk_context* ctx) {
    // Parse the hex oop argument.
    const char* hex = duk_to_string(ctx, 0);
    if (!hex || hex[0] == '\0') {
        duk_push_null(ctx);
        return 1;
    }
    char* end = nullptr;
    uint64_t oop = static_cast<uint64_t>(std::strtoull(hex, &end, 16));
    if (oop == 0) {
        duk_push_null(ctx);
        return 1;
    }

    // Fetch VM helpers from the JS host.
    marrow::JsHost* host = current_host(ctx);
    if (!host || !host->vm_) {
        duk_push_null(ctx);
        return 1;
    }
    VMMeta*     vm  = host->vm_;
    OopDecoder* dec = static_cast<OopDecoder*>(host->dec_);
    ZGCDecoder* zgc = static_cast<ZGCDecoder*>(host->zgc_);

    // Lazy construction with retry-on-failure: if state==2 (failed), reset to
    // 0 so this call gets another shot.  Serialised under g_sr_mutex.
    if (g_sr_state.load(std::memory_order_acquire) != 1) {
        std::lock_guard<std::mutex> lk(g_sr_mutex);
        int state = g_sr_state.load(std::memory_order_relaxed);
        if (state == 2) {
            // Previous attempt failed — allow retry.
            g_sr_state.store(0, std::memory_order_relaxed);
            state = 0;
        }
        if (state == 0) {
            try {
                // Resolve java/lang/String klass under suspension.
                uint64_t string_klass = 0;
                {
                    ScopedSuspend s;
                    ClassWalker cw(vm);
                    for (auto& k : cw.list()) {
                        if (k.name == "java/lang/String") {
                            string_klass = k.address;
                            break;
                        }
                    }
                }
                if (!string_klass) {
                    g_sr_state.store(2, std::memory_order_release);
                } else {
                    // Construct StringReader under suspension so find_field
                    // doesn't race with concurrent CP slot mutation.
                    // std::nothrow prevents std::bad_alloc; any C++ exception
                    // thrown by the constructor (including std::runtime_error
                    // re-raised by InProcessReader's SEH-to-C++ translator) is
                    // caught by the handlers below.  Raw AVs that bypass the
                    // translator are not catchable here under /EHsc; they
                    // require the translator to be active (inproc_reader.cpp).
                    ScopedSuspend s;
                    g_sr = new (std::nothrow) StringReader(vm, dec, zgc, string_klass);
                    if (g_sr) {
                        g_sr_state.store(1, std::memory_order_release);
                    } else {
                        g_sr_state.store(2, std::memory_order_release);
                    }
                }
            } catch (const std::exception&) {
                g_sr_state.store(2, std::memory_order_release);
            } catch (...) {
                g_sr_state.store(2, std::memory_order_release);
            }
        }
    }

    if (!g_sr) {
        duk_push_null(ctx);
        return 1;
    }

    // Try first without thread suspension — most String reads land between
    // GC cycles and the underlying byte[] is stable. The InProcessReader's
    // SEH translator catches any AV from a mid-relocate read, so the worst
    // case is an empty result on race; we retry under suspension only then.
    //
    // This eliminates the multi-millisecond freeze that ScopedSuspend
    // imposed on EVERY String field read — making cast-proxy field access
    // (e.g. obj.greeting) cheap enough to use in hot hook handlers.
    bool succeeded = false;
    try {
        std::string result = g_sr->read(oop, 4096);
        if (!result.empty()) {
            duk_push_lstring(ctx, result.c_str(), result.size());
            succeeded = true;
        }
    } catch (...) {
        // fall through to retry under suspend
    }
    if (!succeeded) {
        try {
            ScopedSuspend s;
            std::string result = g_sr->read(oop, 4096);
            duk_push_lstring(ctx, result.c_str(), result.size());
        } catch (...) {
            duk_push_null(ctx);
        }
    }
    return 1;
}

// Marrow._allocCharArray(length) -> oop hex string | null
// Allocates a fresh char[length] in some JavaThread's TLAB and returns
// the wide oop. The caller fills the elements (each 2 bytes UTF-16) via
// _writeMem at oop + array_data_offset(). Used by Java._jstring to
// produce Java Strings for field assignment.
static duk_ret_t js_allocCharArray(duk_context* ctx) {
    int length = duk_require_int(ctx, 0);
    if (length < 0 || length > (1 << 20)) {
        duk_push_null(ctx);
        return 1;
    }
    auto* host = current_host(ctx);
    auto* vm   = current_vm(ctx);
    if (!host || !vm) { duk_push_null(ctx); return 1; }
    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);
    if (!dec) { duk_push_null(ctx); return 1; }

    // Locate [C klass via Universe::_charArrayKlassObj first; fall back to
    // ClassWalker. The Universe global is the canonical, race-free source.
    uint64_t ca_klass = 0;
    if (vm->has_type("Universe") &&
        vm->type("Universe")->has_field("_charArrayKlassObj")) {
        try {
            ca_klass = vm->reader()->read_u64(
                vm->type("Universe")->field("_charArrayKlassObj")->address);
        } catch (...) {}
    }
    if (!ca_klass) {
        try {
            ClassWalker cw(vm);
            for (auto& k : cw.list()) if (k.name == "[C") { ca_klass = k.address; break; }
        } catch (...) {}
    }
    if (!ca_klass) { duk_push_null(ctx); return 1; }

    uint64_t oop = 0;
    try {
        TLABAllocator alloc(vm, dec, zgc);
        oop = alloc.allocate_type_array(ca_klass, length);
    } catch (...) {
        duk_push_null(ctx);
        return 1;
    }
    if (!oop) { duk_push_null(ctx); return 1; }

    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)oop);
    duk_push_string(ctx, buf);
    return 1;
}

// Marrow._allocInstance(klass_obj) -> oop hex string | null
// TLAB-allocates a zero-initialised instance of the given class. Caller
// is responsible for running the constructor (via Java.invoke / JavaCalls)
// before treating the object as fully formed.
static duk_ret_t js_allocInstance(duk_context* ctx) {
    uint64_t klass = obj_addr(ctx, 0);
    auto* host = current_host(ctx);
    auto* vm   = current_vm(ctx);
    if (!host || !vm || !klass) { duk_push_null(ctx); return 1; }
    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);
    if (!dec) { duk_push_null(ctx); return 1; }

    uint64_t oop = 0;
    try {
        TLABAllocator alloc(vm, dec, zgc);
        oop = alloc.allocate_instance(klass);
    } catch (...) {
        duk_push_null(ctx);
        return 1;
    }
    if (!oop) { duk_push_null(ctx); return 1; }

    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)oop);
    duk_push_string(ctx, buf);
    return 1;
}

// Marrow._allocTypeArray(typeChar, length) -> oop hex string | null
// Generic primitive-array allocator. typeChar is one of I/J/F/D/B/S/C/Z;
// resolves the corresponding [X klass via Universe globals or ClassWalker
// fallback. Used by Java.array to wrap JS arrays for JavaCalls passing.
static duk_ret_t js_allocTypeArray(duk_context* ctx) {
    const char* type_str = duk_require_string(ctx, 0);
    char typeChar = type_str[0];
    int length = duk_require_int(ctx, 1);
    if (length < 0 || length > (1 << 22)) { duk_push_null(ctx); return 1; }

    auto* host = current_host(ctx);
    auto* vm   = current_vm(ctx);
    if (!host || !vm) { duk_push_null(ctx); return 1; }
    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);
    if (!dec) { duk_push_null(ctx); return 1; }

    // Map type letter to Universe global field name.
    const char* universe_field = nullptr;
    const char* class_name     = nullptr;
    switch (typeChar) {
        case 'B': universe_field = "_byteArrayKlassObj";    class_name = "[B"; break;
        case 'C': universe_field = "_charArrayKlassObj";    class_name = "[C"; break;
        case 'I': universe_field = "_intArrayKlassObj";     class_name = "[I"; break;
        case 'J': universe_field = "_longArrayKlassObj";    class_name = "[J"; break;
        case 'F': universe_field = "_floatArrayKlassObj";   class_name = "[F"; break;
        case 'D': universe_field = "_doubleArrayKlassObj";  class_name = "[D"; break;
        case 'S': universe_field = "_shortArrayKlassObj";   class_name = "[S"; break;
        case 'Z': universe_field = "_boolArrayKlassObj";    class_name = "[Z"; break;
        default: duk_push_null(ctx); return 1;
    }

    uint64_t klass = 0;
    if (vm->has_type("Universe") &&
        vm->type("Universe")->has_field(universe_field)) {
        try {
            klass = vm->reader()->read_u64(
                vm->type("Universe")->field(universe_field)->address);
        } catch (...) {}
    }
    if (!klass) {
        try {
            ClassWalker cw(vm);
            for (auto& k : cw.list()) if (k.name == class_name) { klass = k.address; break; }
        } catch (...) {}
    }
    if (!klass) { duk_push_null(ctx); return 1; }

    uint64_t oop = 0;
    try {
        TLABAllocator alloc(vm, dec, zgc);
        oop = alloc.allocate_type_array(klass, length);
    } catch (...) {
        duk_push_null(ctx);
        return 1;
    }
    if (!oop) { duk_push_null(ctx); return 1; }

    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)oop);
    duk_push_string(ctx, buf);
    return 1;
}

// Marrow._readFile(path) -> array of byte values | null
// Native file reader for Java.openClassFile and similar. Reads up to
// 16 MiB; returns null on missing file or larger payload.
static duk_ret_t js_readFile(duk_context* ctx) {
    const char* path = duk_require_string(ctx, 0);
    HANDLE h = CreateFileA(path, GENERIC_READ,
                            FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { duk_push_null(ctx); return 1; }

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart > (16ll * 1024 * 1024)) {
        CloseHandle(h);
        duk_push_null(ctx);
        return 1;
    }
    auto n = size_t(sz.QuadPart);
    std::vector<uint8_t> buf(n);
    DWORD rd = 0;
    if (!ReadFile(h, buf.data(), DWORD(n), &rd, nullptr) || rd != n) {
        CloseHandle(h);
        duk_push_null(ctx);
        return 1;
    }
    CloseHandle(h);

    duk_idx_t arr = duk_push_array(ctx);
    for (size_t i = 0; i < n; ++i) {
        duk_push_uint(ctx, buf[i]);
        duk_put_prop_index(ctx, arr, duk_uarridx_t(i));
    }
    return 1;
}

// Marrow._charArrayDataOffset() -> int
// Returns the offset (bytes) from the array oop to the first element.
// Equal to header + length-field, typically 16 on compressed-klass builds.
static duk_ret_t js_charArrayDataOffset(duk_context* ctx) {
    auto* host = current_host(ctx);
    auto* vm   = current_vm(ctx);
    if (!host || !vm) { duk_push_int(ctx, 16); return 1; }
    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);
    try {
        TLABAllocator alloc(vm, dec, zgc);
        duk_push_int(ctx, (int)alloc.array_data_offset());
    } catch (...) {
        duk_push_int(ctx, 16);
    }
    return 1;
}

void register_string_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_toString, 1);
    duk_put_prop_string(ctx, ns_idx, "_toString");
    duk_push_c_function(ctx, js_allocCharArray, 1);
    duk_put_prop_string(ctx, ns_idx, "_allocCharArray");
    duk_push_c_function(ctx, js_charArrayDataOffset, 0);
    duk_put_prop_string(ctx, ns_idx, "_charArrayDataOffset");
    duk_push_c_function(ctx, js_allocInstance, 1);
    duk_put_prop_string(ctx, ns_idx, "_allocInstance");
    duk_push_c_function(ctx, js_allocTypeArray, 2);
    duk_put_prop_string(ctx, ns_idx, "_allocTypeArray");
    duk_push_c_function(ctx, js_readFile, 1);
    duk_put_prop_string(ctx, ns_idx, "_readFile");
}

} // namespace marrow
