#include "agent_js.hpp"
#include "agent_modules.hpp"
#include "walker.hpp"
#include "method_walker.hpp"
#include "field_reader.hpp"
#include "hooks.hpp"
#include "oop_reader.hpp"
#include "string_reader.hpp"
#include "zgc.hpp"
#include "heap_walker.hpp"
#include "klass_cloner.hpp"

#include "duktape.h"

#include <algorithm>
#include <atomic>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <atomic>
#include <cstdio>
#include <map>
#include <mutex>
#include <unordered_map>

#include <windows.h>

namespace marrow {

// External hook-counter store, shared with agent_main.cpp's `g_hook_counters`.
// We declare it weak-ish here via extern reference; agent_main.cpp owns it.
extern std::mutex g_hook_counters_mu;
extern std::unordered_map<uint64_t, std::atomic<uint64_t>> g_hook_counters;

// Forward — agent_main.cpp's tick-counting callback (used as default).
extern void on_counting_hook(HookContext* ctx);

// External log function from agent_main.cpp.
extern void agent_log(const char* fmt, ...);

// Bootstrap JS text — defined in agent_bootstrap.cpp.
extern const char* k_java_bootstrap;

// Forward declarations from agent_watch.cpp.
struct WatchEvent {
    uint32_t cookie;
    uint64_t addr;
    uint64_t fault_rip;
    uint64_t delta_count;
    uint64_t total_count;
};
uint32_t agent_watch_addr(VMMeta* vm, uint64_t addr, int length, int slot);
bool     agent_unwatch(VMMeta* vm, uint32_t cookie);
void     agent_watch_unwatch_all();
std::vector<WatchEvent> agent_drain_watches();

// Per-hook JS-implementation registry. Each registered hook holds a
// reference to a Duktape function (stashed under a unique key) and a
// fire-counter. The trampoline callback only bumps an atomic; the IPC
// dispatcher thread drains the queue and invokes the JS.
struct JsImplEntry {
    uint64_t cookie;
    std::string method_label;     // for diagnostics
    std::atomic<uint64_t> fired{0};
    std::atomic<uint64_t> drained{0};
    std::mutex regs_mu;

    // sync_mode: dispatch invokes the JS handler synchronously and uses
    // its return value to populate ctx->replace_rax + ctx->skip_orig.
    // async (default): only writes to the ring; handlers fire on
    // Java.drain(). Set by _installImpl based on which JS API the user
    // chose (.implementation = sync, .attach = async).
    std::atomic<bool> sync_mode{false};
    // Cached method signature + return type for arg decoding inside
    // sync handler invocation. Populated at install. Empty for async
    // entries (they decode lazily in Java.drain()).
    std::string sig;
    char        ret_letter = 'V';
    // True for instance methods — sync dispatch reads `this` oop from
    // the slot after the args and binds it as the JS handler's `this`.
    bool        is_instance = false;
    // Class of the method's holder (slashed name) — used to wrap the
    // receiver via Java.cast for instance hooks.
    std::string holder_class;

    struct HookSnapshot {
        uint64_t regs[16];
        uint64_t stack[16];
        uint64_t via;
    };
    // v0.4: bumped 16 → 1024. Under high-throughput .attach observers,
    // the prior 16-slot ring dropped >99% of fires between drains
    // (drain runs ~50ms cadence in JS; a 1MHz hot-path produces 50K
    // fires per drain → only the last 16 are decoded). 1024 absorbs
    // ~1ms of MHz-rate fires, OR 1 second of kHz observers, before
    // overwrite — enough that typical drain cadences see every fire.
    // Memory cost: 1024 * sizeof(HookSnapshot) ≈ 270KB per JsImplEntry.
    static constexpr size_t HOOK_RING_SIZE = 1024;
    HookSnapshot ring[HOOK_RING_SIZE]{};
    std::atomic<uint64_t> ring_head{0};  // monotonic write index
    // slot for write index i: ring[i % HOOK_RING_SIZE]
};
struct JsImplRegistry {
    std::mutex mu;
    std::vector<std::unique_ptr<JsImplEntry>> entries;

    JsImplEntry* find(uint64_t cookie) {
        for (auto& e : entries) if (e->cookie == cookie) return e.get();
        return nullptr;
    }
};
static JsImplRegistry g_js_impl;

// Per-method live-hook tracking: prevents trampoline leak when the same
// Method* is re-hooked (e.g. via a fresh Java.use() handle without a cookie).
struct LiveImplHook {
    MethodHook hook;
    uint64_t   cookie = 0;   // for matching the JsImplEntry to remove on uninstall
};
static std::mutex g_live_impl_mu;
static std::unordered_map<uint64_t, LiveImplHook> g_live_impl; // method_addr → state

// Forward decl: global OopDecoder set by agent worker. Used here for
// narrow→wide expansion of object return values from sync handlers.
extern OopDecoder* g_dec;

// Convert a JS value at top-of-stack to a 64-bit raw value matching the
// method's return-type letter. The trampoline loads this directly into rax.
//
//   V/undefined → 0
//   Z (boolean) → 0/1
//   B/S/C/I     → 32-bit int (sign-extended bits visible in low half)
//   J           → int64
//   F           → float bits in low 32
//   D           → double bits
//   L/[         → oop hex string parsed; null if undefined/null
static uint64_t js_to_rax(duk_context* c, char ret_letter) {
    if (duk_is_undefined(c, -1) || duk_is_null(c, -1)) return 0;
    switch (ret_letter) {
        case 'V': return 0;
        case 'Z': return duk_to_boolean(c, -1) ? 1 : 0;
        case 'B': case 'S': case 'C': case 'I': {
            int32_t v = (int32_t)duk_to_int(c, -1);
            return (uint64_t)(int64_t)v;   // sign-extend
        }
        case 'J': {
            if (duk_is_string(c, -1)) {
                return std::strtoull(duk_to_string(c, -1), nullptr, 0);
            }
            return (uint64_t)(int64_t)duk_to_int(c, -1);
        }
        case 'F': {
            float f = (float)duk_to_number(c, -1);
            uint32_t bits;
            std::memcpy(&bits, &f, 4);
            return (uint64_t)bits;
        }
        case 'D': {
            double d = duk_to_number(c, -1);
            uint64_t bits;
            std::memcpy(&bits, &d, 8);
            return bits;
        }
        case 'L': case '[': {
            // Handler may return a Java.cast'd proxy ({$oop:"0x...", ...}),
            // a plain hex string ("0xabc"), or null. Extract raw oop in
            // each case, then expand narrow→wide for compressed-oop heaps
            // — the trampoline rax expects a wide pointer (caller side
            // gets it as raw oop and JNI surface wraps to jobject upstream).
            uint64_t v = 0;
            if (duk_is_object(c, -1) && !duk_is_function(c, -1)) {
                if (duk_get_prop_string(c, -1, "$oop")) {
                    const char* h = duk_get_string_default(c, -1, "");
                    v = h && h[0] ? std::strtoull(h, nullptr, 0) : 0;
                }
                duk_pop(c);
                if (v == 0) {
                    // Some proxies expose .addr instead.
                    if (duk_get_prop_string(c, -2, "addr")) {
                        const char* h = duk_get_string_default(c, -1, "");
                        v = h && h[0] ? std::strtoull(h, nullptr, 0) : 0;
                    }
                    duk_pop(c);
                }
            } else {
                const char* hex = duk_safe_to_string(c, -1);
                v = hex ? std::strtoull(hex, nullptr, 0) : 0;
            }
            // Expand narrow→wide on compressed-oop heap.
            if (v && (v >> 32) == 0 && g_dec) {
                uint64_t wide = g_dec->decode_oop(v);
                if (wide && (wide >> 32) != 0) v = wide;
            }
            return v;
        }
        default: return 0;
    }
}

// Synchronous handler invocation. Runs on the JVM thread that fired the
// hook, under the JsHost recursive mutex. Decodes register-passed primitive
// args based on the cached signature, calls each handler in fns[],
// and writes the LAST handler's return into ctx->replace_rax + sets
// ctx->skip_orig=1. The caller's tramp then returns directly to the
// method's caller with that rax — original body is skipped.
//
// Limits in v1:
//   - Win64 ABI: rcx/rdx/r8/r9 = first 4 args. Beyond that we read from
//     the stack snapshot. JS handler still gets all args, but mapping
//     for stack-args requires `via=1` (compiled). For interpreter (`via=0`)
//     args sit on the operand stack — we don't decode those here yet.
//   - Object args passed to the C++ side as raw oop hex; the JS-layer
//     proxy in agent_bootstrap auto-casts via Java.cast (see examples
//     11/12 for the multi-arg / nested-object decode pattern).
static void invoke_handler_sync(JsImplEntry* e, HookContext* ctx) {
    if (!g_js_host) return;
    std::lock_guard<std::recursive_mutex> lock(g_js_host->mu());
    auto* c = static_cast<duk_context*>(g_js_host->raw_ctx());
    if (!c) return;

    // Pull Java._impls[cookie].fns from the JS world. If the entry was
    // wiped (Java.reload, explicit .implementation = null), fall through
    // to original execution — leaving ctx->skip_orig = 0 lets the
    // trampoline tail-jmp to orig as usual.
    duk_idx_t top0 = duk_get_top(c);
    duk_push_global_object(c);
    if (!duk_get_prop_string(c, -1, "Java")) { duk_set_top(c, top0); return; }
    if (!duk_get_prop_string(c, -1, "_impls")) { duk_set_top(c, top0); return; }
    duk_push_number(c, (double)e->cookie);
    duk_get_prop(c, -2);  // _impls[cookie]
    if (!duk_is_object(c, -1)) { duk_set_top(c, top0); return; }
    if (!duk_get_prop_string(c, -1, "fns") || !duk_is_array(c, -1)) {
        duk_set_top(c, top0); return;
    }
    duk_idx_t fns_idx = duk_get_top(c) - 1;
    duk_size_t n_fns = duk_get_length(c, fns_idx);
    if (n_fns == 0) { duk_set_top(c, top0); return; }
    // Whether at least one handler actually executed. If none did (all
    // pcalls threw), skip_orig stays 0 so original runs — safer default
    // than returning 0/null with a bogus replacement.
    bool any_handler_ran = false;

    // Args live on the interpreter operand stack — NOT in Win64 reg ABI.
    // c2i adapter (which our trampoline interposes on the _fce path) sets
    // up args as 64-bit slots above the return address before invoking
    // the interpreter. Layout in ctx->stack:
    //   stack[0] = return address
    //   stack[1] = LAST arg (top of operand stack)
    //   stack[2] = previous arg
    //   ...
    //   stack[n_args] = FIRST arg
    // So arg index i maps to stack[n_args - i].
    int  n_args = 0;
    int  total_slots = 0;          // operand-stack slots consumed by all args
    char letters[16] = {};
    char arg_classes[16][128] = {};
    {
        const char* sig = e->sig.c_str();
        size_t sp = (sig[0] == '(') ? 1 : 0;
        while (sig[sp] && sig[sp] != ')' && n_args < 16) {
            char c2 = sig[sp];
            if (c2 == '[') {
                while (sig[sp] == '[') ++sp;
                if (sig[sp] == 'L') {
                    ++sp;                             // skip 'L'
                    size_t cn = sp;
                    while (sig[sp] && sig[sp] != ';') ++sp;
                    size_t len = sp - cn;
                    if (len < sizeof(arg_classes[0]))
                        std::memcpy(arg_classes[n_args], sig + cn, len);
                    if (sig[sp]) ++sp;
                } else {
                    ++sp;
                }
                letters[n_args++] = 'L';
                ++total_slots;
                continue;
            }
            if (c2 == 'L') {
                ++sp;                                 // skip 'L'
                size_t cn = sp;
                while (sig[sp] && sig[sp] != ';') ++sp;
                size_t len = sp - cn;
                if (len < sizeof(arg_classes[0]))
                    std::memcpy(arg_classes[n_args], sig + cn, len);
                if (sig[sp]) ++sp;
                letters[n_args++] = 'L';
                ++total_slots;
                continue;
            }
            letters[n_args++] = c2;
            // long/double take 2 stack slots in HotSpot interpreter.
            total_slots += (c2 == 'J' || c2 == 'D') ? 2 : 1;
            ++sp;
        }
    }

    // Helper: push a Java.cast(oop_hex, className) result on top, falling
    // back to raw oop hex if cast fails. Uses Java global from a stashed
    // index so we don't pollute the stack across calls.
    auto push_cast_or_raw = [&](uint64_t oop, const char* class_name) {
        if (oop == 0) { duk_push_null(c); return; }
        char buf[24]; std::snprintf(buf, sizeof(buf), "0x%llx",
                                      (unsigned long long)oop);
        duk_push_global_object(c);
        if (!duk_get_prop_string(c, -1, "Java")) {
            duk_pop_2(c); duk_push_string(c, buf); return;
        }
        if (!duk_get_prop_string(c, -1, "cast") || !duk_is_callable(c, -1)) {
            duk_pop_n(c, 3); duk_push_string(c, buf); return;
        }
        duk_push_string(c, buf);
        duk_push_string(c, class_name && class_name[0] ? class_name
                                                        : "java/lang/Object");
        if (duk_pcall(c, 2) != 0) {
            duk_pop_n(c, 3);                // error + Java + global
            duk_push_string(c, buf);
            return;
        }
        duk_remove(c, -2);                  // remove Java
        duk_remove(c, -2);                  // remove global; cast result on top
    };

    duk_idx_t last_ret_idx = -1;
    for (duk_size_t i = 0; i < n_fns; ++i) {
        duk_get_prop_index(c, fns_idx, (duk_uarridx_t)i);
        if (!duk_is_callable(c, -1)) { duk_pop(c); continue; }

        // Bind `this` for instance methods. The receiver oop sits one
        // slot beyond the argument area (under everything pushed for the
        // call). HotSpot operand stack convention: stack[1] = TOP of
        // operand stack at call time → last arg → walk down by total_slots
        // to reach the receiver.
        bool method_call = e->is_instance;
        if (method_call) {
            int recv_slot = total_slots + 1;
            uint64_t recv_oop = (recv_slot < 16) ? ctx->stack[recv_slot] : 0;
            push_cast_or_raw(recv_oop, e->holder_class.c_str());
        }

        // Push args. Operand-stack walk:
        //   stack[1] = TOP (last operand pushed = last arg).
        //   stack[total_slots] = bottom = first arg.
        // For 2-slot J/D: HotSpot stores the actual 64-bit value at
        // the TOP slot of the pair (closer to stack[1]); the slot below
        // is padding. So a 2-slot arg's value-bearing index is
        //   value_slot = (remaining - arg_slots + 1)
        // where `remaining` is the top-most slot index allocated to
        // this arg (= total_slots - cum_prior).
        int pushed = 0;
        int cum = 0;
        for (int a = 0; a < n_args; ++a) {
            char L = letters[a];
            int  arg_slots = (L == 'J' || L == 'D') ? 2 : 1;
            int  remaining = total_slots - cum;       // top-most slot for arg #a
            int  value_slot = remaining - arg_slots + 1;
            cum += arg_slots;
            if (value_slot < 1 || value_slot >= 16) {
                duk_push_undefined(c); ++pushed; continue;
            }
            uint64_t v = ctx->stack[value_slot];
            if (L == 'J') {
                char buf[24]; std::snprintf(buf, sizeof(buf), "0x%llx",
                                              (unsigned long long)v);
                duk_push_string(c, buf);
            } else if (L == 'D') {
                double d; std::memcpy(&d, &v, 8); duk_push_number(c, d);
            } else if (L == 'F') {
                uint32_t bits = (uint32_t)v; float f;
                std::memcpy(&f, &bits, 4); duk_push_number(c, (double)f);
            } else if (L == 'L' || L == '[') {
                push_cast_or_raw(v, arg_classes[a]);
            } else {
                duk_push_int(c, (int)(int32_t)(uint32_t)v);
            }
            ++pushed;
        }

        // Call the handler — duk_pcall_method binds `this` from below
        // the args; duk_pcall ignores `this`. Choice depends on hook flavor.
        int rc = method_call ? duk_pcall_method(c, pushed)
                              : duk_pcall(c, pushed);
        if (rc != 0) {
            const char* err = duk_safe_to_string(c, -1);
            agent_log("[hook] sync handler threw: %s\n", err ? err : "?");
            duk_pop(c);
            continue;
        }
        any_handler_ran = true;
        // Save last return as topmost stack slot — but we may push more
        // for subsequent handlers. Reset by popping then re-fetching.
        if (i + 1 == n_fns) {
            last_ret_idx = duk_get_top(c) - 1;
        } else {
            duk_pop(c);
        }
    }

    // Frida `.implementation = fn` semantics: original is ALWAYS replaced
    // by the handler. For void returns replace_rax is irrelevant; for
    // typed returns it's the (possibly-undefined→0) handler return.
    if (any_handler_ran) {
        ctx->skip_orig = 1;
        if (last_ret_idx >= 0) {
            ctx->replace_rax = js_to_rax(c, e->ret_letter);
        }
    }
    duk_set_top(c, top0);
}

void on_js_impl_hook(HookContext* ctx) {
    auto* e = g_js_impl.find(ctx->userdata);
    if (!e) return;

    // Sync mode: run JS handler now, populate skip_orig + replace_rax,
    // skip ring write — async drain has nothing to consume.
    if (e->sync_mode.load(std::memory_order_acquire)) {
        invoke_handler_sync(e, ctx);
        return;
    }

    // Async mode (default for `.attach` and observation paths):
    // Write snapshot into ring slot, then advance ring_head atomically.
    // Lock covers the memcpy so the reader never sees a torn slot.
    {
        std::lock_guard<std::mutex> g(e->regs_mu);
        uint64_t head = e->ring_head.load(std::memory_order_relaxed);
        auto& slot = e->ring[head % JsImplEntry::HOOK_RING_SIZE];
        std::memcpy(slot.regs,  ctx->regs,  sizeof(slot.regs));
        std::memcpy(slot.stack, ctx->stack, sizeof(slot.stack));
        slot.via = ctx->via;
        e->ring_head.store(head + 1, std::memory_order_release);
    }
    e->fired.fetch_add(1, std::memory_order_relaxed);
}

namespace {

VMMeta* current_vm(duk_context* ctx) {
    duk_push_global_stash(ctx);
    duk_get_prop_string(ctx, -1, "vm");
    auto* vm = static_cast<VMMeta*>(duk_to_pointer(ctx, -1));
    duk_pop_2(ctx);
    return vm;
}

JsHost* current_host(duk_context* ctx) {
    duk_push_global_stash(ctx);
    duk_get_prop_string(ctx, -1, "host");
    auto* h = static_cast<JsHost*>(duk_to_pointer(ctx, -1));
    duk_pop_2(ctx);
    return h;
}

// Helper called from string-reading bindings — lazily constructs the
// StringReader on first use (heavy: ClassWalker scan for java/lang/String).
StringReader* ensure_string_reader(JsHost* host) {
    if (host->sr_) return static_cast<StringReader*>(host->sr_);
    host->sr_ = new StringReader(host->vm_,
                                  static_cast<OopDecoder*>(host->dec_),
                                  static_cast<ZGCDecoder*>(host->zgc_));
    return static_cast<StringReader*>(host->sr_);
}

duk_ret_t js_log(duk_context* ctx) {
    duk_push_string(ctx, " ");
    duk_insert(ctx, 0);
    duk_join(ctx, duk_get_top(ctx) - 1);
    const char* s = duk_safe_to_string(ctx, -1);
    agent_log("[js] %s", s);
    return 0;
}

duk_ret_t js_findClass(duk_context* ctx) {
    const char* in_name = duk_require_string(ctx, 0);
    auto* vm = current_vm(ctx);
    if (!vm) { duk_push_null(ctx); return 1; }
    // Accept Frida-style dotted names ("java.lang.String") in addition to
    // JVM-internal slashed form ("java/lang/String"). HotSpot stores
    // names in slashed form, so we normalize the input once.
    std::string name(in_name);
    for (char& c : name) if (c == '.') c = '/';
    ClassWalker cw(vm);
    for (auto& k : cw.list()) {
        if (k.name == name) {
            duk_push_uint(ctx, duk_uint_t(k.address & 0xFFFFFFFF));
            duk_push_uint(ctx, duk_uint_t(k.address >> 32));
            // Pack into object {lo,hi} so JS can compare/print without
            // losing precision (duk_uint is u32).
            duk_idx_t obj = duk_push_object(ctx);
            duk_dup(ctx, -3); duk_put_prop_string(ctx, obj, "lo");
            duk_dup(ctx, -2); duk_put_prop_string(ctx, obj, "hi");
            // Also store full address as string for convenience.
            char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx",
                                          (unsigned long long)k.address);
            duk_push_string(ctx, buf); duk_put_prop_string(ctx, obj, "addr");
            duk_remove(ctx, -2); duk_remove(ctx, -2);  // remove lo,hi from stack
            return 1;
        }
    }
    duk_push_null(ctx);
    return 1;
}

uint64_t obj_addr(duk_context* ctx, duk_idx_t idx) {
    duk_get_prop_string(ctx, idx, "addr");
    const char* s = duk_get_string(ctx, -1);
    uint64_t v = s ? std::strtoull(s, nullptr, 0) : 0;
    duk_pop(ctx);
    return v;
}

duk_ret_t js_findMethod(duk_context* ctx) {
    uint64_t klass = obj_addr(ctx, 0);
    const char* name = duk_require_string(ctx, 1);
    auto* vm = current_vm(ctx);
    if (!vm || !klass) { duk_push_null(ctx); return 1; }
    auto m = find_method(vm, klass, name);
    if (!m) { duk_push_null(ctx); return 1; }
    duk_idx_t o = duk_push_object(ctx);
    char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx",
                                  (unsigned long long)m->address);
    duk_push_string(ctx, buf); duk_put_prop_string(ctx, o, "addr");
    duk_push_string(ctx, m->name.c_str()); duk_put_prop_string(ctx, o, "name");
    duk_push_string(ctx, m->signature.c_str()); duk_put_prop_string(ctx, o, "sig");
    duk_push_uint(ctx, m->code_size); duk_put_prop_string(ctx, o, "codeSize");
    return 1;
}

duk_ret_t js_hookCount(duk_context* ctx) {
    uint64_t klass = obj_addr(ctx, 0);
    const char* mname = duk_require_string(ctx, 1);
    uint64_t cookie = duk_require_uint(ctx, 2);
    auto* vm = current_vm(ctx);
    if (!vm || !klass) { duk_push_false(ctx); return 1; }
    auto m = find_method(vm, klass, mname);
    if (!m) { duk_push_false(ctx); return 1; }
    {
        std::lock_guard<std::mutex> g(g_hook_counters_mu);
        g_hook_counters[cookie].store(0);
    }
    install_callback_hook(vm, *m, &on_counting_hook, cookie);
    duk_push_true(ctx);
    return 1;
}

// Helper: returns the live Java mirror oop for a Klass* (ZGC-aware).
uint64_t mirror_for_klass(VMMeta* vm, ZGCDecoder* zgc, uint64_t klass) {
    auto* mf = vm->type("Klass")->field("_java_mirror");
    uint64_t raw = vm->reader()->read_u64(klass + mf->offset);
    uint64_t mirror = mf->type_string == "OopHandle"
        ? vm->reader()->read_u64(raw) : raw;
    return (zgc && zgc->is_active()) ? zgc->decode(mirror) : mirror;
}

// Marrow.readStaticRef(klass, fieldName) -> oop hex string or null.
// Returns the wide oop pointer; JS code can chain to other helpers.
duk_ret_t js_readStaticRef(duk_context* ctx) {
    uint64_t klass = obj_addr(ctx, 0);
    const char* fname = duk_require_string(ctx, 1);
    auto* vm = current_vm(ctx);
    auto* host = current_host(ctx);
    if (!vm || !klass || !host) { duk_push_null(ctx); return 1; }
    auto fr = find_field(vm, klass, fname);
    if (!fr) { duk_push_null(ctx); return 1; }

    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);
    uint64_t mirror = mirror_for_klass(vm, zgc, klass);
    uint64_t slot = mirror + fr->offset;
    uint64_t oop = 0;
    if (zgc->is_active())
        oop = zgc->decode(vm->reader()->read_u64(slot));
    else if (dec->oops_are_compressed())
        oop = dec->decode_oop(vm->reader()->read_u32(slot));
    else
        oop = vm->reader()->read_u64(slot);
    if (!oop) { duk_push_null(ctx); return 1; }
    char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx",
                                  (unsigned long long)oop);
    duk_push_string(ctx, buf);
    return 1;
}

// Marrow.readStaticString(klass, fieldName) -> string | null
// Decodes a String oop into JS text. Returns null when the String reader
// hasn't been initialized in this build.
duk_ret_t js_readStaticString(duk_context* ctx) {
    auto* host = current_host(ctx);
    if (!host || !host->sr_) { duk_push_null(ctx); return 1; }
    uint64_t klass = obj_addr(ctx, 0);
    const char* fname = duk_require_string(ctx, 1);
    auto* vm = current_vm(ctx);
    if (!vm || !klass) { duk_push_null(ctx); return 1; }
    auto fr = find_field(vm, klass, fname);
    if (!fr) { duk_push_null(ctx); return 1; }
    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);
    auto* sr  = static_cast<StringReader*>(host->sr_);
    uint64_t mirror = mirror_for_klass(vm, zgc, klass);
    uint64_t slot = mirror + fr->offset;
    uint64_t oop = 0;
    if (zgc->is_active())
        oop = zgc->decode(vm->reader()->read_u64(slot));
    else if (dec->oops_are_compressed())
        oop = dec->decode_oop(vm->reader()->read_u32(slot));
    else
        oop = vm->reader()->read_u64(slot);
    if (!oop) { duk_push_null(ctx); return 1; }
    std::string text = sr->read(oop);
    duk_push_lstring(ctx, text.data(), text.size());
    return 1;
}

// Marrow.writeStaticRef(klass, fieldName, srcKlass, srcFieldName) ->
// copy oop value from srcKlass.srcField -> klass.field.
duk_ret_t js_writeStaticRef(duk_context* ctx) {
    uint64_t kdst = obj_addr(ctx, 0);
    const char* fdst = duk_require_string(ctx, 1);
    uint64_t ksrc = obj_addr(ctx, 2);
    const char* fsrc = duk_require_string(ctx, 3);
    auto* vm = current_vm(ctx);
    auto* host = current_host(ctx);
    if (!vm || !host) { duk_push_false(ctx); return 1; }
    auto fdrec = find_field(vm, kdst, fdst);
    auto fsrec = find_field(vm, ksrc, fsrc);
    if (!fdrec || !fsrec) { duk_push_false(ctx); return 1; }
    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);
    uint64_t mdst = mirror_for_klass(vm, zgc, kdst);
    uint64_t msrc = mirror_for_klass(vm, zgc, ksrc);
    uint64_t dst_slot = mdst + fdrec->offset;
    uint64_t src_slot = msrc + fsrec->offset;
    if (zgc->is_active()) {
        uint64_t v = vm->reader()->read_u64(src_slot);
        vm->reader()->write(dst_slot, &v, 8);
    } else if (dec->oops_are_compressed()) {
        uint32_t n = vm->reader()->read_u32(src_slot);
        vm->reader()->write(dst_slot, &n, 4);
    } else {
        uint64_t w = vm->reader()->read_u64(src_slot);
        vm->reader()->write(dst_slot, &w, 8);
    }
    duk_push_true(ctx);
    return 1;
}

// Marrow.listMethods(klass) -> [{name, sig, codeSize}, ...]
duk_ret_t js_listMethods(duk_context* ctx) {
    uint64_t klass = obj_addr(ctx, 0);
    auto* vm = current_vm(ctx);
    duk_idx_t arr = duk_push_array(ctx);
    if (!vm || !klass) return 1;
    auto methods = methods_of(vm, klass);
    for (size_t i = 0; i < methods.size(); ++i) {
        duk_idx_t o = duk_push_object(ctx);
        duk_push_string(ctx, methods[i].name.c_str());
        duk_put_prop_string(ctx, o, "name");
        duk_push_string(ctx, methods[i].signature.c_str());
        duk_put_prop_string(ctx, o, "sig");
        duk_push_uint(ctx, methods[i].code_size);
        duk_put_prop_string(ctx, o, "codeSize");
        char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx",
                                      (unsigned long long)methods[i].address);
        duk_push_string(ctx, buf);
        duk_put_prop_string(ctx, o, "addr");
        duk_put_prop_index(ctx, arr, duk_uarridx_t(i));
    }
    return 1;
}

// Internal: install a callback hook by raw method address with a JS-side
// cookie. Does NOT touch bytecode (so original still runs). Use the
// _muteMethod variant to early-return before original.
// Cookie generator persists across Java.reload (which would otherwise
// reset Java._hookCounter and reuse cookies, colliding with stale C-side
// JsImplEntry entries from before the reload). Strictly increasing,
// process-lifetime unique.
static std::atomic<uint64_t> g_cookie_counter{0x80000000ULL};

static duk_ret_t js_nextCookie(duk_context* c) {
    uint64_t v = ++g_cookie_counter;
    duk_push_number(c, (double)v);
    return 1;
}

duk_ret_t js_installImplHook(duk_context* ctx) {
    uint64_t method = duk_require_uint(ctx, 0);   // Method* low32
    uint64_t method_hi = duk_require_uint(ctx, 1); // Method* hi32
    method |= (method_hi << 32);
    uint64_t cookie = duk_require_uint(ctx, 2);
    const char* label = duk_get_string_default(ctx, 3, "?");
    // Drop any existing g_js_impl entry for the same cookie — left over
    // from a previous install on the same method whose Java._impls
    // record was wiped (e.g. Java.reload). Avoids dispatch finding the
    // stale entry first when cookies happen to repeat.
    {
        std::lock_guard<std::mutex> g(g_js_impl.mu);
        g_js_impl.entries.erase(
            std::remove_if(g_js_impl.entries.begin(), g_js_impl.entries.end(),
                [&](const std::unique_ptr<JsImplEntry>& e) {
                    return e->cookie == cookie;
                }),
            g_js_impl.entries.end());
    }
    // New optional args (back-compat):
    //   arg 4 = sig string ("(II)I" etc.) — required for sync mode args/return
    //   arg 5 = sync_mode bool (default false)
    const char* sig_str = duk_get_string_default(ctx, 4, "()V");
    bool sync_mode      = duk_get_boolean_default(ctx, 5, false);
    // New: arg 6 = is_instance bool, arg 7 = holder class name.
    bool is_instance    = duk_get_boolean_default(ctx, 6, false);
    const char* holder  = duk_get_string_default(ctx, 7, "");
    auto* vm = current_vm(ctx);

    // Reconstitute MethodSnapshot enough for install_callback_hook.
    // We reuse find_method by walking InstanceKlass methods of the
    // method's holder. Cheap path: read ConstMethod -> Klass directly.
    // For MVP just use install_callback_hook with a synthesized snapshot
    // — entry-redirection only needs `address`.
    MethodSnapshot ms;
    ms.address = method;

    // Free any previous trampoline installed for this Method* address,
    // AND drop the corresponding JsImplEntry (else its 264KB ring +
    // cookie remain in g_js_impl.entries forever and hot install/
    // uninstall loops accumulate megabytes + linear-scan slowdown).
    uint64_t prev_cookie = 0;
    {
        std::lock_guard<std::mutex> lk(g_live_impl_mu);
        auto it = g_live_impl.find(method);
        if (it != g_live_impl.end()) {
            prev_cookie = it->second.cookie;
            try { it->second.hook.uninstall(); } catch (...) {}
            g_live_impl.erase(it);
        }
    }
    if (prev_cookie) {
        std::lock_guard<std::mutex> g(g_js_impl.mu);
        auto& v = g_js_impl.entries;
        v.erase(std::remove_if(v.begin(), v.end(),
            [prev_cookie](const std::unique_ptr<JsImplEntry>& e){
                return e && e->cookie == prev_cookie;
            }), v.end());
    }

    MethodHook hk = install_callback_hook_full(vm, ms, &on_js_impl_hook, cookie);
    int    jit_id = hk.jit_detour_id;
    uint64_t jit_va = hk.jit_detour_va;
    uint64_t orig_code = hk.original_code;
    int    vep_src = hk.jit_detour_vep_src;

    {
        std::lock_guard<std::mutex> lk(g_live_impl_mu);
        g_live_impl[method] = LiveImplHook{hk, cookie};
    }

    auto entry = std::make_unique<JsImplEntry>();
    entry->cookie = cookie;
    entry->method_label = label;
    entry->sig = sig_str;
    {
        // Extract return-type letter from sig (last char after ')').
        const char* s = sig_str;
        while (*s && *s != ')') ++s;
        if (*s == ')' && s[1]) entry->ret_letter = s[1];
        else entry->ret_letter = 'V';
    }
    entry->sync_mode.store(sync_mode, std::memory_order_release);
    entry->is_instance  = is_instance;
    entry->holder_class = holder;
    {
        std::lock_guard<std::mutex> g(g_js_impl.mu);
        g_js_impl.entries.push_back(std::move(entry));
    }
    duk_idx_t obj = duk_push_object(ctx);
    duk_push_true(ctx);
    duk_put_prop_string(ctx, obj, "ok");
    duk_push_int(ctx, jit_id);
    duk_put_prop_string(ctx, obj, "jitDetourId");
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)jit_va);
    duk_push_string(ctx, buf); duk_put_prop_string(ctx, obj, "jitDetourVa");
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)orig_code);
    duk_push_string(ctx, buf); duk_put_prop_string(ctx, obj, "origCode");
    duk_push_int(ctx, vep_src);
    duk_put_prop_string(ctx, obj, "vepSrc");
    return 1;
}

// Uninstall a previously-installed JS impl hook by Method* address.
// Restores original bytecode + entries via MethodHook::uninstall(). Drops
// the live-hook tracking entry. Returns true if found+removed, else false.
duk_ret_t js_uninstallImpl(duk_context* ctx) {
    uint64_t method = duk_require_uint(ctx, 0);
    uint64_t method_hi = duk_require_uint(ctx, 1);
    method |= (method_hi << 32);
    bool     removed = false;
    uint64_t cookie  = 0;
    {
        std::lock_guard<std::mutex> lk(g_live_impl_mu);
        auto it = g_live_impl.find(method);
        if (it != g_live_impl.end()) {
            cookie = it->second.cookie;
            try { it->second.hook.uninstall(); removed = true; } catch (...) {}
            g_live_impl.erase(it);
        }
    }
    // v0.5: also drop the JsImplEntry. Without this, every install/
    // uninstall cycle leaks a 264KB ring buffer + makes dispatch
    // slower (linear cookie lookup over an unbounded vector). 50
    // cycles ≈ 13MB leaked, plus the test hangs on JDK 17 because
    // dispatch lookup walks 50 entries per fire.
    if (cookie) {
        std::lock_guard<std::mutex> g(g_js_impl.mu);
        auto& v = g_js_impl.entries;
        v.erase(std::remove_if(v.begin(), v.end(),
            [cookie](const std::unique_ptr<JsImplEntry>& e){
                return e && e->cookie == cookie;
            }), v.end());
    }
    duk_push_boolean(ctx, removed);
    return 1;
}

// Drain pending fire-events for all registered impls. Returns array of
// {cookie, label, count} for entries that fired since last drain.
duk_ret_t js_drainImplEvents(duk_context* ctx) {
    duk_idx_t arr = duk_push_array(ctx);
    std::lock_guard<std::mutex> g(g_js_impl.mu);
    duk_uarridx_t i = 0;
    for (auto& e : g_js_impl.entries) {
        uint64_t fired = e->fired.load(std::memory_order_relaxed);
        uint64_t drained = e->drained.load(std::memory_order_relaxed);
        if (fired == drained) continue;
        uint64_t delta = fired - drained;
        e->drained.store(fired, std::memory_order_relaxed);
        duk_idx_t o = duk_push_object(ctx);
        duk_push_uint(ctx, duk_uint_t(e->cookie));
        duk_put_prop_string(ctx, o, "cookie");
        duk_push_string(ctx, e->method_label.c_str());
        duk_put_prop_string(ctx, o, "label");
        duk_push_number(ctx, double(delta));
        duk_put_prop_string(ctx, o, "delta");
        duk_push_number(ctx, double(fired));
        duk_put_prop_string(ctx, o, "total");
        duk_put_prop_index(ctx, arr, i++);
    }
    return 1;
}

// Replace method body with `return`/`ireturn`/`areturn` based on signature.
// The user's JS callback will fire (via implementation hook) and the
// original method body is skipped. For non-void methods, default value
// returned (0/null). Future: read `Marrow.setReturn(value)` from JS.
// Per-method bytecode backup: muteMethod overwrites bytes with an
// early-return; the originals are saved here so callOriginal can
// temporarily restore them. Indexed by Method* address.
static std::mutex g_mute_backup_mu;
static std::map<uint64_t, std::vector<uint8_t>> g_mute_backup;

duk_ret_t js_muteMethod(duk_context* ctx) {
    uint64_t method = duk_require_uint(ctx, 0);
    uint64_t method_hi = duk_require_uint(ctx, 1);
    method |= (method_hi << 32);
    auto* vm = current_vm(ctx);
    if (!vm) { duk_push_false(ctx); return 1; }

    // Read sig via ConstMethod
    auto* mt = vm->type("Method");
    auto* cmt = vm->type("ConstMethod");
    uint64_t cm = vm->reader()->read_u64(method + mt->field("_constMethod")->offset);
    uint64_t cp = vm->reader()->read_u64(cm + cmt->field("_constants")->offset);
    uint16_t sig_idx = vm->reader()->read_u16(cm + cmt->field("_signature_index")->offset);
    uint16_t code_size = vm->reader()->read_u16(cm + cmt->field("_code_size")->offset);
    uint64_t code_base = cm + cmt->size;

    // Save original bytecode the first time this method is muted.
    {
        std::lock_guard<std::mutex> lk(g_mute_backup_mu);
        if (g_mute_backup.find(method) == g_mute_backup.end()) {
            g_mute_backup[method] = vm->reader()->read(code_base, code_size);
        }
    }

    // Decode return-type char from CP[sig_idx] (Symbol*).
    auto* cp_t = vm->type("ConstantPool");
    uint64_t sym = vm->reader()->read_u64(cp + cp_t->size + size_t(sig_idx) * 8);
    auto* sym_t = vm->type("Symbol");
    uint16_t sym_len = vm->reader()->read_u16(sym + sym_t->field("_length")->offset);
    auto body = vm->reader()->read(sym + sym_t->field("_body")->offset, sym_len);
    char ret_char = 'V';
    for (size_t i = 0; i < body.size(); ++i)
        if (body[i] == ')' && i + 1 < body.size()) { ret_char = body[i + 1]; break; }

    // Pick a single-instruction return + nop-pad.
    std::vector<uint8_t> bc(code_size, 0x00);
    switch (ret_char) {
        case 'V': bc[0] = 0xB1; break;            // return
        case 'I': case 'B': case 'Z': case 'S': case 'C':
                  bc[0] = 0x03; bc[1] = 0xAC; break; // iconst_0; ireturn
        case 'J': bc[0] = 0x09; bc[1] = 0xAD; break; // lconst_0; lreturn
        case 'F': bc[0] = 0x0B; bc[1] = 0xAE; break; // fconst_0; freturn
        case 'D': bc[0] = 0x0E; bc[1] = 0xAF; break; // dconst_0; dreturn
        case 'L': case '[': bc[0] = 0x01; bc[1] = 0xB0; break; // aconst_null; areturn
        default: bc[0] = 0xB1; break;
    }
    vm->reader()->write(code_base, bc.data(), bc.size());
    // Null _code only — DON'T retarget entries (would clobber an
    // already-installed hook trampoline). The hook tramp tails to the
    // original interpreter entry which now interprets our new bytecode.
    uint64_t zero = 0;
    vm->reader()->write(method + mt->field("_code")->offset, &zero, 8);
    duk_push_true(ctx);
    return 1;
}

// JS: Marrow._unmuteMethod(method_lo, method_hi) -> true/false.
// Restores the original bytecode previously saved by _muteMethod. Used
// internally by handle.callOriginal to let the original method body
// run while a hook is installed. Caller must re-mute after invocation.
duk_ret_t js_unmuteMethod(duk_context* ctx) {
    uint64_t method = duk_require_uint(ctx, 0);
    uint64_t method_hi = duk_require_uint(ctx, 1);
    method |= (method_hi << 32);
    auto* vm = current_vm(ctx);
    if (!vm) { duk_push_false(ctx); return 1; }
    std::vector<uint8_t> bytes;
    {
        std::lock_guard<std::mutex> lk(g_mute_backup_mu);
        auto it = g_mute_backup.find(method);
        if (it == g_mute_backup.end()) { duk_push_false(ctx); return 1; }
        bytes = it->second;
    }
    auto* mt  = vm->type("Method");
    auto* cmt = vm->type("ConstMethod");
    uint64_t cm = vm->reader()->read_u64(method + mt->field("_constMethod")->offset);
    uint64_t code_base = cm + cmt->size;
    vm->reader()->write(code_base, bytes.data(), bytes.size());
    duk_push_true(ctx);
    return 1;
}

// Marrow._readInstanceField(oopHex, klass, fieldName) -> value or null.
// Reads one instance field from a live oop captured by a method hook.
// Primitive types push as Number; long/double/oop refs push as hex string.
duk_ret_t js_readInstanceField(duk_context* ctx) {
    const char* oop_hex = duk_require_string(ctx, 0);
    uint64_t klass = obj_addr(ctx, 1);
    const char* fname = duk_require_string(ctx, 2);
    auto* vm = current_vm(ctx);
    auto* host = current_host(ctx);
    if (!vm || !klass || !host) { duk_push_null(ctx); return 1; }

    uint64_t oop = std::strtoull(oop_hex, nullptr, 0);
    if (!oop) { duk_push_null(ctx); return 1; }

    auto fr = find_field(vm, klass, fname);
    if (!fr) { duk_push_null(ctx); return 1; }

    uint64_t slot = oop + uint64_t(fr->offset);
    const std::string& sig = fr->signature;
    char tag = sig.empty() ? '\0' : sig[0];

    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);

    try {
        if (tag == 'I') {
            duk_push_number(ctx, double(int32_t(vm->reader()->read_u32(slot))));
        } else if (tag == 'Z' || tag == 'B') {
            auto b = vm->reader()->read(slot, 1);
            duk_push_number(ctx, double(int8_t(b[0])));
        } else if (tag == 'S') {
            duk_push_number(ctx, double(int16_t(vm->reader()->read_u16(slot))));
        } else if (tag == 'C') {
            duk_push_number(ctx, double(vm->reader()->read_u16(slot)));
        } else if (tag == 'F') {
            uint32_t raw = vm->reader()->read_u32(slot);
            float f; std::memcpy(&f, &raw, 4);
            duk_push_number(ctx, double(f));
        } else if (tag == 'J' || tag == 'D') {
            uint64_t raw = vm->reader()->read_u64(slot);
            char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx",
                                         (unsigned long long)raw);
            duk_push_string(ctx, buf);
        } else {
            // oop reference (tag == 'L' or '[')
            uint64_t ref = 0;
            if (zgc->is_active())
                ref = zgc->decode(vm->reader()->read_u64(slot));
            else if (dec->oops_are_compressed())
                ref = dec->decode_oop(vm->reader()->read_u32(slot));
            else
                ref = vm->reader()->read_u64(slot);
            if (!ref) { duk_push_null(ctx); return 1; }
            char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx",
                                         (unsigned long long)ref);
            duk_push_string(ctx, buf);
        }
    } catch (...) { duk_push_null(ctx); return 1; }
    return 1;
}

// Marrow._writeInstanceField(oopHex, klass, fieldName, value) -> bool.
// Mirror of _readInstanceField for writes. `value` is taken either as a
// JS Number (primitive types) or a hex string "0x..." (J/D/oop refs).
duk_ret_t js_writeInstanceField(duk_context* ctx) {
    const char* oop_hex = duk_require_string(ctx, 0);
    uint64_t klass = obj_addr(ctx, 1);
    const char* fname = duk_require_string(ctx, 2);
    auto* vm = current_vm(ctx);
    auto* host = current_host(ctx);
    if (!vm || !klass || !host) { duk_push_false(ctx); return 1; }

    uint64_t oop = std::strtoull(oop_hex, nullptr, 0);
    if (!oop) { duk_push_false(ctx); return 1; }

    auto fr = find_field(vm, klass, fname);
    if (!fr) { duk_push_false(ctx); return 1; }

    uint64_t slot = oop + uint64_t(fr->offset);
    char tag = fr->signature.empty() ? '\0' : fr->signature[0];

    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);

    try {
        if (tag == 'I') {
            // Direct double→int32_t saturates at INT_MIN/MAX on out-of-range
            // values (MSVC). Route through int64_t so JS Numbers up to
            // 2^53 truncate cleanly to the low 32 bits we want.
            int64_t big = int64_t(duk_require_number(ctx, 3));
            int32_t v = int32_t(big);
            vm->reader()->write(slot, &v, 4);
        } else if (tag == 'Z' || tag == 'B') {
            int64_t big = int64_t(duk_require_number(ctx, 3));
            uint8_t v = uint8_t(big);
            vm->reader()->write(slot, &v, 1);
        } else if (tag == 'S' || tag == 'C') {
            int64_t big = int64_t(duk_require_number(ctx, 3));
            uint16_t v = uint16_t(big);
            vm->reader()->write(slot, &v, 2);
        } else if (tag == 'F') {
            float f = float(duk_require_number(ctx, 3));
            uint32_t raw; std::memcpy(&raw, &f, 4);
            vm->reader()->write(slot, &raw, 4);
        } else if (tag == 'J' || tag == 'D') {
            // Accept hex string "0x..." for full 64-bit precision.
            const char* s = duk_require_string(ctx, 3);
            uint64_t raw = std::strtoull(s, nullptr, 0);
            vm->reader()->write(slot, &raw, 8);
        } else {
            // oop reference: caller passes hex string of the wide oop;
            // we re-encode for compressed/ZGC modes when storing.
            const char* s = duk_require_string(ctx, 3);
            uint64_t wide = std::strtoull(s, nullptr, 0);
            if (wide != 0) {
                if ((wide & 7u) != 0 || wide < 0x10000ULL || wide >= 0x800000000000ULL) {
                    duk_push_false(ctx);
                    return 1;
                }
            }
            if (zgc->is_active()) {
                vm->reader()->write(slot, &wide, 8);
            } else if (dec->oops_are_compressed()) {
                uint32_t narrow = dec->encode_oop(wide);
                vm->reader()->write(slot, &narrow, 4);
            } else {
                vm->reader()->write(slot, &wide, 8);
            }
        }
    } catch (...) { duk_push_false(ctx); return 1; }
    duk_push_true(ctx);
    return 1;
}

// Marrow.findInstances(klass, limit) -> array of oop hex strings
// Brute-force scans every writable region for object headers whose
// narrow-klass matches `klass`. `limit=0` means unbounded.
// Marrow._fieldSlotAddr(klass, fieldName) -> "0x..." absolute address
// of the static-field slot in the class mirror. Used by Java.watchField.
duk_ret_t js_fieldSlotAddr(duk_context* ctx) {
    uint64_t klass = obj_addr(ctx, 0);
    const char* fname = duk_require_string(ctx, 1);
    auto* vm = current_vm(ctx);
    auto* host = current_host(ctx);
    if (!vm || !klass || !host) { duk_push_null(ctx); return 1; }
    auto fr = find_field(vm, klass, fname);
    if (!fr) { duk_push_null(ctx); return 1; }
    auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);
    uint64_t mirror = mirror_for_klass(vm, zgc, klass);
    uint64_t slot = mirror + fr->offset;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)slot);
    duk_push_string(ctx, buf);
    return 1;
}

// Marrow.watchAddr(addrLo, addrHi, length, slot) -> cookie
duk_ret_t js_watchAddr(duk_context* ctx) {
    uint64_t lo = duk_require_uint(ctx, 0);
    uint64_t hi = duk_require_uint(ctx, 1);
    int length = duk_get_int_default(ctx, 2, 4);
    int slot = duk_get_int_default(ctx, 3, 0);
    auto* vm = current_vm(ctx);
    if (!vm) { duk_push_uint(ctx, 0); return 1; }
    uint32_t cookie = agent_watch_addr(vm, (hi << 32) | lo, length, slot);
    duk_push_uint(ctx, cookie);
    return 1;
}

duk_ret_t js_unwatch(duk_context* ctx) {
    uint32_t cookie = duk_require_uint(ctx, 0);
    auto* vm = current_vm(ctx);
    duk_push_boolean(ctx, vm ? agent_unwatch(vm, cookie) : 0);
    return 1;
}

duk_ret_t js_drainWatches(duk_context* ctx) {
    duk_idx_t arr = duk_push_array(ctx);
    auto events = agent_drain_watches();
    for (size_t i = 0; i < events.size(); ++i) {
        duk_idx_t o = duk_push_object(ctx);
        duk_push_uint(ctx, events[i].cookie);
        duk_put_prop_string(ctx, o, "cookie");
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                       (unsigned long long)events[i].addr);
        duk_push_string(ctx, buf); duk_put_prop_string(ctx, o, "addr");
        std::snprintf(buf, sizeof(buf), "0x%llx",
                       (unsigned long long)events[i].fault_rip);
        duk_push_string(ctx, buf); duk_put_prop_string(ctx, o, "faultRip");
        duk_push_number(ctx, double(events[i].delta_count));
        duk_put_prop_string(ctx, o, "delta");
        duk_push_number(ctx, double(events[i].total_count));
        duk_put_prop_string(ctx, o, "total");
        duk_put_prop_index(ctx, arr, duk_uarridx_t(i));
    }
    return 1;
}

duk_ret_t js_findInstances(duk_context* ctx) {
    uint64_t klass = obj_addr(ctx, 0);
    duk_int_t limit = duk_get_int_default(ctx, 1, 0);
    auto* vm = current_vm(ctx);
    auto* host = current_host(ctx);
    duk_idx_t arr = duk_push_array(ctx);
    if (!vm || !klass || !host) return 1;
    auto* dec = static_cast<OopDecoder*>(host->dec_);
    auto found = find_instances_by_klass(vm, dec, klass, size_t(limit));
    for (size_t i = 0; i < found.size(); ++i) {
        char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx",
                                      (unsigned long long)found[i]);
        duk_push_string(ctx, buf);
        duk_put_prop_index(ctx, arr, duk_uarridx_t(i));
    }
    return 1;
}

// Marrow.checkJit(klass) -> [{name, sig, jitCompiled, codePtr}, ...]
// Inspects each method's `_code` field. Non-zero = JIT-compiled
// nmethod present. Useful to observe which methods got hot.
duk_ret_t js_checkJit(duk_context* ctx) {
    uint64_t klass = obj_addr(ctx, 0);
    auto* vm = current_vm(ctx);
    duk_idx_t arr = duk_push_array(ctx);
    if (!vm || !klass) return 1;
    auto* mt = vm->type("Method");
    size_t code_off = mt->field("_code")->offset;
    auto methods = methods_of(vm, klass);
    for (size_t i = 0; i < methods.size(); ++i) {
        uint64_t code = vm->reader()->read_u64(methods[i].address + code_off);
        duk_idx_t o = duk_push_object(ctx);
        duk_push_string(ctx, methods[i].name.c_str());
        duk_put_prop_string(ctx, o, "name");
        duk_push_string(ctx, methods[i].signature.c_str());
        duk_put_prop_string(ctx, o, "sig");
        duk_push_boolean(ctx, code != 0);
        duk_put_prop_string(ctx, o, "jitCompiled");
        char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx",
                                      (unsigned long long)code);
        duk_push_string(ctx, buf);
        duk_put_prop_string(ctx, o, "codePtr");
        duk_put_prop_index(ctx, arr, duk_uarridx_t(i));
    }
    return 1;
}

// Marrow.traceClass(klass) -> N (count of hooks installed)
// Installs a counting callback hook on EVERY method of the class.
// Each method gets its own cookie = (cookie_base + index). Caller can
// then call Marrow.readCount(cookie_base + i) per method.
duk_ret_t js_traceClass(duk_context* ctx) {
    uint64_t klass = obj_addr(ctx, 0);
    uint32_t cookie_base = duk_require_uint(ctx, 1);
    auto* vm = current_vm(ctx);
    if (!vm || !klass) { duk_push_uint(ctx, 0); return 1; }
    auto methods = methods_of(vm, klass);
    int n = 0;
    for (size_t i = 0; i < methods.size(); ++i) {
        uint64_t cookie = cookie_base + uint32_t(i);
        {
            std::lock_guard<std::mutex> g(g_hook_counters_mu);
            g_hook_counters[cookie].store(0);
        }
        try {
            install_callback_hook(vm, methods[i], &on_counting_hook, cookie);
            ++n;
        } catch (...) { /* skip method we can't hook */ }
    }
    duk_push_uint(ctx, duk_uint_t(n));
    return 1;
}

// Marrow.cloneClass(donorKlass, newName) -> { addr, symbol }
// Performs a Level-1 clone (insert into CLDG._klasses linked list).
duk_ret_t js_cloneClass(duk_context* ctx) {
    uint64_t donor = obj_addr(ctx, 0);
    const char* new_name = duk_require_string(ctx, 1);
    auto* vm = current_vm(ctx);
    if (!vm || !donor) { duk_push_null(ctx); return 1; }
    try {
        auto c = clone_klass(vm, donor, new_name);
        duk_idx_t o = duk_push_object(ctx);
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)c.clone_addr);
        duk_push_string(ctx, buf); duk_put_prop_string(ctx, o, "addr");
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)c.new_symbol);
        duk_push_string(ctx, buf); duk_put_prop_string(ctx, o, "symbol");
    } catch (const std::exception& e) {
        duk_push_error_object(ctx, DUK_ERR_ERROR, "%s", e.what());
        return duk_throw(ctx);
    }
    return 1;
}

// Marrow.cloneClassDeep(donorKlass, newName) -> { addr, symbol, methods[] }
// Level-2 clone: independent _methods array + Method/ConstMethod copies
// living in our own pages. Bytecode is per-clone, so .setReturn() on the
// new class no longer mutates the donor's body. Used by Java.registerClass
// to make every JS-defined class fully isolated.
duk_ret_t js_cloneClassDeep(duk_context* ctx) {
    uint64_t donor = obj_addr(ctx, 0);
    const char* new_name = duk_require_string(ctx, 1);
    auto* vm = current_vm(ctx);
    if (!vm || !donor) { duk_push_null(ctx); return 1; }
    try {
        auto d = clone_klass_deep(vm, donor, new_name, nullptr);
        duk_idx_t o = duk_push_object(ctx);
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      (unsigned long long)d.base.clone_addr);
        duk_push_string(ctx, buf); duk_put_prop_string(ctx, o, "addr");
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      (unsigned long long)d.base.new_symbol);
        duk_push_string(ctx, buf); duk_put_prop_string(ctx, o, "symbol");

        // Expose the cloned Method* addresses so the JS layer can wire
        // hooks / setReturn directly on independent copies.
        duk_idx_t methods = duk_push_array(ctx);
        for (size_t i = 0; i < d.new_methods.size(); ++i) {
            std::snprintf(buf, sizeof(buf), "0x%llx",
                          (unsigned long long)d.new_methods[i]);
            duk_push_string(ctx, buf);
            duk_put_prop_index(ctx, methods, duk_uarridx_t(i));
        }
        duk_put_prop_string(ctx, o, "methods");
    } catch (const std::exception& e) {
        duk_push_error_object(ctx, DUK_ERR_ERROR, "%s", e.what());
        return duk_throw(ctx);
    }
    return 1;
}

// Marrow.snapshotHeap(maxClasses=64) -> [{name, count}, ...]
// Brute-scans every writable region once, building a histogram of
// narrow-klass values. Then resolves narrow→Klass*→name for the most
// frequent buckets. Far cheaper than Java.choose × N classes.
duk_ret_t js_snapshotHeap(duk_context* ctx) {
    auto* vm = current_vm(ctx);
    auto* host = current_host(ctx);
    duk_idx_t arr = duk_push_array(ctx);
    if (!vm || !host) return 1;
    auto* dec = static_cast<OopDecoder*>(host->dec_);

    // Build narrow→klass map by walking every loaded Klass and computing
    // its narrow encoding once.
    ClassWalker cw(vm);
    auto klasses = cw.list();
    std::unordered_map<uint32_t, std::pair<uint64_t, std::string>> narrow_map;
    const auto& kp = dec->klass_params;
    for (auto& k : klasses) {
        uint32_t narrow;
        if (!kp.enabled()) narrow = uint32_t(k.address);
        else narrow = uint32_t((k.address - kp.base) >> kp.shift);
        narrow_map[narrow] = {k.address, k.name};
    }

    // Single sweep of writable regions, accumulating narrow-klass slot hits.
    std::unordered_map<uint64_t, uint64_t> counts; // klass_ptr → count
    Reader* r = vm->reader();
    constexpr size_t CHUNK = 4 * 1024 * 1024;
    for (auto& region : r->enumerate_regions(true)) {
        if (region.size < 64 * 1024) continue;
        for (uint64_t off = 0; off < region.size; off += CHUNK) {
            size_t part = size_t(std::min<uint64_t>(CHUNK, region.size - off));
            std::vector<uint8_t> buf;
            try { buf = r->read(region.base + off, part); }
            catch (...) { continue; }
            for (size_t pos = 0; pos + 12 <= buf.size(); pos += 8) {
                uint32_t narrow;
                std::memcpy(&narrow, buf.data() + pos + 8, 4);
                auto it = narrow_map.find(narrow);
                if (it != narrow_map.end())
                    counts[it->second.first]++;
            }
        }
    }

    // Sort descending by count, return top N.
    int max_classes = duk_get_int_default(ctx, 0, 64);
    std::vector<std::pair<uint64_t, uint64_t>> sorted(counts.begin(), counts.end());
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b){ return a.second > b.second; });
    duk_uarridx_t i = 0;
    for (auto& [klass, count] : sorted) {
        if (i >= duk_uarridx_t(max_classes)) break;
        duk_idx_t o = duk_push_object(ctx);
        // Look up name from our walker results
        std::string name;
        for (auto& k : klasses) if (k.address == klass) { name = k.name; break; }
        duk_push_string(ctx, name.c_str()); duk_put_prop_string(ctx, o, "name");
        duk_push_number(ctx, double(count)); duk_put_prop_string(ctx, o, "count");
        char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx",
                                      (unsigned long long)klass);
        duk_push_string(ctx, buf); duk_put_prop_string(ctx, o, "klass");
        duk_put_prop_index(ctx, arr, i++);
    }
    return 1;
}

// Marrow.classLoaders() -> array of {cld: addr, klassesCount}
// Walks CLDG and yields each ClassLoaderData entry.
duk_ret_t js_classLoaders(duk_context* ctx) {
    auto* vm = current_vm(ctx);
    duk_idx_t arr = duk_push_array(ctx);
    if (!vm) return 1;
    auto* cldg_t = vm->type("ClassLoaderDataGraph");
    auto* cld_t = vm->type("ClassLoaderData");
    if (!cldg_t || !cld_t) return 1;
    uint64_t cld = vm->reader()->read_u64(cldg_t->field("_head")->address);
    size_t klasses_off = cld_t->field("_klasses")->offset;
    size_t next_off = cld_t->field("_next")->offset;
    duk_uarridx_t i = 0;
    std::unordered_set<uint64_t> seen;
    while (cld && !seen.count(cld) && i < 256) {
        seen.insert(cld);
        // Count klasses in this CLD via _next_link chain.
        uint64_t k_head = vm->reader()->read_u64(cld + klasses_off);
        size_t k_count = 0;
        std::unordered_set<uint64_t> kseen;
        size_t nl_off = vm->type("Klass")->field("_next_link")->offset;
        uint64_t k = k_head;
        while (k && !kseen.count(k) && k_count < 10000) {
            kseen.insert(k); ++k_count;
            try { k = vm->reader()->read_u64(k + nl_off); }
            catch (...) { break; }
        }
        duk_idx_t o = duk_push_object(ctx);
        char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx",
                                      (unsigned long long)cld);
        duk_push_string(ctx, buf); duk_put_prop_string(ctx, o, "addr");
        duk_push_uint(ctx, duk_uint_t(k_count));
        duk_put_prop_string(ctx, o, "klasses");
        duk_put_prop_index(ctx, arr, i++);
        try { cld = vm->reader()->read_u64(cld + next_off); }
        catch (...) { break; }
    }
    return 1;
}

// Resolve the ring slot for a given eventIndex argument (stack index 1).
// Convention: -1 (or omitted) means "latest" (ring_head - 1).
// Returns nullptr when the ring_head is 0 (no fires yet) or when the
// requested event has been overwritten (eventIndex < ring_head - RING_SIZE).
static const JsImplEntry::HookSnapshot*
resolve_ring_slot(duk_context* ctx_, const JsImplEntry* e) {
    uint64_t head = e->ring_head.load(std::memory_order_acquire);
    if (head == 0) return nullptr;  // no fires yet
    int64_t idx = duk_get_int_default(ctx_, 1, -1);
    uint64_t target;
    if (idx < 0) {
        target = head - 1;  // latest
    } else {
        target = static_cast<uint64_t>(idx);
        // Check if it's been overwritten by the ring
        if (head > JsImplEntry::HOOK_RING_SIZE &&
            target < head - JsImplEntry::HOOK_RING_SIZE) {
            return nullptr;
        }
    }
    return &e->ring[target % JsImplEntry::HOOK_RING_SIZE];
}

// Marrow._lastRegs(cookie [, eventIndex]) -> array[16] of hex strings,
// indexed by AMD64 register number: RAX=0 .. R15=15.
// eventIndex: omit or -1 for latest; otherwise ring event index.
// Returns null if cookie unknown, no fires yet, or event overwritten.
duk_ret_t js_lastRegs(duk_context* ctx_) {
    uint64_t cookie = duk_require_uint(ctx_, 0);
    auto* e = g_js_impl.find(cookie);
    if (!e) { duk_push_null(ctx_); return 1; }
    std::lock_guard<std::mutex> g(e->regs_mu);
    const auto* slot = resolve_ring_slot(ctx_, e);
    if (!slot) { duk_push_null(ctx_); return 1; }
    duk_idx_t arr = duk_push_array(ctx_);
    for (int i = 0; i < 16; ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      (unsigned long long)slot->regs[i]);
        duk_push_string(ctx_, buf);
        duk_put_prop_index(ctx_, arr, duk_uarridx_t(i));
    }
    return 1;
}

// Marrow._lastStack(cookie [, eventIndex]) -> array[16] of hex strings
// (qwords starting at the original return address pushed by caller's CALL).
duk_ret_t js_lastStack(duk_context* ctx_) {
    uint64_t cookie = duk_require_uint(ctx_, 0);
    auto* e = g_js_impl.find(cookie);
    if (!e) { duk_push_null(ctx_); return 1; }
    std::lock_guard<std::mutex> g(e->regs_mu);
    const auto* slot = resolve_ring_slot(ctx_, e);
    if (!slot) { duk_push_null(ctx_); return 1; }
    duk_idx_t arr = duk_push_array(ctx_);
    for (int i = 0; i < 16; ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      (unsigned long long)slot->stack[i]);
        duk_push_string(ctx_, buf);
        duk_put_prop_index(ctx_, arr, duk_uarridx_t(i));
    }
    return 1;
}

// Marrow._lastVia(cookie [, eventIndex]) -> 0 (interpreter) | 1 (compiled)
// Tells the JS-side decoder whether to read args from the operand stack
// (interpreter) or from registers per HotSpot's Java calling convention.
duk_ret_t js_lastVia(duk_context* ctx_) {
    uint64_t cookie = duk_require_uint(ctx_, 0);
    auto* e = g_js_impl.find(cookie);
    if (!e) { duk_push_int(ctx_, -1); return 1; }
    std::lock_guard<std::mutex> g(e->regs_mu);
    const auto* slot = resolve_ring_slot(ctx_, e);
    if (!slot) { duk_push_int(ctx_, -1); return 1; }
    duk_push_uint(ctx_, duk_uint_t(slot->via));
    return 1;
}

// Marrow._ringHead(cookie) -> Number (ring_head monotonic write index).
// JS drain uses this to iterate ring[startIdx..head-1] per-event.
duk_ret_t js_ringHead(duk_context* ctx_) {
    uint64_t cookie = duk_require_uint(ctx_, 0);
    auto* e = g_js_impl.find(cookie);
    if (!e) { duk_push_int(ctx_, -1); return 1; }
    uint64_t head = e->ring_head.load(std::memory_order_acquire);
    // Duktape numbers are doubles; ring_head fits in 53-bit mantissa for
    // any realistic invocation count, so this cast is safe.
    duk_push_number(ctx_, static_cast<duk_double_t>(head));
    return 1;
}

// ---- Hotkey polling -------------------------------------------------
// Lazy-spawned background thread polls GetAsyncKeyState every 16 ms for
// registered VKs and bumps a press counter on each 0→1 transition. JS
// drains via Marrow._drainKeys() which returns {vk, presses_delta}.

struct HotkeyEntry {
    int vk;
    bool was_down{false};
    std::atomic<uint64_t> presses{0};
    std::atomic<uint64_t> drained{0};
};
struct HotkeyState {
    std::mutex mu;
    std::vector<std::unique_ptr<HotkeyEntry>> entries;
    std::atomic<bool> thread_running{false};
};
static HotkeyState g_hotkeys;

static void hotkey_poll_loop() {
    g_hotkeys.thread_running.store(true);
    while (g_hotkeys.thread_running.load()) {
        {
            std::lock_guard<std::mutex> g(g_hotkeys.mu);
            for (auto& e : g_hotkeys.entries) {
                bool now_down = (GetAsyncKeyState(e->vk) & 0x8000) != 0;
                if (now_down && !e->was_down) {
                    e->presses.fetch_add(1, std::memory_order_relaxed);
                }
                e->was_down = now_down;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
}

duk_ret_t js_registerKey(duk_context* ctx) {
    int vk = duk_require_int(ctx, 0);
    {
        std::lock_guard<std::mutex> g(g_hotkeys.mu);
        for (auto& e : g_hotkeys.entries) {
            if (e->vk == vk) { duk_push_true(ctx); return 1; }  // already registered
        }
        auto e = std::make_unique<HotkeyEntry>();
        e->vk = vk;
        g_hotkeys.entries.push_back(std::move(e));
    }
    if (!g_hotkeys.thread_running.exchange(true)) {
        std::thread(hotkey_poll_loop).detach();
    }
    duk_push_true(ctx);
    return 1;
}

duk_ret_t js_drainKeys(duk_context* ctx) {
    duk_idx_t arr = duk_push_array(ctx);
    std::lock_guard<std::mutex> g(g_hotkeys.mu);
    duk_uarridx_t i = 0;
    for (auto& e : g_hotkeys.entries) {
        uint64_t cur = e->presses.load(std::memory_order_relaxed);
        uint64_t prev = e->drained.load(std::memory_order_relaxed);
        if (cur == prev) continue;
        e->drained.store(cur, std::memory_order_relaxed);
        duk_idx_t o = duk_push_object(ctx);
        duk_push_int(ctx, e->vk);     duk_put_prop_string(ctx, o, "vk");
        duk_push_number(ctx, double(cur - prev));
                                       duk_put_prop_string(ctx, o, "delta");
        duk_push_number(ctx, double(cur));
                                       duk_put_prop_string(ctx, o, "total");
        duk_put_prop_index(ctx, arr, i++);
    }
    return 1;
}

duk_ret_t js_readCount(duk_context* ctx) {
    uint64_t cookie = duk_require_uint(ctx, 0);
    uint64_t n = 0;
    auto it = g_hook_counters.find(cookie);
    if (it != g_hook_counters.end())
        n = it->second.load(std::memory_order_relaxed);
    duk_push_number(ctx, double(n));
    return 1;
}

// Marrow._setReturnInt(method_lo, method_hi, value) -> bool
// Patches bytecode to push `value` then ireturn. Supports iconst_m1..5,
// bipush (i8), sipush (i16). Larger ints would need ldc + new CP entry.
duk_ret_t js_setReturnInt(duk_context* ctx) {
    uint64_t method = duk_require_uint(ctx, 0);
    uint64_t method_hi = duk_require_uint(ctx, 1);
    method |= (method_hi << 32);
    int32_t value = int32_t(duk_require_number(ctx, 2));
    auto* vm = current_vm(ctx);
    if (!vm) { duk_push_false(ctx); return 1; }

    auto* mt = vm->type("Method");
    auto* cmt = vm->type("ConstMethod");
    uint64_t cm = vm->reader()->read_u64(method + mt->field("_constMethod")->offset);
    uint16_t code_size = vm->reader()->read_u16(cm + cmt->field("_code_size")->offset);
    uint64_t code_base = cm + cmt->size;

    // Pick the shortest encoding that fits `value`, then check the
    // method's existing code_size is at least that many bytes. The old
    // hardcoded `< 4` rejected single-byte iconst_X + ireturn = 2 bytes.
    size_t needed = 0;
    if (value >= -1 && value <= 5) needed = 2;       // iconst_X; ireturn
    else if (value >= -128 && value <= 127) needed = 3;  // bipush; ireturn
    else if (value >= -32768 && value <= 32767) needed = 4; // sipush; ireturn
    else { duk_push_false(ctx); return 1; }

    if (code_size < needed) {
        // Original method's bytecode buffer is too small to hold the
        // override safely. We could pad with nops upstream, but to keep
        // this primitive tight we surface the failure to the caller.
        duk_push_false(ctx);
        return 1;
    }
    std::vector<uint8_t> bc(code_size, 0x00);
    if (value >= -1 && value <= 5) {
        bc[0] = uint8_t(0x03 + value);
        bc[1] = 0xAC;
    } else if (value >= -128 && value <= 127) {
        bc[0] = 0x10;
        bc[1] = uint8_t(value);
        bc[2] = 0xAC;
    } else {
        bc[0] = 0x11;
        bc[1] = uint8_t((value >> 8) & 0xFF);
        bc[2] = uint8_t(value & 0xFF);
        bc[3] = 0xAC;
    }
    vm->reader()->write(code_base, bc.data(), bc.size());
    uint64_t zero = 0;
    vm->reader()->write(method + mt->field("_code")->offset, &zero, 8);
    duk_push_true(ctx);
    return 1;
}

duk_ret_t js_reloadBootstrap(duk_context* c) {
    // k_java_bootstrap is declared at namespace scope below (line ~1267).
    // Reference it through the enclosing marrow namespace.
    // Uninstall every live hook trampoline before wiping JS state.
    {
        std::lock_guard<std::mutex> lk(g_live_impl_mu);
        for (auto& kv : g_live_impl) {
            try { kv.second.hook.uninstall(); } catch (...) {}
        }
        g_live_impl.clear();
    }
    // Re-evaluate bootstrap — redefines Java = { ... } from scratch,
    // which resets _impls, _classFieldsCache, _hookCounter, etc.
    int rc = duk_peval_string(c, k_java_bootstrap);
    if (rc != 0) {
        const char* err = duk_safe_to_string(c, -1);
        duk_pop(c);
        duk_push_string(c, err ? err : "bootstrap eval failed");
        return 1;
    }
    duk_pop(c);  // result
    duk_push_true(c);
    return 1;
}

// Marrow._setReturnNull(method_lo, method_hi) -> bool
duk_ret_t js_setReturnNull(duk_context* ctx) {
    uint64_t method = duk_require_uint(ctx, 0);
    uint64_t method_hi = duk_require_uint(ctx, 1);
    method |= (method_hi << 32);
    auto* vm = current_vm(ctx);
    if (!vm) { duk_push_false(ctx); return 1; }
    auto* mt = vm->type("Method");
    auto* cmt = vm->type("ConstMethod");
    uint64_t cm = vm->reader()->read_u64(method + mt->field("_constMethod")->offset);
    uint16_t code_size = vm->reader()->read_u16(cm + cmt->field("_code_size")->offset);
    uint64_t code_base = cm + cmt->size;
    if (code_size < 2) { duk_push_false(ctx); return 1; }
    std::vector<uint8_t> bc(code_size, 0x00);
    bc[0] = 0x01; bc[1] = 0xB0;  // aconst_null; areturn
    vm->reader()->write(code_base, bc.data(), bc.size());
    uint64_t zero = 0;
    vm->reader()->write(method + mt->field("_code")->offset, &zero, 8);
    duk_push_true(ctx);
    return 1;
}

void install_bindings(duk_context* ctx) {
    duk_push_global_object(ctx);

    // print()
    duk_push_c_function(ctx, js_log, DUK_VARARGS);
    duk_put_prop_string(ctx, -2, "print");

    // Marrow namespace
    duk_idx_t ns = duk_push_object(ctx);
    duk_push_c_function(ctx, js_log, DUK_VARARGS);
    duk_put_prop_string(ctx, ns, "log");
    duk_push_c_function(ctx, js_findClass, 1);
    duk_put_prop_string(ctx, ns, "findClass");
    duk_push_c_function(ctx, js_findMethod, 2);
    duk_put_prop_string(ctx, ns, "findMethod");
    duk_push_c_function(ctx, js_hookCount, 3);
    duk_put_prop_string(ctx, ns, "hookCount");
    duk_push_c_function(ctx, js_readCount, 1);
    duk_put_prop_string(ctx, ns, "readCount");
    duk_push_c_function(ctx, js_readStaticString, 2);
    duk_put_prop_string(ctx, ns, "readStaticString");
    duk_push_c_function(ctx, js_readStaticRef, 2);
    duk_put_prop_string(ctx, ns, "readStaticRef");
    duk_push_c_function(ctx, js_writeStaticRef, 4);
    duk_put_prop_string(ctx, ns, "writeStaticRef");
    duk_push_c_function(ctx, js_listMethods, 1);
    duk_put_prop_string(ctx, ns, "listMethods");
    duk_push_c_function(ctx, js_installImplHook, DUK_VARARGS);
    duk_put_prop_string(ctx, ns, "_installImpl");
    duk_push_c_function(ctx, js_nextCookie, 0);
    duk_put_prop_string(ctx, ns, "_nextCookie");
    duk_push_c_function(ctx, js_uninstallImpl, 2);
    duk_put_prop_string(ctx, ns, "_uninstallImpl");
    duk_push_c_function(ctx, js_drainImplEvents, 0);
    duk_put_prop_string(ctx, ns, "_drainImplEvents");
    duk_push_c_function(ctx, js_lastRegs, 2);
    duk_put_prop_string(ctx, ns, "_lastRegs");
    duk_push_c_function(ctx, js_lastStack, 2);
    duk_put_prop_string(ctx, ns, "_lastStack");
    duk_push_c_function(ctx, js_lastVia, 2);
    duk_put_prop_string(ctx, ns, "_lastVia");
    duk_push_c_function(ctx, js_ringHead, 1);
    duk_put_prop_string(ctx, ns, "_ringHead");
    duk_push_c_function(ctx, js_registerKey, 1);
    duk_put_prop_string(ctx, ns, "_registerKey");
    duk_push_c_function(ctx, js_drainKeys, 0);
    duk_put_prop_string(ctx, ns, "_drainKeys");
    duk_push_c_function(ctx, js_muteMethod, 2);
    duk_put_prop_string(ctx, ns, "_muteMethod");
    duk_push_c_function(ctx, js_unmuteMethod, 2);
    duk_put_prop_string(ctx, ns, "_unmuteMethod");
    duk_push_c_function(ctx, js_findInstances, 2);
    duk_put_prop_string(ctx, ns, "findInstances");
    duk_push_c_function(ctx, js_classLoaders, 0);
    duk_put_prop_string(ctx, ns, "classLoaders");
    duk_push_c_function(ctx, js_cloneClass, 2);
    duk_put_prop_string(ctx, ns, "cloneClass");
    duk_push_c_function(ctx, js_cloneClassDeep, 2);
    duk_put_prop_string(ctx, ns, "cloneClassDeep");
    duk_push_c_function(ctx, js_snapshotHeap, 1);
    duk_put_prop_string(ctx, ns, "snapshotHeap");
    duk_push_c_function(ctx, js_checkJit, 1);
    duk_put_prop_string(ctx, ns, "checkJit");
    duk_push_c_function(ctx, js_traceClass, 2);
    duk_put_prop_string(ctx, ns, "_traceClass");
    duk_push_c_function(ctx, js_watchAddr, 4);
    duk_put_prop_string(ctx, ns, "watchAddr");
    duk_push_c_function(ctx, js_unwatch, 1);
    duk_put_prop_string(ctx, ns, "unwatch");
    duk_push_c_function(ctx, js_drainWatches, 0);
    duk_put_prop_string(ctx, ns, "drainWatches");
    duk_push_c_function(ctx, js_fieldSlotAddr, 2);
    duk_put_prop_string(ctx, ns, "_fieldSlotAddr");
    duk_push_c_function(ctx, js_readInstanceField, 3);
    duk_put_prop_string(ctx, ns, "_readInstanceField");
    duk_push_c_function(ctx, js_writeInstanceField, 4);
    duk_put_prop_string(ctx, ns, "_writeInstanceField");
    duk_push_c_function(ctx, js_setReturnInt, 3);
    duk_put_prop_string(ctx, ns, "_setReturnInt");
    duk_push_c_function(ctx, js_setReturnNull, 2);
    duk_put_prop_string(ctx, ns, "_setReturnNull");
    duk_push_c_function(ctx, js_reloadBootstrap, 0);
    duk_put_prop_string(ctx, ns, "_reloadBootstrap");

    // Per-module registrars (each lives in its own src/agent_*.cpp).
    register_invoke_bindings(ctx, ns);
    register_freeze_bindings(ctx, ns);
    register_arrays_bindings(ctx, ns);
    register_mouse_bindings(ctx, ns);
    register_bytecode_bindings(ctx, ns);
    register_jit_force_bindings(ctx, ns);
    register_toast_bindings(ctx, ns);
    register_string_bindings(ctx, ns);
    // register_jni_bindings removed: JNI violates project philosophy.
    register_overlay_bindings(ctx, ns);
    register_window_bindings(ctx, ns);
    register_cursor_bindings(ctx, ns);
    register_heapfilter_bindings(ctx, ns);
    register_disasm_bindings(ctx, ns);
    register_symtab_bindings(ctx, ns);
    register_events_bindings(ctx, ns);
    register_inlhook_bindings(ctx, ns);
    register_nmdump_bindings(ctx, ns);
    register_stackwalk_bindings(ctx, ns);
    register_cpdump_bindings(ctx, ns);
    register_memlog_bindings(ctx, ns);
    register_klassinfo_bindings(ctx, ns);
    register_alloc_bindings(ctx, ns);
    register_modulesenum_bindings(ctx, ns);
    register_callnative_bindings(ctx, ns);
    register_diagnose_bindings(ctx, ns);
    register_codecache_bindings(ctx, ns);
    register_klassfields_bindings(ctx, ns);
    register_threads_bindings(ctx, ns);
    register_mhdump_bindings(ctx, ns);
    register_hwwatch_ext_bindings(ctx, ns);
    register_opstack_bindings(ctx, ns);
    register_monitors_bindings(ctx, ns);
    register_inlhook_cb_bindings(ctx, ns);
    register_explorer_bindings(ctx, ns);
    register_masstracer_bindings(ctx, ns);
    register_backtrace_bindings(ctx, ns);
    register_hooklist_bindings(ctx, ns);
    register_threadname_bindings(ctx, ns);
    register_sysinfo_bindings(ctx, ns);
    register_gcmap_bindings(ctx, ns);
    register_heapscan2_bindings(ctx, ns);
    register_memscan_bindings(ctx, ns);
    register_redefine_bindings(ctx, ns);
    register_writemem_bindings(ctx, ns);
    register_methsym_bindings(ctx, ns);
    register_memprotect_bindings(ctx, ns);
    register_javacall_bindings(ctx, ns);
    register_pattern_bindings(ctx, ns);
    register_pattern_registry_bindings(ctx, ns);
    register_xref_bindings(ctx, ns);

    duk_put_prop_string(ctx, -2, "Marrow");

    duk_pop(ctx); // global
}

} // anon

// Single global pointer published by bind(). Sync hook dispatch uses it to
// reach the JS context (it lives on a different thread than the IPC
// dispatcher). All access through `g_js_host->mu()`.
JsHost* g_js_host = nullptr;

JsHost::JsHost() {
    ctx_ = duk_create_heap_default();
    install_bindings(static_cast<duk_context*>(ctx_));
}

JsHost::~JsHost() {
    if (ctx_) duk_destroy_heap(static_cast<duk_context*>(ctx_));
    if (g_js_host == this) g_js_host = nullptr;
    // dec_/zgc_/sr_ are externally owned (worker thread) — don't delete.
}

// Bootstrap script that defines the high-level Java.use(...) facade in
// terms of the low-level Marrow.* bindings exposed from C++.
// Bootstrap text lives in agent_bootstrap.cpp — extern reference here.
// We're already inside `namespace marrow` at this point.
extern const char* k_java_bootstrap;

void JsHost::bind(VMMeta* vm) {
    std::lock_guard<std::recursive_mutex> g(mu_);
    vm_ = vm;
    auto* c = static_cast<duk_context*>(ctx_);
    duk_push_global_stash(c);
    duk_push_pointer(c, vm);   duk_put_prop_string(c, -2, "vm");
    duk_push_pointer(c, this); duk_put_prop_string(c, -2, "host");
    duk_pop(c);
    g_js_host = this;
    // Bootstrap the Frida-style facade. Errors are surfaced via agent_log.
    int rc = duk_peval_string(c, k_java_bootstrap);
    if (rc != 0) {
        const char* err = duk_safe_to_string(c, -1);
        agent_log("Java bootstrap eval failed: %s", err);
    }
    duk_pop(c);
}

int JsHost::eval(const char* script, std::string& out) {
    std::lock_guard<std::recursive_mutex> g(mu_);
    auto* c = static_cast<duk_context*>(ctx_);
    int rc = duk_peval_string(c, script);
    if (rc != 0) {
        out = duk_safe_to_string(c, -1);
        duk_pop(c);
        return rc;
    }
    out = duk_safe_to_string(c, -1);
    duk_pop(c);
    return 0;
}

} // namespace marrow
