// agent_alloc.cpp — sampled TLAB allocation tracker.
//
// Poll-based: every 5 ms walk JavaThreads via ThreadWalker, read each
// thread's TLAB _top. A bump means new objects were allocated in [old, new).
// We stride through that region in 16-byte steps (minimum HotSpot object
// size) reading the narrow klass word at offset +8, then accumulate a
// per-klass histogram. Object sizes are NOT decoded — the 16-byte stride
// is a first-order approximation; larger objects will be over-counted or
// produce phantom entries. This is intentional for a low-overhead sampler.

#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "agent_js.hpp"
#include "oop_reader.hpp"
#include "vm_meta.hpp"
#include "walker.hpp"
#include "duktape.h"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <algorithm>

namespace marrow {

namespace {

// ---------------------------------------------------------------------------
// Resolve TLAB _top for a given JavaThread pointer. Mirrors the offset chain
// used by TLABAllocator: thread + _tlab offset + _top offset.
// ---------------------------------------------------------------------------
uint64_t read_tlab_top(VMMeta* vm, uint64_t thread_ptr,
                       size_t off_thread_tlab, size_t off_tlab_top) {
    return vm->reader()->read_u64(thread_ptr + off_thread_tlab + off_tlab_top);
}

// ---------------------------------------------------------------------------
// Global allocation tracking state.
// ---------------------------------------------------------------------------
struct AllocState {
    std::mutex mu;
    std::atomic<bool> running{false};
    std::atomic<bool> stop_requested{false};
    std::unordered_map<uint64_t, uint64_t> histogram;     // klass* -> count
    std::unordered_map<uint64_t, std::string> klass_names; // klass* -> name (cached)
    std::unordered_map<uint64_t, uint64_t> last_top;       // thread* -> last TLAB top
};
static AllocState g_alloc;

// ---------------------------------------------------------------------------
// Background poll loop.
// ---------------------------------------------------------------------------
void alloc_poll_loop(VMMeta* vm, OopDecoder* dec) {
    // Resolve offsets once up front — same logic as TLABAllocator constructor.
    const TypeInfo* thread_t = vm->type("Thread");
    const TypeInfo* tlab_t   = vm->type("ThreadLocalAllocBuffer");
    if (!thread_t || !tlab_t) {
        g_alloc.running.store(false);
        return;
    }
    const FieldInfo* tlab_f = thread_t->field("_tlab");
    const FieldInfo* top_f  = tlab_t->field("_top");
    if (!tlab_f || !top_f) {
        g_alloc.running.store(false);
        return;
    }
    const size_t off_thread_tlab = tlab_f->offset;
    const size_t off_tlab_top    = top_f->offset;

    const bool compressed_klass  = dec->compressed_klass();
    const auto& kp               = dec->klass_params;

    int idle_cycles = 0;
    int sleep_ms = 5;

    while (!g_alloc.stop_requested.load()) {
        bool any_alloc_this_cycle = false;
        try {
            ThreadWalker tw(vm);
            for (const ThreadSnapshot& ts : tw.list()) {
                const uint64_t tptr = ts.address;
                if (!tptr) continue;

                uint64_t top = 0;
                try {
                    top = read_tlab_top(vm, tptr, off_thread_tlab, off_tlab_top);
                } catch (...) { continue; }
                if (!top) continue;

                uint64_t last = 0;
                {
                    std::lock_guard<std::mutex> g(g_alloc.mu);
                    auto it = g_alloc.last_top.find(tptr);
                    last = (it != g_alloc.last_top.end()) ? it->second : top;
                    g_alloc.last_top[tptr] = top;
                }

                // Sanity: bump must be forward and < 16 MiB to ignore resets.
                if (!last || top <= last || (top - last) >= (1u << 24)) continue;

                // Walk newly allocated region in 16-byte strides.
                uint64_t pos = last;
                int safety = 0;
                while (pos + 16 <= top && safety++ < 1024) {
                    uint64_t klass = 0;
                    try {
                        if (compressed_klass) {
                            uint32_t narrow = vm->reader()->read_u32(pos + 8);
                            if (!narrow) break;
                            klass = kp.enabled()
                                ? (kp.base + (static_cast<uint64_t>(narrow) << kp.shift))
                                : static_cast<uint64_t>(narrow);
                        } else {
                            klass = vm->reader()->read_u64(pos + 8);
                        }
                    } catch (...) { break; }
                    if (!klass) break;
                    // Plausibility: klass must be 8-aligned and in metaspace
                    // range. Without this, narrow-klass garbage produces
                    // bogus pointers that crash the histogram-stat path.
                    if ((klass & 7u) != 0 || klass < 0x10000ULL ||
                        klass >= 0x800000000000ULL) break;

                    {
                        std::lock_guard<std::mutex> g(g_alloc.mu);
                        g_alloc.histogram[klass]++;
                    }
                    any_alloc_this_cycle = true;
                    pos += 16;
                }
            }
        } catch (...) { /* absorb one bad cycle */ }

        if (any_alloc_this_cycle) {
            idle_cycles = 0;
            sleep_ms = 5;
        } else {
            ++idle_cycles;
            if (idle_cycles >= 10) sleep_ms = 100;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    }
    g_alloc.running.store(false);
}

// ---------------------------------------------------------------------------
// JS bindings.
// ---------------------------------------------------------------------------

duk_ret_t js_allocStart(duk_context* c) {
    auto* vm   = current_vm(c);
    auto* host = current_host(c);
    if (!vm || !host) { duk_push_false(c); return 1; }
    if (g_alloc.running.exchange(true)) { duk_push_false(c); return 1; }
    g_alloc.stop_requested.store(false);
    auto* dec = static_cast<OopDecoder*>(host->dec_);
    std::thread([vm, dec]{ alloc_poll_loop(vm, dec); }).detach();
    duk_push_true(c);
    return 1;
}

duk_ret_t js_allocStop(duk_context* c) {
    g_alloc.stop_requested.store(true);
    duk_push_true(c);
    return 1;
}

duk_ret_t js_allocStats(duk_context* c) {
    const int max_n = duk_get_int_default(c, 0, 32);
    auto* vm = current_vm(c);
    duk_idx_t arr = duk_push_array(c);
    if (!vm) return 1;

    std::vector<std::pair<uint64_t, uint64_t>> sorted;
    {
        std::lock_guard<std::mutex> g(g_alloc.mu);
        sorted.reserve(g_alloc.histogram.size());
        for (auto& [k, v] : g_alloc.histogram) sorted.push_back({k, v});
    }
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b){ return a.second > b.second; });

    duk_uarridx_t i = 0;
    for (auto& [klass, count] : sorted) {
        if (static_cast<int>(i) >= max_n) break;

        // Klass-name resolution requires dereferencing a klass pointer
        // captured during a TLAB sample. The pointer may be garbage if
        // sampling raced with TLAB refill, OR may have been freed via
        // class-unloading by the GC service thread. Either way → crash.
        // SKIP live name deref. Caller can match klass hex against
        // ClassWalker output to map to names safely.
        std::string name;
        {
            std::lock_guard<std::mutex> g(g_alloc.mu);
            auto it = g_alloc.klass_names.find(klass);
            if (it != g_alloc.klass_names.end()) name = it->second;
        }

        duk_idx_t o = duk_push_object(c);
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(klass));
        duk_push_string(c, buf);           duk_put_prop_string(c, o, "klass");
        duk_push_string(c, name.c_str());  duk_put_prop_string(c, o, "name");
        duk_push_number(c, static_cast<double>(count));
                                           duk_put_prop_string(c, o, "count");
        duk_put_prop_index(c, arr, i++);
    }
    return 1;
}

duk_ret_t js_allocReset(duk_context* c) {
    std::lock_guard<std::mutex> g(g_alloc.mu);
    g_alloc.histogram.clear();
    g_alloc.last_top.clear();
    // klass_names intentionally kept — names don't change across resets.
    duk_push_true(c);
    return 1;
}

} // anonymous namespace

void register_alloc_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_allocStart, 0);
    duk_put_prop_string(ctx, ns_idx, "_allocStart");
    duk_push_c_function(ctx, js_allocStop, 0);
    duk_put_prop_string(ctx, ns_idx, "_allocStop");
    duk_push_c_function(ctx, js_allocStats, 1);
    duk_put_prop_string(ctx, ns_idx, "_allocStats");
    duk_push_c_function(ctx, js_allocReset, 0);
    duk_put_prop_string(ctx, ns_idx, "_allocReset");
}

} // namespace marrow
