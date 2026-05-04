#include "agent_modules.hpp"
#include "duktape.h"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

namespace marrow {

namespace {

struct MemEntry {
    uint64_t addr;
    uint32_t size;
    uint64_t ts_ms;
    char source[64];
};
constexpr size_t MEMLOG_SIZE = 256;
struct MemLog {
    std::mutex mu;
    MemEntry ring[MEMLOG_SIZE];
    std::atomic<uint64_t> next_seq{1};   // 1 = first slot
};
static MemLog g_memlog;

uint64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void memlog_record_impl(uint64_t addr, uint32_t size, const char* source) {
    std::lock_guard<std::mutex> g(g_memlog.mu);
    uint64_t seq = g_memlog.next_seq.fetch_add(1, std::memory_order_relaxed);
    auto& slot = g_memlog.ring[(seq - 1) % MEMLOG_SIZE];
    slot.addr = addr;
    slot.size = size;
    slot.ts_ms = now_ms();
    if (source) {
        std::strncpy(slot.source, source, sizeof(slot.source) - 1);
        slot.source[sizeof(slot.source) - 1] = 0;
    } else {
        slot.source[0] = 0;
    }
}

duk_ret_t js_memlogPush(duk_context* c) {
    const char* addr_hex = duk_require_string(c, 0);
    uint32_t size = (uint32_t)duk_require_int(c, 1);
    const char* source = duk_get_string_default(c, 2, "");
    uint64_t addr = strtoull(addr_hex, nullptr, 0);
    memlog_record_impl(addr, size, source);
    duk_push_true(c);
    return 1;
}

duk_ret_t js_memlogList(duk_context* c) {
    int max_n = duk_get_int_default(c, 0, 64);
    if (max_n <= 0 || max_n > (int)MEMLOG_SIZE) max_n = (int)MEMLOG_SIZE;
    duk_idx_t arr = duk_push_array(c);
    std::lock_guard<std::mutex> g(g_memlog.mu);
    uint64_t head = g_memlog.next_seq.load(std::memory_order_relaxed) - 1;
    if (head == 0) return 1;
    uint64_t start = head > (uint64_t)max_n ? head - max_n + 1 : 1;
    duk_uarridx_t out_i = 0;
    for (uint64_t s = head; s >= start && s > 0; --s) {  // most-recent first
        auto& slot = g_memlog.ring[(s - 1) % MEMLOG_SIZE];
        duk_idx_t o = duk_push_object(c);
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)slot.addr);
        duk_push_string(c, buf); duk_put_prop_string(c, o, "addr");
        duk_push_uint(c, slot.size); duk_put_prop_string(c, o, "size");
        duk_push_number(c, (double)slot.ts_ms); duk_put_prop_string(c, o, "ts");
        duk_push_string(c, slot.source); duk_put_prop_string(c, o, "source");
        duk_put_prop_index(c, arr, out_i++);
        if (s == 0) break;
    }
    return 1;
}

duk_ret_t js_memlogClear(duk_context* c) {
    std::lock_guard<std::mutex> g(g_memlog.mu);
    g_memlog.next_seq.store(1, std::memory_order_relaxed);
    duk_push_true(c);
    return 1;
}

} // anon

// Public extern so other modules can record without going through JS.
void memlog_record(uint64_t addr, uint32_t size, const char* source) {
    memlog_record_impl(addr, size, source);
}

void register_memlog_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_memlogPush, 3);
    duk_put_prop_string(ctx, ns_idx, "_memlogPush");
    duk_push_c_function(ctx, js_memlogList, 1);
    duk_put_prop_string(ctx, ns_idx, "_memlogList");
    duk_push_c_function(ctx, js_memlogClear, 0);
    duk_put_prop_string(ctx, ns_idx, "_memlogClear");
}

} // namespace marrow
