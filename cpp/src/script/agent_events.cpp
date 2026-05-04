#include "agent_modules.hpp"
#include "duktape.h"
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>

namespace marrow {
namespace {

struct EventEntry {
    uint64_t seq{0};
    uint64_t ts_ms{0};
    char tag[33] = {};
    char body[257] = {};
};

constexpr size_t RING_SIZE = 256;

struct EventRing {
    std::mutex mu;
    EventEntry ring[RING_SIZE];
    std::atomic<uint64_t> next_seq{1};   // 0 means "never written"
    std::atomic<uint64_t> last_drained{0};
};
static EventRing g_events;

uint64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

duk_ret_t js_event(duk_context* c) {
    const char* tag  = duk_get_string_default(c, 0, "");
    const char* body = duk_get_string_default(c, 1, "");
    std::lock_guard<std::mutex> g(g_events.mu);
    uint64_t seq = g_events.next_seq.fetch_add(1, std::memory_order_relaxed);
    auto& slot = g_events.ring[seq % RING_SIZE];
    slot.seq = seq;
    slot.ts_ms = now_ms();
    std::strncpy(slot.tag, tag, sizeof(slot.tag) - 1);
    slot.tag[sizeof(slot.tag) - 1] = 0;
    std::strncpy(slot.body, body, sizeof(slot.body) - 1);
    slot.body[sizeof(slot.body) - 1] = 0;
    duk_push_true(c);
    return 1;
}

duk_ret_t js_eventDrain(duk_context* c) {
    int max_n = duk_get_int_default(c, 0, 64);
    if (max_n <= 0) max_n = 64;
    if (max_n > (int)RING_SIZE) max_n = (int)RING_SIZE;
    std::lock_guard<std::mutex> g(g_events.mu);
    uint64_t head = g_events.next_seq.load(std::memory_order_relaxed) - 1;
    uint64_t last = g_events.last_drained.load(std::memory_order_relaxed);
    if (last >= head) {
        duk_push_array(c);
        return 1;
    }
    // Window: [last+1 .. head]
    uint64_t start = last + 1;
    if (head - last > RING_SIZE) start = head - RING_SIZE + 1;  // overrun
    uint64_t take = head - start + 1;
    if ((int)take > max_n) {
        // Take latest max_n
        start = head - max_n + 1;
        take = max_n;
    }
    duk_idx_t arr = duk_push_array(c);
    duk_uarridx_t i = 0;
    for (uint64_t s = start; s <= head; ++s) {
        auto& slot = g_events.ring[s % RING_SIZE];
        if (slot.seq != s) continue;  // skip overwritten
        duk_idx_t o = duk_push_object(c);
        duk_push_number(c, double(slot.seq));   duk_put_prop_string(c, o, "seq");
        duk_push_number(c, double(slot.ts_ms)); duk_put_prop_string(c, o, "ts");
        duk_push_string(c, slot.tag);            duk_put_prop_string(c, o, "tag");
        duk_push_string(c, slot.body);           duk_put_prop_string(c, o, "body");
        duk_put_prop_index(c, arr, i++);
    }
    g_events.last_drained.store(head, std::memory_order_relaxed);
    return 1;
}

} // anon

void register_events_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_event, 2);
    duk_put_prop_string(ctx, ns_idx, "event");
    duk_push_c_function(ctx, js_eventDrain, 1);
    duk_put_prop_string(ctx, ns_idx, "_eventDrain");
}

} // namespace marrow
