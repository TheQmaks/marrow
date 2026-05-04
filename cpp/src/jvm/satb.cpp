#include "satb.hpp"
#include <algorithm>
#include <cstring>

namespace marrow {

static size_t sizeof_satb_queue(VMMeta* vm) {
    const TypeInfo* q = vm->type("SATBMarkQueue");
    return q ? size_t(q->size) : 32;
}

static std::pair<size_t, size_t> ptrqueue_offsets(VMMeta* vm) {
    const TypeInfo* pq = vm->type("PtrQueue");
    if (!pq) return {0, 16};
    size_t idx = pq->has_field("_index") ? pq->field("_index")->offset : 0;
    size_t buf = pq->has_field("_buf")   ? pq->field("_buf")->offset   : 16;
    return {idx, buf};
}

static size_t satb_active_offset(VMMeta* vm) {
    const TypeInfo* q = vm->type("SATBMarkQueue");
    if (q && q->has_field("_active")) return q->field("_active")->offset;
    return 24;
}

static size_t last_known_field_end(VMMeta* vm) {
    size_t high = 0;
    for (const char* tname : {"JavaThread", "Thread"}) {
        const TypeInfo* t = vm->type(tname);
        if (!t) continue;
        for (auto& entry : t->fields) {
            const FieldInfo& f = entry.second;
            if (f.is_static) continue;
            high = std::max(high, size_t(f.offset + 8));
        }
    }
    return high;
}

std::vector<SATBQueueProbe>
find_satb_queue(VMMeta* vm, uint64_t java_thread, size_t max_candidates)
{
    std::vector<SATBQueueProbe> out;
    const TypeInfo* jt = vm->type("JavaThread");
    if (!jt) return out;
    size_t sz = size_t(jt->size);
    size_t gap_start = last_known_field_end(vm);
    if (sz <= gap_start) return out;
    size_t gap_len = sz - gap_start;
    size_t q_size = sizeof_satb_queue(vm);
    auto [idx_off, buf_off] = ptrqueue_offsets(vm);
    size_t act_off = satb_active_offset(vm);

    auto region = vm->reader()->read(java_thread + gap_start, gap_len);
    for (size_t pos = 0; pos + q_size <= region.size(); pos += 8) {
        uint64_t index_val; std::memcpy(&index_val, region.data() + pos + idx_off, 8);
        uint64_t buf_val;   std::memcpy(&buf_val,   region.data() + pos + buf_off, 8);
        uint8_t active_byte = region[pos + act_off];
        if (active_byte != 0 && active_byte != 1) continue;
        if (buf_val != 0 && buf_val < 0x10000) continue;
        if (index_val > (uint64_t(1) << 40) && index_val != 0xFFFFFFFFFFFFFFFFull) continue;
        out.push_back({uint64_t(gap_start + pos), index_val, buf_val, active_byte == 1});
        if (max_candidates && out.size() >= max_candidates) break;
    }
    return out;
}

} // namespace marrow
