#include "dict_analyzer.hpp"
#include <cstring>
#include <unordered_set>

namespace marrow {

static bool looks_like_c_heap_ptr(uint64_t addr) {
    return addr >= 0x10000000000ull && addr < 0x7FFFFFFFFFFFull;
}

static bool looks_like_klass(VMMeta* vm, uint64_t addr) {
    if (!addr || addr < 0x10000 || addr > 0x7FFFFFFFFFFFull) return false;
    try {
        size_t name_off = vm->type("Klass")->field("_name")->offset;
        uint64_t sym = vm->reader()->read_u64(addr + name_off);
        if (sym < 0x10000 || sym > 0x7FFFFFFFFFFFull) return false;
        const TypeInfo* sym_t = vm->type("Symbol");
        size_t len_off = sym_t->field("_length")->offset;
        size_t body_off = sym_t->field("_body")->offset;
        uint16_t length = vm->reader()->read_u16(sym + len_off);
        if (length == 0 || length > 2048) return false;
        size_t n = length < 32 ? length : 32;
        auto body = vm->reader()->read(sym + body_off, n);
        for (auto b : body) {
            if (!((b >= 0x20 && b < 0x80) || b == '/' || b == '$'
                  || b == ';' || b == '['))
                return false;
        }
        return true;
    } catch (...) { return false; }
}

int validate_layout(VMMeta* vm, uint64_t dict_ptr, const DictLayout& l)
{
    Reader* r = vm->reader();
    int32_t ts;
    uint64_t bk;
    try {
        ts = r->read_i32(dict_ptr + l.table_size_off);
        if (ts <= 0 || ts > 200000) return 0;
        bk = r->read_u64(dict_ptr + l.buckets_off);
        if (!looks_like_c_heap_ptr(bk)) return 0;
    } catch (...) { return 0; }
    int score = 0;
    std::unordered_set<uint64_t> seen;
    size_t cap = size_t(ts < 200 ? ts : 200);
    std::vector<uint8_t> bucket_data;
    try { bucket_data = r->read(bk, cap * 8); }
    catch (...) { return 0; }
    for (size_t i = 0; i < cap; ++i) {
        uint64_t head;
        std::memcpy(&head, bucket_data.data() + i * 8, 8);
        if (!looks_like_c_heap_ptr(head)) continue;
        uint64_t e = head;
        int chain_len = 0;
        while (e && !seen.count(e) && chain_len < 5) {
            seen.insert(e);
            std::vector<uint8_t> eb;
            try { eb = r->read(e, l.entry_size); }
            catch (...) { break; }
            uint64_t lit;
            std::memcpy(&lit, eb.data() + l.entry_literal_off, 8);
            if (!looks_like_klass(vm, lit)) break;
            ++score;
            std::memcpy(&e, eb.data() + l.entry_next_off, 8);
            ++chain_len;
        }
        if (score >= 50) break;
    }
    return score;
}

std::optional<DictLayout>
find_dictionary_layout(VMMeta* vm, uint64_t dict_ptr)
{
    std::optional<DictLayout> best;
    int best_score = 5;  // require at least 5 valid entries
    for (size_t entry_size : {size_t(32), size_t(40)}) {
        for (size_t ts_off = 8; ts_off < 80; ts_off += 4) {
            for (size_t bk_off = 8; bk_off < 80; bk_off += 8) {
                if (bk_off == ts_off) continue;
                for (auto [next_off, lit_off] :
                     std::initializer_list<std::pair<size_t, size_t>>{
                         {8, 16}, {8, 24}}) {
                    DictLayout l{ts_off, bk_off, 0, next_off, lit_off, entry_size};
                    int s = validate_layout(vm, dict_ptr, l);
                    if (s > best_score) {
                        best_score = s;
                        best = l;
                    }
                }
            }
        }
    }
    return best;
}

std::optional<DictLayout> discover_dict_layout(VMMeta* vm)
{
    if (!vm->has_type("Dictionary") || !vm->has_type("ClassLoaderData")
        || !vm->has_type("ClassLoaderDataGraph"))
        return std::nullopt;
    Reader* r = vm->reader();
    const TypeInfo* cld_t = vm->type("ClassLoaderData");
    if (!cld_t->has_field("_dictionary") || !cld_t->has_field("_next"))
        return std::nullopt;
    size_t d_off = cld_t->field("_dictionary")->offset;
    size_t n_off = cld_t->field("_next")->offset;
    uint64_t cld = r->read_u64(vm->type("ClassLoaderDataGraph")
                                ->field("_head")->address);
    std::unordered_set<uint64_t> seen;
    while (cld && !seen.count(cld)) {
        seen.insert(cld);
        uint64_t d = 0;
        try { d = r->read_u64(cld + d_off); } catch (...) {}
        if (d) {
            auto lay = find_dictionary_layout(vm, d);
            if (lay) return lay;
        }
        try { cld = r->read_u64(cld + n_off); } catch (...) { break; }
    }
    return std::nullopt;
}

} // namespace marrow
