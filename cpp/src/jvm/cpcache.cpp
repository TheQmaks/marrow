#include "cpcache.hpp"
#include "signature.hpp"
#include "walker.hpp"
#include <cstring>
#include <stdexcept>

namespace marrow {

static size_t cpcache_header_size(VMMeta* vm) {
    const TypeInfo* t = vm->type("ConstantPoolCache");
    return t ? size_t(t->size) : 32;
}

uint64_t find_cpcache(VMMeta* vm, uint64_t cp_ptr) {
    return vm->reader()->read_u64(cp_ptr + 16);
}

std::vector<CacheEntryInfo>
iterate_cpcache_entries_legacy(VMMeta* vm, uint64_t cpcache)
{
    std::vector<CacheEntryInfo> out;
    const TypeInfo* entry_t = vm->type("ConstantPoolCacheEntry");
    if (!entry_t) return out; // JDK 25+
    Reader* r = vm->reader();
    int32_t length = r->read_i32(cpcache);
    size_t header = cpcache_header_size(vm);
    size_t entry_size = size_t(entry_t->size);
    out.reserve(length);
    for (int32_t i = 0; i < length; ++i) {
        uint64_t base = cpcache + header + size_t(i) * entry_size;
        uint64_t raw = r->read_u64(base);
        uint64_t f1  = r->read_u64(base + 8);
        uint32_t low = uint32_t(raw & 0xFFFFFFFFu);
        out.push_back({i, raw, uint16_t(low & 0xFFFF), f1,
                       uint8_t((low >> 16) & 0xFF)});
    }
    return out;
}

static size_t page_align(size_t n) { return (n + 0xFFF) & ~size_t(0xFFF); }

ExtendCPCacheResult clone_and_extend_cpcache_legacy(
    VMMeta* vm, uint64_t cp_ptr,
    const std::vector<NewEntrySpec>& new_entries)
{
    const TypeInfo* entry_t = vm->type("ConstantPoolCacheEntry");
    if (!entry_t)
        throw std::runtime_error("legacy CPCacheEntry layout not present");
    Reader* r = vm->reader();
    uint64_t cpcache_old = find_cpcache(vm, cp_ptr);
    if (!cpcache_old) throw std::runtime_error("CP has no cache to extend");

    size_t header = cpcache_header_size(vm);
    size_t entry_size = size_t(entry_t->size);
    int32_t old_len = r->read_i32(cpcache_old);
    int32_t extra   = int32_t(new_entries.size());
    int32_t new_len = old_len + extra;
    size_t new_total = header + size_t(new_len) * entry_size;
    uint64_t cpcache_new = r->alloc(page_align(new_total), false);

    auto prefix = r->read(cpcache_old, header + size_t(old_len) * entry_size);
    r->write(cpcache_new, prefix.data(), prefix.size());
    r->write(cpcache_new, &new_len, 4);

    auto existing = iterate_cpcache_entries_legacy(vm, cpcache_old);
    std::vector<int32_t> out_idx;
    out_idx.reserve(new_entries.size());

    for (size_t i = 0; i < new_entries.size(); ++i) {
        const NewEntrySpec& spec = new_entries[i];
        // Donor matching: exact (cp_index, b1), else any resolved entry
        // with matching b1 when a sig is provided.
        const CacheEntryInfo* donor = nullptr;
        for (auto& e : existing) {
            if (e.cp_index == spec.cp_index && e.b1 == spec.b1) { donor = &e; break; }
        }
        if (!donor && spec.sig) {
            for (auto& e : existing) {
                if (e.b1 == spec.b1 && e.f1 != 0) { donor = &e; break; }
            }
        }
        if (!donor) {
            throw std::runtime_error("no CPCache donor for extension");
        }
        uint64_t donor_slot = cpcache_old + header + size_t(donor->index) * entry_size;
        uint64_t slot = cpcache_new + header + size_t(old_len + int32_t(i)) * entry_size;
        auto donor_bytes = r->read(donor_slot, entry_size);
        r->write(slot, donor_bytes.data(), donor_bytes.size());

        // Patch _indices to point at OUR cp_index.
        uint64_t orig64 = r->read_u64(slot);
        uint32_t donor_low = uint32_t(orig64 & 0xFFFFFFFFu);
        uint32_t new_low = (donor_low & ~uint32_t(0xFFFF)) | (spec.cp_index & 0xFFFF);
        uint64_t new_u64 = (orig64 & ~uint64_t(0xFFFFFFFF)) | new_low;
        r->write(slot, &new_u64, 8);

        if (spec.override_f1) {
            uint64_t v = spec.override_f1;
            r->write(slot + 8, &v, 8);
        }
        if (spec.sig) {
            uint64_t donor_flags = r->read_u64(slot + 24);
            uint64_t new_flags = synth_flags_legacy(
                uint32_t(donor_flags), *spec.sig, spec.is_static);
            // Preserve high bits of the intx donor value.
            uint64_t packed = (donor_flags & ~uint64_t(0xFFFFFFFF))
                              | (new_flags & 0xFFFFFFFF);
            r->write(slot + 24, &packed, 8);
        }
        out_idx.push_back(old_len + int32_t(i));
    }

    // Redirect CP._cache at the clone.
    uint64_t v = cpcache_new;
    r->write(cp_ptr + 16, &v, 8);
    return {cpcache_old, cpcache_new, std::move(out_idx)};
}

ExtendRMEResult clone_and_extend_cpcache_modern(
    VMMeta* vm, uint64_t cp_ptr,
    const std::vector<uint16_t>& new_cp_indices)
{
    const TypeInfo* rme_t = vm->type("ResolvedMethodEntry");
    const TypeInfo* cc_t = vm->type("ConstantPoolCache");
    if (!rme_t) throw std::runtime_error("ResolvedMethodEntry type missing");
    Reader* r = vm->reader();
    uint64_t cpcache = find_cpcache(vm, cp_ptr);
    if (!cpcache) throw std::runtime_error("CP has no cache");
    size_t rme_arr_off = cc_t->field("_resolved_method_entries")->offset;
    uint64_t rme_arr_old = r->read_u64(cpcache + rme_arr_off);
    if (!rme_arr_old) throw std::runtime_error("no _resolved_method_entries");
    size_t rme_size = size_t(rme_t->size);
    size_t cpool_off = rme_t->field("_cpool_index")->offset;
    int32_t old_len = r->read_i32(rme_arr_old);
    int32_t extra = int32_t(new_cp_indices.size());
    int32_t new_len = old_len + extra;
    constexpr size_t DATA_OFF = 8;
    size_t total = DATA_OFF + size_t(new_len) * rme_size;
    uint64_t rme_arr_new = r->alloc(page_align(total), false);
    r->write(rme_arr_new, &new_len, 4);
    auto existing = r->read(rme_arr_old + DATA_OFF, size_t(old_len) * rme_size);
    r->write(rme_arr_new + DATA_OFF, existing.data(), existing.size());

    std::vector<int32_t> out_idx;
    for (size_t i = 0; i < new_cp_indices.size(); ++i) {
        uint16_t wanted = new_cp_indices[i];
        const uint8_t* donor = nullptr;
        for (int32_t j = 0; j < old_len; ++j) {
            uint16_t cpi;
            std::memcpy(&cpi, existing.data() + j * rme_size + cpool_off, 2);
            if (cpi == wanted) {
                donor = existing.data() + j * rme_size;
                break;
            }
        }
        if (!donor) throw std::runtime_error("no ResolvedMethodEntry donor");
        uint64_t dest = rme_arr_new + DATA_OFF + size_t(old_len + int32_t(i)) * rme_size;
        r->write(dest, donor, rme_size);
        out_idx.push_back(old_len + int32_t(i));
    }

    uint64_t v = rme_arr_new;
    r->write(cpcache + rme_arr_off, &v, 8);
    return {rme_arr_old, rme_arr_new, std::move(out_idx)};
}

std::optional<int32_t>
cache_index_for_cp(VMMeta* vm, uint64_t cp_ptr, uint16_t cp_index, uint8_t bytecode)
{
    uint64_t cpcache = find_cpcache(vm, cp_ptr);
    if (!cpcache) return std::nullopt;

    for (auto& e : iterate_cpcache_entries_legacy(vm, cpcache)) {
        if (e.cp_index == cp_index && e.b1 == bytecode) return e.index;
    }
    const TypeInfo* cc_t = vm->type("ConstantPoolCache");
    const TypeInfo* rme_t = vm->type("ResolvedMethodEntry");
    if (!cc_t || !rme_t || !cc_t->has_field("_resolved_method_entries"))
        return std::nullopt;
    Reader* r = vm->reader();
    size_t rme_arr_off = cc_t->field("_resolved_method_entries")->offset;
    uint64_t rme_arr = r->read_u64(cpcache + rme_arr_off);
    if (!rme_arr) return std::nullopt;
    int32_t rme_len = r->read_i32(rme_arr);
    size_t rme_size = size_t(rme_t->size);
    size_t cpool_off = rme_t->field("_cpool_index")->offset;
    constexpr size_t DATA_OFF = 8;
    auto buf = r->read(rme_arr + DATA_OFF, size_t(rme_len) * rme_size);
    for (int32_t i = 0; i < rme_len; ++i) {
        uint16_t cpi;
        std::memcpy(&cpi, buf.data() + i * rme_size + cpool_off, 2);
        if (cpi == cp_index) return i;
    }
    return std::nullopt;
}

std::vector<CacheTemplate>
scan_all_caches_for_template(VMMeta* vm, uint8_t bytecode)
{
    std::vector<CacheTemplate> results;
    const TypeInfo* ik_t = vm->type("InstanceKlass");
    const TypeInfo* entry_t = vm->type("ConstantPoolCacheEntry");
    if (!ik_t || !entry_t) return results;
    size_t constants_off = ik_t->field("_constants")->offset;
    size_t entry_size = size_t(entry_t->size);
    size_t header = cpcache_header_size(vm);
    Reader* r = vm->reader();

    ClassWalker cw(vm);
    for (auto& k : cw.list()) {
        if (k.kind != "instance") continue;
        try {
            uint64_t cp = r->read_u64(k.address + constants_off);
            if (!cp) continue;
            uint64_t cc = find_cpcache(vm, cp);
            if (!cc) continue;
            for (auto& e : iterate_cpcache_entries_legacy(vm, cc)) {
                if (e.b1 != bytecode || e.f1 == 0) continue;
                uint64_t slot = cc + header + size_t(e.index) * entry_size;
                results.push_back({k.address, cc, r->read(slot, entry_size)});
            }
        } catch (...) { continue; }
    }
    return results;
}

} // namespace marrow
