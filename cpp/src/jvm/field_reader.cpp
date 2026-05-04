#include "field_reader.hpp"
#include "walker.hpp"
#include <cstring>

namespace marrow {

// UNSIGNED5 parameters from HotSpot utilities/unsigned5.hpp.
static constexpr uint8_t U5_X   = 1;
static constexpr uint8_t U5_L   = 191;
static constexpr uint8_t U5_LGH = 6;   // log2(64)

// Decode one UNSIGNED5 value starting at buf[pos]. Returns pair(value, new_pos).
static std::pair<uint64_t, size_t>
u5_read(const std::vector<uint8_t>& buf, size_t pos)
{
    if (pos >= buf.size()) return {0, pos};
    uint8_t b0 = buf[pos];
    if (b0 == 0) return {0, pos + 1};
    uint64_t s = b0 - U5_X;
    if (s < U5_L) return {s, pos + 1};
    int lg = U5_LGH;
    for (int i = 1; i < 5 && pos + i < buf.size(); ++i) {
        uint8_t bi = buf[pos + i];
        s += uint64_t(bi - U5_X) << lg;
        if (bi < U5_X + U5_L || i == 4) return {s, pos + i + 1};
        lg += U5_LGH;
    }
    return {s, std::min(pos + 5, buf.size())};
}

// HotSpot Array<T>: int32 _length @0, data @4.
static std::vector<uint8_t> read_u1_array(Reader* r, uint64_t arr_ptr)
{
    if (!arr_ptr) return {};
    int32_t length = r->read_i32(arr_ptr);
    if (length <= 0) return {};
    return r->read(arr_ptr + 4, size_t(length));
}

static std::vector<uint16_t> read_u2_array(Reader* r, uint64_t arr_ptr)
{
    if (!arr_ptr) return {};
    int32_t length = r->read_i32(arr_ptr);
    if (length <= 0) return {};
    auto raw = r->read(arr_ptr + 4, size_t(length) * 2);
    std::vector<uint16_t> out(length);
    std::memcpy(out.data(), raw.data(), raw.size());
    return out;
}

// Minimal CP resolver: reads the raw slot as Symbol* and decodes to UTF-8.
// The CP holds heterogeneous payloads per tag; a non-Utf8 slot yields an
// empty string, which callers treat as "skip this field".
//
// Race-resistance: the CP slots array (cp_base .. cp_base + length*8) is
// bulk-snapshotted once in the constructor so that per-field lookups read
// from the local copy and never touch live CP memory again.  Symbol*
// contents (length + body bytes) are still read live, which is the
// remaining race surface.
namespace {
class CPSymbols {
public:
    CPSymbols(VMMeta* vm, uint64_t cp_ptr)
        : vm_(vm), r_(vm->reader()), cp_(cp_ptr)
    {
        if (auto* t = vm->type("ConstantPool")) {
            header_size_ = t->size;
            if (t->has_field("_length"))
                length_ = r_->read_i32(cp_ptr + t->field("_length")->offset);
        }
        // Bulk-snapshot all CP slot bytes so per-field reads use the local copy.
        if (cp_ && length_ > 0) {
            try {
                slots_snapshot_ = r_->read(cp_ + header_size_,
                                           size_t(length_) * 8);
            } catch (...) {
                slots_snapshot_.clear();
            }
        }
    }

    std::string symbol(int index) const {
        if (!cp_ || index <= 0 || index >= length_) return {};
        // Read Symbol* from the pre-fetched snapshot to avoid CP slot races.
        uint64_t sym = 0;
        size_t byte_off = size_t(index) * 8;
        if (byte_off + 8 <= slots_snapshot_.size()) {
            std::memcpy(&sym, slots_snapshot_.data() + byte_off, 8);
        } else {
            // Snapshot was truncated — skip this slot rather than crash.
            return {};
        }
        if (!sym || sym < 0x10000) return {};
        // Symbol* contents (length + body) are still read live here.
        try { return read_symbol(vm_, sym); } catch (...) { return {}; }
    }

private:
    VMMeta* vm_;
    Reader* r_;
    uint64_t cp_;
    size_t header_size_ = 0;
    int32_t length_ = 0;
    std::vector<uint8_t> slots_snapshot_; // bulk copy of cp slots array
};
}

// Stream field_flags bits relevant to payload length.
static constexpr uint64_t FF_INITIALIZED = 1ull << 0;
static constexpr uint64_t FF_GENERIC     = 1ull << 2;
static constexpr uint64_t FF_CONTENDED   = 1ull << 4;

static std::vector<FieldRecord>
read_stream(VMMeta* vm, uint64_t klass_ptr, const TypeInfo* ik,
            const CPSymbols& cp)
{
    uint64_t arr = vm->reader()->read_u64(klass_ptr + ik->field("_fieldinfo_stream")->offset);
    auto buf = read_u1_array(vm->reader(), arr);
    std::vector<FieldRecord> out;
    if (buf.empty()) return out;

    size_t pos = 0;
    auto [num_java, p1] = u5_read(buf, pos);     pos = p1;
    auto [num_inj, p2]  = u5_read(buf, pos);     pos = p2;
    uint64_t total = num_java + num_inj;

    for (uint64_t i = 0; i < total && pos < buf.size(); ++i) {
        auto [name_idx, p]   = u5_read(buf, pos); pos = p;
        auto [sig_idx, q]    = u5_read(buf, pos); pos = q;
        auto [offset, r_]    = u5_read(buf, pos); pos = r_;
        auto [access, s]     = u5_read(buf, pos); pos = s;
        auto [fflags, t]     = u5_read(buf, pos); pos = t;
        if (fflags & FF_INITIALIZED) { auto [_, u] = u5_read(buf, pos); pos = u; }
        if (fflags & FF_GENERIC)     { auto [_, u] = u5_read(buf, pos); pos = u; }
        if (fflags & FF_CONTENDED)   { auto [_, u] = u5_read(buf, pos); pos = u; }
        FieldRecord rec;
        rec.name         = cp.symbol(int(name_idx));
        rec.signature    = cp.symbol(int(sig_idx));
        rec.access_flags = int32_t(access);
        rec.offset       = int32_t(offset);
        rec.is_static    = (access & 0x0008) != 0;
        out.push_back(std::move(rec));
    }
    return out;
}

static std::vector<FieldRecord>
read_legacy(VMMeta* vm, uint64_t klass_ptr, const TypeInfo* ik,
            const CPSymbols& cp)
{
    constexpr size_t SLOTS = 6;
    uint64_t arr = vm->reader()->read_u64(klass_ptr + ik->field("_fields")->offset);
    auto words = read_u2_array(vm->reader(), arr);
    std::vector<FieldRecord> out;
    size_t complete = (words.size() / SLOTS) * SLOTS;
    for (size_t i = 0; i < complete; i += SLOTS) {
        uint16_t access   = words[i + 0];
        uint16_t name_idx = words[i + 1];
        uint16_t sig_idx  = words[i + 2];
        uint16_t low      = words[i + 4];
        uint16_t high     = words[i + 5];
        uint32_t packed   = (uint32_t(high) << 16) | low;
        FieldRecord rec;
        rec.name         = cp.symbol(name_idx);
        rec.signature    = cp.symbol(sig_idx);
        rec.access_flags = access;
        rec.offset       = int32_t(packed >> 2);
        rec.is_static    = (access & 0x0008) != 0;
        out.push_back(std::move(rec));
    }
    return out;
}

std::vector<FieldRecord> read_fields(VMMeta* vm, uint64_t klass_ptr)
{
    if (!klass_ptr) return {};
    const TypeInfo* ik = vm->type("InstanceKlass");
    if (!ik) return {};
    uint64_t cp_ptr = vm->reader()->read_u64(klass_ptr + ik->field("_constants")->offset);
    CPSymbols cp(vm, cp_ptr);
    if (ik->has_field("_fieldinfo_stream")) return read_stream(vm, klass_ptr, ik, cp);
    if (ik->has_field("_fields"))           return read_legacy(vm, klass_ptr, ik, cp);
    return {};
}

std::optional<FieldRecord>
find_field(VMMeta* vm, uint64_t klass_ptr, const std::string& name)
{
    for (auto& f : read_fields(vm, klass_ptr))
        if (f.name == name) return f;
    return std::nullopt;
}

} // namespace marrow
