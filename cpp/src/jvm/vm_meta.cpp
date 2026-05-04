#include "vm_meta.hpp"
#include <cstring>
#include <stdexcept>

namespace marrow {

namespace {

struct Layout {
    size_t type_name = 0, field_name = 0, type_string = 0;
    size_t is_static = 0, offset = 0, address = 0, stride = 0;
};

struct TypeLayout {
    size_t type_name = 0, super_name = 0, is_oop = 0;
    size_t is_int = 0, is_unsigned = 0, size_off = 0, stride = 0;
};

size_t read_size_at(Reader* r, uint64_t a) { return r->read_size_t(a); }

template<class Layout>
void load_struct_layout(Reader* r, const std::string& prefix,
                        const std::vector<std::pair<const char*, size_t Layout::*>>& fields) {
    (void)r; (void)prefix; (void)fields;  // placeholder
}

} // unnamed

VMMeta::VMMeta(Reader* reader) : reader_(reader) { parse(); }

const TypeInfo* VMMeta::type(const std::string& name) const {
    auto it = types_.find(name);
    return it == types_.end() ? nullptr : &it->second;
}

bool VMMeta::has_type(const std::string& name) const {
    return types_.count(name);
}

std::optional<int32_t> VMMeta::int_constant(const std::string& name) const {
    auto it = int_consts_.find(name);
    if (it == int_consts_.end()) return std::nullopt;
    return it->second;
}

std::optional<uint64_t> VMMeta::long_constant(const std::string& name) const {
    auto it = long_consts_.find(name);
    if (it == long_consts_.end()) return std::nullopt;
    return it->second;
}

void VMMeta::parse() {
    // Struct-entry layout descriptors.
    Layout sL{};
    sL.type_name   = read_size_at(reader_, reader_->symbol("gHotSpotVMStructEntryTypeNameOffset"));
    sL.field_name  = read_size_at(reader_, reader_->symbol("gHotSpotVMStructEntryFieldNameOffset"));
    sL.type_string = read_size_at(reader_, reader_->symbol("gHotSpotVMStructEntryTypeStringOffset"));
    sL.is_static   = read_size_at(reader_, reader_->symbol("gHotSpotVMStructEntryIsStaticOffset"));
    sL.offset      = read_size_at(reader_, reader_->symbol("gHotSpotVMStructEntryOffsetOffset"));
    sL.address     = read_size_at(reader_, reader_->symbol("gHotSpotVMStructEntryAddressOffset"));
    sL.stride      = read_size_at(reader_, reader_->symbol("gHotSpotVMStructEntryArrayStride"));

    TypeLayout tL{};
    tL.type_name   = read_size_at(reader_, reader_->symbol("gHotSpotVMTypeEntryTypeNameOffset"));
    tL.super_name  = read_size_at(reader_, reader_->symbol("gHotSpotVMTypeEntrySuperclassNameOffset"));
    tL.is_oop      = read_size_at(reader_, reader_->symbol("gHotSpotVMTypeEntryIsOopTypeOffset"));
    tL.is_int      = read_size_at(reader_, reader_->symbol("gHotSpotVMTypeEntryIsIntegerTypeOffset"));
    tL.is_unsigned = read_size_at(reader_, reader_->symbol("gHotSpotVMTypeEntryIsUnsignedOffset"));
    tL.size_off    = read_size_at(reader_, reader_->symbol("gHotSpotVMTypeEntrySizeOffset"));
    tL.stride      = read_size_at(reader_, reader_->symbol("gHotSpotVMTypeEntryArrayStride"));

    // Walk types first.
    uint64_t p = reader_->read_ptr(reader_->symbol("gHotSpotVMTypes"));
    while (true) {
        uint64_t tn_ptr = reader_->read_ptr(p + tL.type_name);
        if (!tn_ptr) break;
        TypeInfo t;
        t.name = reader_->cstring(tn_ptr);
        t.super_name = reader_->cstring(reader_->read_ptr(p + tL.super_name));
        t.size = reader_->read_u64(p + tL.size_off);
        t.is_oop = reader_->read_i32(p + tL.is_oop) != 0;
        t.is_integer = reader_->read_i32(p + tL.is_int) != 0;
        t.is_unsigned = reader_->read_i32(p + tL.is_unsigned) != 0;
        types_.emplace(t.name, std::move(t));
        p += tL.stride;
    }

    // Walk structs (fields), attaching each to its type.
    p = reader_->read_ptr(reader_->symbol("gHotSpotVMStructs"));
    while (true) {
        uint64_t tn_ptr = reader_->read_ptr(p + sL.type_name);
        if (!tn_ptr) break;
        FieldInfo f;
        f.type_name  = reader_->cstring(tn_ptr);
        f.name       = reader_->cstring(reader_->read_ptr(p + sL.field_name));
        f.type_string= reader_->cstring(reader_->read_ptr(p + sL.type_string));
        f.is_static  = reader_->read_i32(p + sL.is_static) != 0;
        if (f.is_static)  f.address = reader_->read_ptr(p + sL.address);
        else              f.offset  = reader_->read_u64(p + sL.offset);
        auto it = types_.find(f.type_name);
        if (it != types_.end()) it->second.fields.emplace(f.name, f);
        p += sL.stride;
        ++num_structs_;
    }

    // Int constants (best-effort; may be absent on exotic builds).
    auto try_walk_consts = [&](const std::string& prefix,
                                const std::string& arr_sym, bool as_int) {
        auto stride_opt = reader_->opt_symbol(prefix + "ArrayStride");
        auto name_off_opt = reader_->opt_symbol(prefix + "NameOffset");
        auto val_off_opt = reader_->opt_symbol(prefix + "ValueOffset");
        auto arr_opt = reader_->opt_symbol(arr_sym);
        if (!(stride_opt && name_off_opt && val_off_opt && arr_opt)) return;
        size_t stride = reader_->read_size_t(*stride_opt);
        size_t n_off = reader_->read_size_t(*name_off_opt);
        size_t v_off = reader_->read_size_t(*val_off_opt);
        uint64_t q = reader_->read_ptr(*arr_opt);
        while (true) {
            uint64_t np = reader_->read_ptr(q + n_off);
            if (!np) break;
            std::string nm = reader_->cstring(np);
            if (as_int) int_consts_.emplace(nm, reader_->read_i32(q + v_off));
            else        long_consts_.emplace(nm, reader_->read_u64(q + v_off));
            q += stride;
        }
    };
    try_walk_consts("gHotSpotVMIntConstantEntry",  "gHotSpotVMIntConstants",  true);
    try_walk_consts("gHotSpotVMLongConstantEntry", "gHotSpotVMLongConstants", false);
}

} // namespace marrow
