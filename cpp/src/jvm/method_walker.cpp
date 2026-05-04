#include "method_walker.hpp"
#include "walker.hpp"
#include <cstring>
#include <stdexcept>

namespace marrow {

// Minimal CP resolver: reads the raw slot as Symbol* and decodes to UTF-8.
// Lives here in addition to the one in field_reader.cpp to keep the two
// modules independent.
namespace {
class CPNames {
public:
    CPNames(VMMeta* vm, uint64_t cp_ptr)
        : vm_(vm), r_(vm->reader()), cp_(cp_ptr)
    {
        if (auto* t = vm->type("ConstantPool")) {
            header_size_ = t->size;
            if (t->has_field("_length"))
                length_ = r_->read_i32(cp_ptr + t->field("_length")->offset);
        }
    }
    std::string symbol(int idx) const {
        if (!cp_ || idx <= 0 || idx >= length_) return {};
        try {
            uint64_t sym = r_->read_u64(cp_ + header_size_ + size_t(idx) * 8);
            if (!sym || sym < 0x10000) return {};
            return read_symbol(vm_, sym);
        } catch (...) { return {}; }
    }
private:
    VMMeta* vm_;
    Reader* r_;
    uint64_t cp_;
    size_t header_size_ = 0;
    int32_t length_ = 0;
};
}

static std::vector<uint64_t> array_methods(VMMeta* vm, uint64_t klass_ptr)
{
    const TypeInfo* ik = vm->type("InstanceKlass");
    uint64_t arr = vm->reader()->read_u64(klass_ptr + ik->field("_methods")->offset);
    if (!arr) return {};
    int32_t length = vm->reader()->read_i32(arr);
    if (length <= 0) return {};
    auto raw = vm->reader()->read(arr + 8, size_t(length) * 8);
    std::vector<uint64_t> out(length);
    std::memcpy(out.data(), raw.data(), raw.size());
    return out;
}

std::vector<MethodSnapshot> methods_of(VMMeta* vm, uint64_t klass_ptr)
{
    Reader* r = vm->reader();
    const TypeInfo* mt = vm->type("Method");
    const TypeInfo* cmt = vm->type("ConstMethod");
    size_t off_constmethod = mt->field("_constMethod")->offset;
    size_t off_name_idx    = cmt->field("_name_index")->offset;
    size_t off_sig_idx     = cmt->field("_signature_index")->offset;
    size_t off_code_size   = cmt->field("_code_size")->offset;
    size_t off_cp          = cmt->field("_constants")->offset;
    size_t header_size     = cmt->size;

    std::vector<MethodSnapshot> out;
    for (uint64_t m : array_methods(vm, klass_ptr)) {
        if (!m) continue;
        uint64_t cm = r->read_u64(m + off_constmethod);
        if (!cm) continue;
        uint64_t cp_ptr = r->read_u64(cm + off_cp);
        CPNames cp(vm, cp_ptr);
        std::string name = cp.symbol(r->read_u16(cm + off_name_idx));
        std::string sig  = cp.symbol(r->read_u16(cm + off_sig_idx));
        uint16_t code_size = r->read_u16(cm + off_code_size);
        out.push_back({m, cm, std::move(name), std::move(sig),
                       code_size, cm + header_size});
    }
    return out;
}

std::optional<MethodSnapshot>
find_method(VMMeta* vm, uint64_t klass_ptr,
             const std::string& name,
             const std::optional<std::string>& signature)
{
    for (auto& m : methods_of(vm, klass_ptr)) {
        if (m.name != name) continue;
        if (signature && m.signature != *signature) continue;
        return m;
    }
    return std::nullopt;
}

void rewrite_method_body(VMMeta* vm, const MethodSnapshot& method,
                          const std::vector<uint8_t>& new_bytecode)
{
    if (new_bytecode.size() > method.code_size)
        throw std::runtime_error("new bytecode exceeds code_size slot");
    Reader* r = vm->reader();
    const TypeInfo* mt = vm->type("Method");

    // Rewrite bytecode; pad tail with nops.
    std::vector<uint8_t> padded(method.code_size, 0x00 /* nop */);
    std::memcpy(padded.data(), new_bytecode.data(), new_bytecode.size());
    r->write(method.code_base, padded.data(), padded.size());

    // Null out _code so any JIT-compiled body is dropped.
    uint64_t zero = 0;
    r->write(method.address + mt->field("_code")->offset, &zero, 8);

    // Retarget _from_compiled_entry / _from_interpreted_entry to the
    // interpreter-to-interpreter stub so calls re-enter the interpreter.
    if (mt->has_field("_i2i_entry")) {
        uint64_t i2i = r->read_u64(method.address + mt->field("_i2i_entry")->offset);
        if (i2i) {
            r->write(method.address + mt->field("_from_compiled_entry")->offset, &i2i, 8);
            r->write(method.address + mt->field("_from_interpreted_entry")->offset, &i2i, 8);
        }
    }
}

std::vector<uint8_t> make_nop_return()
{
    return std::vector<uint8_t>{0xB1}; // return (void)
}

} // namespace marrow
