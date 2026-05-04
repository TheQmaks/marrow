#include "string_reader.hpp"
#include "field_reader.hpp"
#include "walker.hpp"
#include "zgc.hpp"
#include <cstring>
#include <stdexcept>

namespace marrow {

StringReader::StringReader(VMMeta* vm, OopDecoder* decoder, ZGCDecoder* zgc)
    : vm_(vm), r_(vm->reader()), dec_(decoder), zgc_(zgc)
{
    build_layout();
}

StringReader::StringReader(VMMeta* vm, OopDecoder* decoder, ZGCDecoder* zgc,
                            uint64_t string_klass)
    : vm_(vm), r_(vm->reader()), dec_(decoder), zgc_(zgc)
{
    if (!string_klass)
        throw std::runtime_error("StringReader: null string_klass");
    if (auto v = find_field(vm_, string_klass, "value"))
        layout_.value_offset = v->offset;
    else
        throw std::runtime_error("java/lang/String has no `value` field");
    if (auto c = find_field(vm_, string_klass, "coder"))
        layout_.coder_offset = c->offset;
}

void StringReader::build_layout()
{
    // Find java/lang/String Klass* by scanning CLDG.
    ClassWalker cw(vm_);
    uint64_t string_klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == "java/lang/String") { string_klass = k.address; break; }
    }
    if (!string_klass)
        throw std::runtime_error("java/lang/String not loaded in target");

    if (auto v = find_field(vm_, string_klass, "value"))
        layout_.value_offset = v->offset;
    else
        throw std::runtime_error("java/lang/String has no `value` field");
    if (auto c = find_field(vm_, string_klass, "coder"))
        layout_.coder_offset = c->offset;
}

std::pair<size_t, size_t> StringReader::array_header_offsets() const
{
    // Non-const access to dec_ is fine — decoder caches the probe result.
    auto* d = const_cast<OopDecoder*>(dec_);
    if (d->compressed_klass()) return {12, 16};
    return {16, 24};
}

// UTF-16LE little-endian -> UTF-8.
static std::string utf16le_to_utf8(const std::vector<uint8_t>& raw)
{
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
        uint32_t c = uint32_t(raw[i]) | (uint32_t(raw[i + 1]) << 8);
        if (c < 0x80) out.push_back(char(c));
        else if (c < 0x800) {
            out.push_back(char(0xC0 | (c >> 6)));
            out.push_back(char(0x80 | (c & 0x3F)));
        } else if (c < 0xD800 || c >= 0xE000) {
            out.push_back(char(0xE0 | (c >> 12)));
            out.push_back(char(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(char(0x80 | (c & 0x3F)));
        } else {
            // Leading surrogate — combine with the next one if possible.
            if (i + 3 < raw.size() && (c & 0xFC00) == 0xD800) {
                uint32_t lo = uint32_t(raw[i + 2]) | (uint32_t(raw[i + 3]) << 8);
                uint32_t cp = 0x10000 + (((c - 0xD800) << 10) | (lo - 0xDC00));
                out.push_back(char(0xF0 | (cp >> 18)));
                out.push_back(char(0x80 | ((cp >> 12) & 0x3F)));
                out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back(char(0x80 | (cp & 0x3F)));
                i += 2;
            } else {
                out.push_back('?');
            }
        }
    }
    return out;
}

std::string StringReader::read(uint64_t string_oop, size_t max_bytes)
{
    if (!string_oop) return {};

    // Shenandoah / STW mark-word forwarding on the string oop itself.
    string_oop = dec_->resolve_forwarding(string_oop);

    // Read String.value slot. Storage size depends on ZGC colouring,
    // compressed oops, or wide mode.
    uint64_t v_slot = string_oop + layout_.value_offset;
    uint64_t value_oop = 0;
    if (zgc_ && zgc_->is_active()) {
        uint64_t raw = r_->read_u64(v_slot);
        value_oop = zgc_->decode(raw);
    } else if (dec_->oops_are_compressed()) {
        uint32_t narrow = r_->read_u32(v_slot);
        value_oop = dec_->decode_oop(narrow);
    } else {
        value_oop = r_->read_u64(v_slot);
    }
    if (!value_oop) return {};
    value_oop = dec_->resolve_forwarding(value_oop);

    int coder = 1;  // JDK 8 default: char[] = UTF-16.
    if (layout_.coder_offset >= 0) {
        auto b = r_->read(string_oop + size_t(layout_.coder_offset), 1);
        coder = b.empty() ? 0 : int(b[0]);
    }

    auto [len_off, data_off] = array_header_offsets();
    int32_t length = r_->read_i32(value_oop + len_off);
    if (length <= 0) return {};

    if (coder == 0) {
        // Latin1: length counts bytes.
        size_t n = std::min<size_t>(size_t(length), max_bytes);
        auto raw = r_->read(value_oop + data_off, n);
        return std::string(raw.begin(), raw.end());
    }

    // coder == 1: UTF-16 two bytes per code unit.
    size_t byte_len;
    if (layout_.coder_offset < 0) {
        // JDK 8 char[]: length is char count → 2 bytes each.
        byte_len = std::min<size_t>(size_t(length) * 2, max_bytes);
    } else {
        byte_len = std::min<size_t>(size_t(length), max_bytes);
    }
    auto raw = r_->read(value_oop + data_off, byte_len);
    return utf16le_to_utf8(raw);
}

} // namespace marrow
