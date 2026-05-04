#pragma once
// java.lang.String decoder. Handles pre-Compact Strings (JDK 8, char[])
// and Compact Strings (JDK 9+, byte[] + coder). Offsets come from
// FieldInfoStream/legacy Array<u2> via field_reader.
//
// ZGC support is optional — pass a ZGCDecoder* when the target may be
// running under ZGC so reference slots get uncoloured before deref.

#include "oop_reader.hpp"
#include "vm_meta.hpp"
#include <cstdint>
#include <optional>
#include <string>

namespace marrow {

class ZGCDecoder; // fwd

class StringReader {
public:
    StringReader(VMMeta* vm, OopDecoder* decoder, ZGCDecoder* zgc = nullptr);
    // In-process variant: skip the second ClassWalker scan (which races
    // with concurrent class loading and stalls the agent) and use a
    // pre-resolved java/lang/String klass address.
    StringReader(VMMeta* vm, OopDecoder* decoder, ZGCDecoder* zgc,
                 uint64_t string_klass);

    // Decode a String oop to a UTF-8 string. Returns empty on null / error.
    // `max_bytes` caps output length so a corrupt length field can't blow
    // through memory.
    std::string read(uint64_t string_oop, size_t max_bytes = 4096);

private:
    struct Layout {
        int32_t value_offset = -1;
        int32_t coder_offset = -1; // -1 == not present (JDK 8)
    };
    Layout layout_;

    std::pair<size_t, size_t> array_header_offsets() const;
    void build_layout();

    VMMeta* vm_;
    Reader* r_;
    OopDecoder* dec_;
    ZGCDecoder* zgc_;
};

} // namespace marrow
