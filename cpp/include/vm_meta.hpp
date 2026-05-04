#pragma once
// High-level view of HotSpot's self-describing metadata, populated by
// parsing `gHotSpotVMStructs` and friends from a jvm.dll loaded either
// locally or in a remote process.

#include "reader.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace marrow {

struct FieldInfo {
    std::string type_name;
    std::string name;
    std::string type_string;
    bool        is_static = false;
    uint64_t    offset    = 0;  // for instance fields
    uint64_t    address   = 0;  // for static fields
};

struct TypeInfo {
    std::string name;
    std::string super_name;
    uint64_t    size = 0;
    bool        is_oop = false;
    bool        is_integer = false;
    bool        is_unsigned = false;
    std::unordered_map<std::string, FieldInfo> fields;

    const FieldInfo* field(const std::string& n) const {
        auto it = fields.find(n);
        return it == fields.end() ? nullptr : &it->second;
    }
    bool has_field(const std::string& n) const { return fields.count(n); }
};

class VMMeta {
public:
    explicit VMMeta(Reader* reader);

    Reader* reader() { return reader_; }

    const TypeInfo* type(const std::string& name) const;
    bool has_type(const std::string& name) const;
    const std::unordered_map<std::string, TypeInfo>& types() const { return types_; }

    std::optional<int32_t> int_constant(const std::string& name) const;
    std::optional<uint64_t> long_constant(const std::string& name) const;

    size_t num_types() const { return types_.size(); }
    size_t num_structs() const { return num_structs_; }
    size_t num_int_consts() const { return int_consts_.size(); }
    size_t num_long_consts() const { return long_consts_.size(); }

private:
    void parse();

    Reader* reader_;
    std::unordered_map<std::string, TypeInfo> types_;
    std::unordered_map<std::string, int32_t> int_consts_;
    std::unordered_map<std::string, uint64_t> long_consts_;
    size_t num_structs_ = 0;
};

} // namespace marrow
