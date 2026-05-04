#pragma once
// Reader that operates on the CURRENT process's memory directly. Used by
// an injected DLL agent — jvm.dll is already mapped in our address space,
// so RPM/WPM are unnecessary and far slower than direct dereferencing.
//
// Every module in marrow_core (oop_reader, klass_cloner, hooks, ...)
// talks through the Reader abstraction, so handing them an InProcessReader
// instantly makes the entire library work from inside the target.

#include "reader.hpp"
#include <cstdint>
#include <string>
#include <unordered_map>

namespace marrow {

class InProcessReader : public Reader {
public:
    // `module_name` is loaded (or incremented refcount if already loaded)
    // via LoadLibraryEx just to pin it and to get a handle for
    // GetProcAddress. For the common case of injected DLL in a JVM
    // process, jvm.dll is already in memory.
    explicit InProcessReader(const std::string& module_name = "jvm.dll");
    ~InProcessReader() override;

    std::vector<uint8_t> read(uint64_t addr, size_t size) override;
    uint64_t symbol(const std::string& name) override;
    std::optional<uint64_t> opt_symbol(const std::string& name) override;
    std::string cstring(uint64_t addr) override;

    void write(uint64_t addr, const void* data, size_t size) override;
    uint64_t alloc(size_t size, bool executable = false) override;
    uint64_t alloc_near(uint64_t near_addr, size_t size, bool executable) override;
    void free(uint64_t addr) override;
    std::vector<MemoryRegion> enumerate_regions(bool writable_only) override;

private:
    HMODULE module_ = nullptr;
    std::string module_name_;
};

} // namespace marrow
