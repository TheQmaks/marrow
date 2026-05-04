#pragma once
// Memory reader abstraction and two concrete backends.
//
//   LocalReader  — loads jvm.dll into our own process (offline dumping).
//   RemoteReader — attaches to a live target via PROCESS_VM_READ/WRITE,
//                  parses the target's PE export table, and exposes
//                  symbol resolution + raw read/write.
//
// Both share the pure-virtual `Reader` interface that VMMeta and every
// higher-level module consumes.

#include <windows.h>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace marrow {

struct MemoryRegion {
    uint64_t base;
    uint64_t size;
    uint32_t protect; // Windows PAGE_* low byte
};

class Reader {
public:
    virtual ~Reader() = default;

    virtual std::vector<uint8_t> read(uint64_t addr, size_t size) = 0;
    virtual uint64_t symbol(const std::string& name) = 0;
    virtual std::optional<uint64_t> opt_symbol(const std::string& name) = 0;
    virtual std::string cstring(uint64_t addr) = 0;

    // Writes only supported by RemoteReader; default impl throws.
    virtual void write(uint64_t addr, const void* data, size_t size);
    virtual uint64_t alloc(size_t size, bool executable = false);
    // Allocate within ±2 GB of `near_addr`. Required for 5-byte JMP REL32
    // patches targeting jvm.dll when the default alloc lands far away.
    virtual uint64_t alloc_near(uint64_t near_addr, size_t size, bool executable);
    virtual void free(uint64_t addr);

    // Enumerate committed regions. LocalReader returns empty (meaningless
    // for in-process layout scanning).
    virtual std::vector<MemoryRegion> enumerate_regions(bool writable_only = true);

    // Convenience typed reads. Little-endian x64 only.
    uint16_t read_u16(uint64_t addr);
    uint32_t read_u32(uint64_t addr);
    uint64_t read_u64(uint64_t addr);
    int32_t  read_i32(uint64_t addr);
    uint64_t read_ptr(uint64_t addr) { return read_u64(addr); }
    size_t   read_size_t(uint64_t addr) { return read_u64(addr); }
};


class LocalReader : public Reader {
public:
    explicit LocalReader(const std::string& dll_path);
    ~LocalReader() override;

    std::vector<uint8_t> read(uint64_t addr, size_t size) override;
    uint64_t symbol(const std::string& name) override;
    std::optional<uint64_t> opt_symbol(const std::string& name) override;
    std::string cstring(uint64_t addr) override;

private:
    HMODULE h_ = nullptr;
    std::string path_;
};


class RemoteReader : public Reader {
public:
    RemoteReader(DWORD pid, const std::string& module_name = "jvm.dll",
                 bool writable = true);
    ~RemoteReader() override;

    std::vector<uint8_t> read(uint64_t addr, size_t size) override;
    uint64_t symbol(const std::string& name) override;
    std::optional<uint64_t> opt_symbol(const std::string& name) override;
    std::string cstring(uint64_t addr) override;

    void write(uint64_t addr, const void* data, size_t size) override;
    uint64_t alloc(size_t size, bool executable) override;
    uint64_t alloc_near(uint64_t near_addr, size_t size, bool executable) override;
    void free(uint64_t addr) override;
    std::vector<MemoryRegion> enumerate_regions(bool writable_only) override;

    DWORD pid() const { return pid_; }
    uint64_t module_base() const { return module_base_; }
    std::string module_path() const { return module_path_; }

private:
    void find_module_and_parse_exports(const std::string& module_name);

    DWORD pid_ = 0;
    HANDLE h_ = nullptr;
    uint64_t module_base_ = 0;
    uint64_t module_size_ = 0;
    std::string module_path_;
    std::unordered_map<std::string, uint64_t> exports_;
    bool writable_ = false;
};

} // namespace marrow
