#include "inproc_reader.hpp"
#include <windows.h>
#include <cstring>
#include <sstream>
#include <stdexcept>

// SEH helper: no C++ destructors in scope, so __try is legal here (MSVC C2712).
static __declspec(noinline) bool seh_memcpy(void* dst, const void* src, size_t n) {
    __try {
        memcpy(dst, src, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

namespace marrow {

InProcessReader::InProcessReader(const std::string& module_name)
    : module_name_(module_name)
{
    // GetModuleHandle first — if module already loaded (the expected case
    // for an injected agent), we just grab the existing mapping. Only
    // call LoadLibrary if it isn't.
    module_ = GetModuleHandleA(module_name.c_str());
    if (!module_) {
        module_ = LoadLibraryA(module_name.c_str());
        if (!module_) {
            std::ostringstream os;
            os << "InProcessReader: cannot load " << module_name
               << " (GetLastError=" << GetLastError() << ")";
            throw std::runtime_error(os.str());
        }
    }
}

InProcessReader::~InProcessReader() {}

std::vector<uint8_t> InProcessReader::read(uint64_t addr, size_t size) {
    std::vector<uint8_t> out(size);
    if (!seh_memcpy(out.data(), reinterpret_cast<const void*>(addr), size)) {
        std::ostringstream os;
        os << "InProcessReader::read AV at 0x" << std::hex << addr
           << " size=" << std::dec << size;
        throw std::runtime_error(os.str());
    }
    return out;
}

uint64_t InProcessReader::symbol(const std::string& name) {
    auto p = GetProcAddress(module_, name.c_str());
    if (!p) throw std::runtime_error("missing export: " + name);
    return reinterpret_cast<uint64_t>(p);
}

std::optional<uint64_t> InProcessReader::opt_symbol(const std::string& name) {
    auto p = GetProcAddress(module_, name.c_str());
    if (!p) return std::nullopt;
    return reinterpret_cast<uint64_t>(p);
}

std::string InProcessReader::cstring(uint64_t addr) {
    if (!addr) return "";
    return std::string(reinterpret_cast<const char*>(addr));
}

void InProcessReader::write(uint64_t addr, const void* data, size_t size) {
    // In-process — just memcpy. If the target page is read-only, flip it
    // with VirtualProtect first.
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        std::memcpy(reinterpret_cast<void*>(addr), data, size);
        return;
    }
    DWORD prot = mbi.Protect & 0xFF;
    bool writable = (prot == PAGE_READWRITE || prot == PAGE_WRITECOPY
                     || prot == PAGE_EXECUTE_READWRITE
                     || prot == PAGE_EXECUTE_WRITECOPY);
    if (writable) {
        std::memcpy(reinterpret_cast<void*>(addr), data, size);
        return;
    }
    DWORD old = 0;
    SIZE_T region = mbi.RegionSize - (addr - reinterpret_cast<uint64_t>(mbi.BaseAddress));
    if (region > size) region = size;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(addr), region, PAGE_READWRITE, &old))
        throw std::runtime_error("VirtualProtect failed");
    std::memcpy(reinterpret_cast<void*>(addr), data, size);
    VirtualProtect(reinterpret_cast<LPVOID>(addr), region, old, &old);
}

uint64_t InProcessReader::alloc(size_t size, bool executable) {
    DWORD prot = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    LPVOID p = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, prot);
    if (!p) throw std::runtime_error("VirtualAlloc failed");
    return reinterpret_cast<uint64_t>(p);
}

uint64_t InProcessReader::alloc_near(uint64_t near_addr, size_t size, bool executable) {
    DWORD prot = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    constexpr uint64_t GRAN = 0x10000;
    constexpr int64_t WINDOW = int64_t(0x7FFFF000);
    uint64_t base = near_addr & ~(GRAN - 1);
    for (int64_t offset = 0; offset < WINDOW; offset += GRAN) {
        for (int dir = 0; dir < 2; ++dir) {
            uint64_t cand = (dir == 0) ? base - uint64_t(offset)
                                       : base + uint64_t(offset);
            LPVOID p = VirtualAlloc(reinterpret_cast<LPVOID>(cand), size,
                                     MEM_COMMIT | MEM_RESERVE, prot);
            if (p) {
                uint64_t r = reinterpret_cast<uint64_t>(p);
                int64_t delta = int64_t(r) - int64_t(near_addr);
                if (delta > -WINDOW && delta < WINDOW) return r;
                VirtualFree(p, 0, MEM_RELEASE);
            }
        }
    }
    throw std::runtime_error("alloc_near (in-process): no region within ±2 GiB");
}

void InProcessReader::free(uint64_t addr) {
    if (addr) VirtualFree(reinterpret_cast<LPVOID>(addr), 0, MEM_RELEASE);
}

std::vector<MemoryRegion> InProcessReader::enumerate_regions(bool writable_only) {
    std::vector<MemoryRegion> out;
    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t addr = 0;
    constexpr uint64_t USER_MAX = 0x00007FFFFFFFFFFFull;
    while (addr < USER_MAX) {
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
            break;
        uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        uint64_t size = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT) {
            uint32_t prot = mbi.Protect & 0xFF;
            bool writable = (prot == 0x04 || prot == 0x40);
            if (!writable_only || writable)
                out.push_back({base, size, prot});
        }
        addr = base + size;
    }
    return out;
}

} // namespace marrow
