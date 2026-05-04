#include "reader.hpp"
#ifndef DONT_RESOLVE_DLL_REFS
#define DONT_RESOLVE_DLL_REFS 0x00000001
#endif
#include <tlhelp32.h>
#include <cstring>
#include <stdexcept>
#include <sstream>

namespace marrow {

static std::string win_error(const std::string& fn) {
    std::ostringstream os;
    os << fn << " failed: Windows error " << GetLastError();
    return os.str();
}

// --- Reader base methods ---

void Reader::write(uint64_t, const void*, size_t) {
    throw std::logic_error("this Reader is read-only");
}
uint64_t Reader::alloc(size_t, bool) {
    throw std::logic_error("this Reader doesn't support alloc");
}
uint64_t Reader::alloc_near(uint64_t, size_t, bool) {
    throw std::logic_error("this Reader doesn't support alloc_near");
}
void Reader::free(uint64_t) {}
std::vector<MemoryRegion> Reader::enumerate_regions(bool) {
    return {};
}

uint16_t Reader::read_u16(uint64_t addr) {
    auto b = read(addr, 2);
    return uint16_t(b[0]) | (uint16_t(b[1]) << 8);
}
uint32_t Reader::read_u32(uint64_t addr) {
    auto b = read(addr, 4);
    return uint32_t(b[0]) | (uint32_t(b[1]) << 8)
         | (uint32_t(b[2]) << 16) | (uint32_t(b[3]) << 24);
}
uint64_t Reader::read_u64(uint64_t addr) {
    auto b = read(addr, 8);
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | b[i];
    return v;
}
int32_t Reader::read_i32(uint64_t addr) {
    return static_cast<int32_t>(read_u32(addr));
}


// --- LocalReader ---

LocalReader::LocalReader(const std::string& dll_path) : path_(dll_path) {
    h_ = LoadLibraryExA(dll_path.c_str(), nullptr, DONT_RESOLVE_DLL_REFS);
    if (!h_) throw std::runtime_error(win_error("LoadLibraryEx(" + dll_path + ")"));
}

LocalReader::~LocalReader() { if (h_) FreeLibrary(h_); }

std::vector<uint8_t> LocalReader::read(uint64_t addr, size_t size) {
    std::vector<uint8_t> out(size);
    std::memcpy(out.data(), reinterpret_cast<const void*>(addr), size);
    return out;
}

uint64_t LocalReader::symbol(const std::string& name) {
    auto p = GetProcAddress(h_, name.c_str());
    if (!p) throw std::runtime_error("missing export: " + name);
    return reinterpret_cast<uint64_t>(p);
}

std::optional<uint64_t> LocalReader::opt_symbol(const std::string& name) {
    auto p = GetProcAddress(h_, name.c_str());
    if (!p) return std::nullopt;
    return reinterpret_cast<uint64_t>(p);
}

std::string LocalReader::cstring(uint64_t addr) {
    if (!addr) return "";
    return std::string(reinterpret_cast<const char*>(addr));
}


// --- RemoteReader ---

static std::string to_lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    return s;
}

static std::string utf16_to_utf8(const wchar_t* w) {
    if (!w) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string s(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
    return s;
}

RemoteReader::RemoteReader(DWORD pid, const std::string& module_name, bool writable)
    : pid_(pid), writable_(writable)
{
    DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    if (writable) access |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    h_ = OpenProcess(access, FALSE, pid);
    if (!h_) throw std::runtime_error(win_error("OpenProcess"));
    find_module_and_parse_exports(module_name);
}

RemoteReader::~RemoteReader() { if (h_) CloseHandle(h_); }

void RemoteReader::find_module_and_parse_exports(const std::string& wanted) {
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
    if (snap == INVALID_HANDLE_VALUE)
        throw std::runtime_error(win_error("CreateToolhelp32Snapshot"));

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    std::string wlow = to_lower(wanted);
    if (Module32FirstW(snap, &me)) {
        do {
            std::string mod = utf16_to_utf8(me.szModule);
            if (to_lower(mod) == wlow) {
                module_base_ = reinterpret_cast<uint64_t>(me.modBaseAddr);
                module_size_ = me.modBaseSize;
                module_path_ = utf16_to_utf8(me.szExePath);
                found = true; break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    if (!found)
        throw std::runtime_error("module not found in pid: " + wanted);

    // Parse PE export table.
    auto dos = read(module_base_, 64);
    if (dos[0] != 'M' || dos[1] != 'Z')
        throw std::runtime_error("not a PE image");
    int32_t e_lfanew = int32_t(dos[0x3C]) | (int32_t(dos[0x3D]) << 8)
                     | (int32_t(dos[0x3E]) << 16) | (int32_t(dos[0x3F]) << 24);

    auto nt = read(module_base_ + e_lfanew, 24 + 240);
    if (!(nt[0] == 'P' && nt[1] == 'E' && nt[2] == 0 && nt[3] == 0))
        throw std::runtime_error("bad NT signature");
    // OptionalHeader starts at +24; Magic must be 0x20B for PE32+ x64.
    uint16_t magic = uint16_t(nt[24]) | (uint16_t(nt[25]) << 8);
    if (magic != 0x20B)
        throw std::runtime_error("not PE32+ x64");
    // DataDirectory[0] (Export Directory) at offset 24 + 112 = 136.
    uint32_t exp_rva = 0, exp_size = 0;
    std::memcpy(&exp_rva, nt.data() + 24 + 112, 4);
    std::memcpy(&exp_size, nt.data() + 24 + 116, 4);
    if (!exp_rva || !exp_size) return;
    uint64_t exp_start = module_base_ + exp_rva;
    uint64_t exp_end   = exp_start + exp_size;

    auto exp = read(exp_start, 40);
    uint32_t n_funcs, n_names, af_rva, an_rva, ao_rva;
    std::memcpy(&n_funcs, exp.data() + 20, 4);
    std::memcpy(&n_names, exp.data() + 24, 4);
    std::memcpy(&af_rva,  exp.data() + 28, 4);
    std::memcpy(&an_rva,  exp.data() + 32, 4);
    std::memcpy(&ao_rva,  exp.data() + 36, 4);

    auto funcs = read(module_base_ + af_rva, n_funcs * 4);
    auto names = read(module_base_ + an_rva, n_names * 4);
    auto ords  = read(module_base_ + ao_rva, n_names * 2);

    for (uint32_t i = 0; i < n_names; ++i) {
        uint32_t name_rva;
        std::memcpy(&name_rva, names.data() + i * 4, 4);
        std::string nm = cstring(module_base_ + name_rva);
        uint16_t ord;
        std::memcpy(&ord, ords.data() + i * 2, 2);
        uint32_t func_rva;
        std::memcpy(&func_rva, funcs.data() + ord * 4, 4);
        uint64_t func_abs = module_base_ + func_rva;
        // Skip forwarded exports (RVA falls within the export dir range).
        if (func_abs >= exp_start && func_abs < exp_end) continue;
        exports_.emplace(std::move(nm), func_abs);
    }
}

std::vector<uint8_t> RemoteReader::read(uint64_t addr, size_t size) {
    std::vector<uint8_t> out(size);
    SIZE_T got = 0;
    if (!ReadProcessMemory(h_, reinterpret_cast<LPCVOID>(addr),
                           out.data(), size, &got) || got != size) {
        std::ostringstream os;
        os << "ReadProcessMemory(" << std::hex << addr << ", " << std::dec
           << size << ") failed: " << GetLastError();
        throw std::runtime_error(os.str());
    }
    return out;
}

uint64_t RemoteReader::symbol(const std::string& name) {
    auto it = exports_.find(name);
    if (it == exports_.end())
        throw std::runtime_error("export not in pid: " + name);
    return it->second;
}

std::optional<uint64_t> RemoteReader::opt_symbol(const std::string& name) {
    auto it = exports_.find(name);
    if (it == exports_.end()) return std::nullopt;
    return it->second;
}

std::string RemoteReader::cstring(uint64_t addr) {
    if (!addr) return "";
    std::string out;
    constexpr size_t chunk = 64;
    constexpr size_t cap = 4096;
    while (out.size() < cap) {
        try {
            auto bytes = read(addr + out.size(), chunk);
            size_t i = 0;
            for (; i < bytes.size(); ++i)
                if (bytes[i] == 0) { out.append(
                    reinterpret_cast<const char*>(bytes.data()), i); return out; }
            out.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        } catch (...) {
            return out;
        }
    }
    return out;
}

void RemoteReader::write(uint64_t addr, const void* data, size_t size) {
    if (!writable_) throw std::logic_error("RemoteReader not opened writable");
    SIZE_T written = 0;
    // First attempt as-is. WriteProcessMemory auto-grants write on
    // read-only pages when the handle has PROCESS_VM_OPERATION, so this
    // covers almost every Java-heap slot. On TRUE, Windows guarantees
    // `written == size` — verifying it defensively.
    BOOL ok = WriteProcessMemory(h_, reinterpret_cast<LPVOID>(addr),
                                 data, size, &written);
    if (ok && written == size) return;
    // Some Windows/page-protection combinations (observed on Shenandoah's
    // wide-oop heap regions) return FALSE from WPM even though the bytes
    // did land. Verify by reading back before falling into VPE, which
    // itself can refuse with ERROR 87 on those regions.
    try {
        auto rb = read(addr, size);
        if (rb.size() == size &&
            std::memcmp(rb.data(), data, size) == 0) return;
    } catch (...) {}
    // Fallback: explicitly flip the covering page(s) to PAGE_READWRITE.
    // Use VirtualQueryEx for the exact region span — VPE returns error 87
    // if the length crosses multiple VA ranges.
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T vq = VirtualQueryEx(h_, reinterpret_cast<LPCVOID>(addr),
                               &mbi, sizeof(mbi));
    if (vq == 0) {
        // VQE can refuse very small or otherwise suspicious addresses
        // (rare but seen). If WPM already succeeded semantically (the
        // common case on heap slots), treat it as best-effort and return.
        if (written == size) return;
        throw std::runtime_error(win_error("VirtualQueryEx"));
    }
    uint64_t page_base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
    SIZE_T offset_in_region = size_t(addr - page_base);
    SIZE_T region_len = offset_in_region + size;
    SIZE_T region_cap = mbi.RegionSize - offset_in_region;
    if (region_len > region_cap) region_len = region_cap;
    DWORD old = 0;
    if (!VirtualProtectEx(h_, reinterpret_cast<LPVOID>(addr), region_len,
                          PAGE_READWRITE, &old)) {
        if (written == size) return;  // first WPM already wrote it
        throw std::runtime_error(win_error("VirtualProtectEx"));
    }
    WriteProcessMemory(h_, reinterpret_cast<LPVOID>(addr), data, size, &written);
    VirtualProtectEx(h_, reinterpret_cast<LPVOID>(addr), region_len, old, &old);
    if (written != size)
        throw std::runtime_error("WriteProcessMemory short");
}

uint64_t RemoteReader::alloc(size_t size, bool executable) {
    if (!writable_) throw std::logic_error("RemoteReader read-only");
    DWORD prot = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    LPVOID addr = VirtualAllocEx(h_, nullptr, size,
                                  MEM_COMMIT | MEM_RESERVE, prot);
    if (!addr) throw std::runtime_error(win_error("VirtualAllocEx"));
    return reinterpret_cast<uint64_t>(addr);
}

void RemoteReader::free(uint64_t addr) {
    if (addr && h_) VirtualFreeEx(h_, reinterpret_cast<LPVOID>(addr), 0, MEM_RELEASE);
}

uint64_t RemoteReader::alloc_near(uint64_t near_addr, size_t size, bool executable) {
    if (!writable_) throw std::logic_error("RemoteReader read-only");
    DWORD prot = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    // VirtualAllocEx allocates at the given hint only if the hint is
    // available and falls on allocation granularity (64 KiB). We walk
    // outward from `near_addr` in 64 KiB steps until an allocation
    // succeeds or we leave the ±2 GiB window.
    constexpr uint64_t GRAN = 0x10000; // 64 KiB allocation granularity
    constexpr int64_t WINDOW = int64_t(0x7FFFF000); // safe ~2 GiB
    uint64_t base = (near_addr & ~(GRAN - 1));
    for (int64_t offset = 0; offset < WINDOW; offset += GRAN) {
        for (int dir = 0; dir < 2; ++dir) {
            uint64_t cand = (dir == 0) ? base - uint64_t(offset)
                                       : base + uint64_t(offset);
            LPVOID addr = VirtualAllocEx(h_, reinterpret_cast<LPVOID>(cand),
                                          size, MEM_COMMIT | MEM_RESERVE, prot);
            if (addr) {
                uint64_t r = reinterpret_cast<uint64_t>(addr);
                int64_t delta = int64_t(r) - int64_t(near_addr);
                if (delta > -WINDOW && delta < WINDOW) return r;
                VirtualFreeEx(h_, addr, 0, MEM_RELEASE);
            }
        }
    }
    throw std::runtime_error("alloc_near: no free region within ±2 GiB");
}

std::vector<MemoryRegion> RemoteReader::enumerate_regions(bool writable_only) {
    std::vector<MemoryRegion> out;
    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t addr = 0;
    constexpr uint64_t USER_MAX = 0x00007FFFFFFFFFFFull;
    while (addr < USER_MAX) {
        SIZE_T ret = VirtualQueryEx(h_, reinterpret_cast<LPCVOID>(addr),
                                    &mbi, sizeof(mbi));
        if (ret == 0) break;
        uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        uint64_t size = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT) {
            uint32_t prot = mbi.Protect & 0xFF;
            // 0x04 = RW, 0x40 = ExecuteReadWrite, 0x02 = ReadOnly, 0x20 = ExecuteRead
            bool writable = (prot == 0x04 || prot == 0x40);
            if (!writable_only || writable)
                out.push_back({base, size, prot});
        }
        addr = base + size;
    }
    return out;
}

} // namespace marrow
