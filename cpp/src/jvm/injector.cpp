#include "injector.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <cstring>
#include <sstream>
#include <stdexcept>

namespace marrow {

static std::string win_error(const std::string& fn) {
    std::ostringstream os;
    os << fn << ": Windows error " << GetLastError();
    return os.str();
}

// --- SharedControlBlock ---------------------------------------------------

SharedControlBlock::SharedControlBlock() {
    HANDLE h = CreateFileMappingA(
        INVALID_HANDLE_VALUE, nullptr,
        PAGE_READWRITE, 0, CONTROL_BLOCK_SIZE, SHARED_NAME);
    if (!h) throw std::runtime_error(win_error("CreateFileMapping"));
    file_mapping_ = h;
    void* view = MapViewOfFile(h, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                                CONTROL_BLOCK_SIZE);
    if (!view) {
        CloseHandle(h);
        throw std::runtime_error(win_error("MapViewOfFile"));
    }
    view_ = static_cast<uint8_t*>(view);
    addr_ = reinterpret_cast<uint64_t>(view_);
    clear();
}

SharedControlBlock::~SharedControlBlock() {
    if (view_) UnmapViewOfFile(view_);
    if (file_mapping_) CloseHandle(HANDLE(file_mapping_));
}

void SharedControlBlock::clear() {
    std::memset(view_, 0, CONTROL_BLOCK_SIZE);
}

void SharedControlBlock::set_watched(uint64_t addr) {
    std::memcpy(view_ + 0, &addr, 8);
}
uint64_t SharedControlBlock::get_watched() const {
    uint64_t v; std::memcpy(&v, view_ + 0, 8); return v;
}
uint64_t SharedControlBlock::get_count() const {
    uint64_t v; std::memcpy(&v, view_ + 8, 8); return v;
}
uint64_t SharedControlBlock::get_last_fault_rip() const {
    uint64_t v; std::memcpy(&v, view_ + 16, 8); return v;
}
uint64_t SharedControlBlock::get_last_fault_addr() const {
    uint64_t v; std::memcpy(&v, view_ + 24, 8); return v;
}
bool SharedControlBlock::is_installed() const {
    int32_t v; std::memcpy(&v, view_ + 32, 4); return v == 1;
}

// --- DLL injection --------------------------------------------------------

uint32_t inject_dll(uint32_t pid, const std::string& dll_path,
                     uint32_t timeout_ms)
{
    HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hproc) throw std::runtime_error(win_error("OpenProcess"));
    LPVOID remote = nullptr;
    HANDLE hthread = nullptr;
    uint32_t exit_code = 0;
    try {
        std::string path_nt = dll_path + '\0';
        remote = VirtualAllocEx(hproc, nullptr, path_nt.size(),
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote) throw std::runtime_error(win_error("VirtualAllocEx(path)"));
        SIZE_T written = 0;
        if (!WriteProcessMemory(hproc, remote, path_nt.data(),
                                 path_nt.size(), &written)
                || written != path_nt.size())
            throw std::runtime_error(win_error("WriteProcessMemory(path)"));
        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        FARPROC load = GetProcAddress(k32, "LoadLibraryA");
        if (!load) throw std::runtime_error(win_error("GetProcAddress(LoadLibraryA)"));
        DWORD tid = 0;
        hthread = CreateRemoteThread(
            hproc, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(load),
            remote, 0, &tid);
        if (!hthread) throw std::runtime_error(win_error("CreateRemoteThread"));
        if (WaitForSingleObject(hthread, timeout_ms) != WAIT_OBJECT_0)
            throw std::runtime_error("injected thread did not finish in time");
        DWORD ec = 0;
        GetExitCodeThread(hthread, &ec);
        exit_code = ec;
    } catch (...) {
        if (hthread) CloseHandle(hthread);
        if (remote) VirtualFreeEx(hproc, remote, 0, MEM_RELEASE);
        CloseHandle(hproc);
        throw;
    }
    CloseHandle(hthread);
    VirtualFreeEx(hproc, remote, 0, MEM_RELEASE);
    CloseHandle(hproc);
    return exit_code;
}

// --- Hardware watchpoints (DR0..DR3) --------------------------------------

static constexpr DWORD CTX_AMD64_FLAG = 0x00100000;
static constexpr DWORD CTX_DR_FLAG = CTX_AMD64_FLAG | 0x10;
static constexpr DWORD THREAD_DR_ACCESS = THREAD_GET_CONTEXT
                                          | THREAD_SET_CONTEXT
                                          | THREAD_SUSPEND_RESUME;

static std::vector<uint32_t> enumerate_thread_ids(uint32_t pid)
{
    std::vector<uint32_t> tids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        throw std::runtime_error(win_error("CreateToolhelp32Snapshot"));
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid)
                tids.push_back(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tids;
}

static uint64_t dr7_for_slot(int slot, int length, bool write_only)
{
    int len_code;
    switch (length) {
        case 1: len_code = 0; break;
        case 2: len_code = 1; break;
        case 4: len_code = 3; break;
        case 8: len_code = 2; break;
        default: throw std::runtime_error("hw watch length must be 1/2/4/8");
    }
    int rw_code = write_only ? 1 : 3;
    return (uint64_t(1) << (slot * 2))
         | (uint64_t(rw_code) << (16 + slot * 4))
         | (uint64_t(len_code) << (18 + slot * 4));
}

static uint64_t dr7_clear_mask(int slot) {
    return (uint64_t(0b11) << (slot * 2))
         | (uint64_t(0b1111) << (16 + slot * 4));
}

static uint64_t& dr_slot(CONTEXT& ctx, int slot) {
    switch (slot) {
        case 0: return ctx.Dr0;
        case 1: return ctx.Dr1;
        case 2: return ctx.Dr2;
        case 3: return ctx.Dr3;
    }
    throw std::runtime_error("slot must be 0..3");
}

int set_hw_watchpoint(uint32_t pid, uint64_t addr, int length,
                      int slot, bool write_only)
{
    int ok = 0;
    uint64_t dr7_bits = dr7_for_slot(slot, length, write_only);
    for (uint32_t tid : enumerate_thread_ids(pid)) {
        HANDLE h = OpenThread(THREAD_DR_ACCESS, FALSE, tid);
        if (!h) continue;
        SuspendThread(h);
        CONTEXT ctx{};
        ctx.ContextFlags = CTX_DR_FLAG;
        if (GetThreadContext(h, &ctx)) {
            dr_slot(ctx, slot) = addr;
            ctx.Dr7 = (ctx.Dr7 & ~dr7_clear_mask(slot)) | dr7_bits;
            ctx.ContextFlags = CTX_DR_FLAG;
            if (SetThreadContext(h, &ctx)) ++ok;
        }
        ResumeThread(h);
        CloseHandle(h);
    }
    return ok;
}

int clear_hw_watchpoint(uint32_t pid, int slot)
{
    int ok = 0;
    for (uint32_t tid : enumerate_thread_ids(pid)) {
        HANDLE h = OpenThread(THREAD_DR_ACCESS, FALSE, tid);
        if (!h) continue;
        SuspendThread(h);
        CONTEXT ctx{};
        ctx.ContextFlags = CTX_DR_FLAG;
        if (GetThreadContext(h, &ctx)) {
            dr_slot(ctx, slot) = 0;
            ctx.Dr7 &= ~dr7_clear_mask(slot);
            ctx.ContextFlags = CTX_DR_FLAG;
            if (SetThreadContext(h, &ctx)) ++ok;
        }
        ResumeThread(h);
        CloseHandle(h);
    }
    return ok;
}

uint32_t protect_remote_page(uint32_t pid, uint64_t addr, bool readonly)
{
    HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hproc) throw std::runtime_error(win_error("OpenProcess"));
    uint64_t page = addr & ~uint64_t(0xFFF);
    DWORD new_prot = readonly ? PAGE_READONLY : PAGE_READWRITE;
    DWORD old = 0;
    if (!VirtualProtectEx(hproc, reinterpret_cast<LPVOID>(page),
                          0x1000, new_prot, &old)) {
        CloseHandle(hproc);
        throw std::runtime_error(win_error("VirtualProtectEx"));
    }
    CloseHandle(hproc);
    return old;
}

} // namespace marrow
