#pragma once
// DLL injection + hardware watchpoints + shared control block.
//
// `inject_dll` uses the classic CreateRemoteThread(LoadLibraryA) trick.
// The shared control block mirrors watcher.cpp::ControlBlock — we use a
// named file mapping so the injected watcher DLL and our Python/C++
// process can coordinate through the same page.
//
// DR0-DR3 hardware watchpoints are armed per-thread via SuspendThread +
// SetThreadContext. The watcher DLL's VEH translates the resulting
// EXCEPTION_SINGLE_STEP into counter updates.

#include <cstdint>
#include <string>
#include <vector>

namespace marrow {

constexpr size_t CONTROL_BLOCK_SIZE = 56;
constexpr const char* SHARED_NAME = "Local\\jvm-probe-watch-v1";

// Named shared-memory region the injected watcher and our process share.
// Creating two instances with the same name returns handles to the same
// underlying page.
class SharedControlBlock {
public:
    SharedControlBlock();
    ~SharedControlBlock();
    SharedControlBlock(const SharedControlBlock&) = delete;
    SharedControlBlock& operator=(const SharedControlBlock&) = delete;

    uint64_t addr() const { return addr_; }   // our-process address
    void     clear();

    void set_watched(uint64_t target_addr);
    uint64_t get_watched() const;
    uint64_t get_count() const;
    uint64_t get_last_fault_rip() const;
    uint64_t get_last_fault_addr() const;
    bool     is_installed() const;

private:
    void*    file_mapping_ = nullptr;
    uint8_t* view_         = nullptr;
    uint64_t addr_         = 0;
};

// Load `dll_path` into `pid`. Returns LoadLibraryA's HMODULE truncated to
// DWORD (the thread exit code we get back from CreateRemoteThread).
uint32_t inject_dll(uint32_t pid, const std::string& dll_path,
                     uint32_t timeout_ms = 5000);

// Arm DR<slot> across every thread of the target process. Returns how
// many threads accepted the SetThreadContext.
int set_hw_watchpoint(uint32_t pid, uint64_t addr,
                       int length = 4, int slot = 0, bool write_only = true);

int clear_hw_watchpoint(uint32_t pid, int slot = 0);

// Flip the page at `addr` in the target to PAGE_READONLY (or back to RW).
// Returns the previous protection value.
uint32_t protect_remote_page(uint32_t pid, uint64_t addr, bool readonly = true);

} // namespace marrow
