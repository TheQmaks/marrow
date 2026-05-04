// In-process watcher DLL for hardware-assisted field monitoring.
//
// Python injects this DLL into a target JVM via CreateRemoteThread +
// LoadLibrary. On attach we open a named shared-memory section that the
// injector created, install a vectored exception handler, and use it
// together with a one-page VirtualProtect toggle to log every write to
// the watched field.
//
// Flow per hit:
//     1. Page holding watched address is PAGE_READONLY.
//     2. Target writes into it       -> STATUS_ACCESS_VIOLATION.
//     3. Our VEH verifies fault is a write inside the watched page,
//        increments the shared counter, unprotects the page, sets TF
//        (trap flag) on the context, and resumes execution.
//     4. CPU completes the write, then single-steps -> EXCEPTION_SINGLE_STEP.
//     5. Our VEH re-protects the page and resumes.
//
// `g_step_pending` exists so we don't mistake unrelated single-step
// exceptions (e.g. a debugger) for our own.

#include <windows.h>
#include <cstdint>

struct ControlBlock {
    volatile uintptr_t watched_addr;       // 0 = disabled
    volatile uint64_t  write_count;        // page-protect hits (per fault)
    volatile uintptr_t last_fault_rip;     // diagnostic
    volatile uintptr_t last_fault_addr;
    volatile int       installed;          // DLL sets 1 when VEH registered
    volatile int       _pad;
    volatile uint64_t  hw_write_count;     // DR0-DR3 hardware watchpoint hits
    volatile uint64_t  last_hw_rip;
};

static ControlBlock* g_ctl = nullptr;
static PVOID         g_veh = nullptr;
static volatile LONG g_step_pending = 0;

static uintptr_t page_of(uintptr_t a) { return a & ~(uintptr_t)0xFFF; }

static LONG CALLBACK VehHandler(PEXCEPTION_POINTERS info) {
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    const auto  ctl  = g_ctl;
    if (!ctl) return EXCEPTION_CONTINUE_SEARCH;

    if (code == EXCEPTION_SINGLE_STEP) {
        // Two possible causes for a single-step inside our process:
        //   (a) a CPU debug register (DR0..DR3) watchpoint fired — bits
        //       B0..B3 set in DR6. Log as a hardware hit, clear the
        //       bits, and resume. The DR config stays armed.
        //   (b) our own TF flag from the page-protect flow. Reprotect.
        // Order matters: check hardware bits first because they can
        // coexist with (b) only if the same instruction both wrote and
        // tripped DR — unusual but handled cleanly by checking DR first.
        const uint64_t dr6_triggers = info->ContextRecord->Dr6 & 0xF;
        if (dr6_triggers) {
            InterlockedIncrement64((LONG64*)&ctl->hw_write_count);
            ctl->last_hw_rip = info->ContextRecord->Rip;
            // Clear the trigger indicator bits so subsequent hits
            // register; leave the configuration (DR0..DR3, DR7) alone.
            info->ContextRecord->Dr6 &= ~(DWORD64)0xF;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (InterlockedExchange(&g_step_pending, 0) == 0) {
            return EXCEPTION_CONTINUE_SEARCH; // not ours
        }
        // Re-arm the protection: write already landed.
        if (ctl->watched_addr) {
            DWORD old = 0;
            VirtualProtect((LPVOID)page_of(ctl->watched_addr), 0x1000,
                           PAGE_READONLY, &old);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code != STATUS_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
    if (info->ExceptionRecord->NumberParameters < 2) return EXCEPTION_CONTINUE_SEARCH;
    if (info->ExceptionRecord->ExceptionInformation[0] != 1) {
        // Not a write access — let JVM's own handlers deal with it.
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const uintptr_t fault  = (uintptr_t)info->ExceptionRecord->ExceptionInformation[1];
    const uintptr_t target = ctl->watched_addr;
    if (!target || page_of(fault) != page_of(target)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    InterlockedIncrement64((LONG64*)&ctl->write_count);
    ctl->last_fault_addr = fault;
    ctl->last_fault_rip  = info->ContextRecord->Rip;

    DWORD old = 0;
    VirtualProtect((LPVOID)page_of(target), 0x1000, PAGE_READWRITE, &old);

    // Trap flag: CPU single-steps after the offending write completes.
    InterlockedExchange(&g_step_pending, 1);
    info->ContextRecord->EFlags |= 0x100;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static bool attach_shared(HINSTANCE hinst) {
    HANDLE h = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE,
                                "Local\\jvm-probe-watch-v1");
    if (!h) return false;
    g_ctl = (ControlBlock*)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0,
                                          sizeof(ControlBlock));
    CloseHandle(h);
    if (!g_ctl) return false;

    g_veh = AddVectoredExceptionHandler(/*first=*/1, VehHandler);
    if (!g_veh) {
        UnmapViewOfFile(g_ctl);
        g_ctl = nullptr;
        return false;
    }
    g_ctl->installed = 1;
    return true;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinst);
        attach_shared(hinst);
        break;
    case DLL_PROCESS_DETACH:
        if (g_veh) {
            RemoveVectoredExceptionHandler(g_veh);
            g_veh = nullptr;
        }
        if (g_ctl) {
            UnmapViewOfFile(g_ctl);
            g_ctl = nullptr;
        }
        break;
    }
    return TRUE;
}
