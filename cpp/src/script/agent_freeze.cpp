#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <mutex>

namespace marrow {

static std::mutex          g_freeze_mtx;
static std::vector<HANDLE> g_suspended_handles;
static bool                g_suspended = false;

static duk_ret_t js_suspendAll(duk_context* ctx) {
    std::lock_guard<std::mutex> lock(g_freeze_mtx);
    if (g_suspended) {
        duk_push_int(ctx, static_cast<int>(g_suspended_handles.size()));
        return 1;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        duk_push_int(ctx, -1);
        return 1;
    }

    const DWORD our_pid = GetCurrentProcessId();
    const DWORD our_tid = GetCurrentThreadId();
    int count = 0;
    bool partial_failure = false;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != our_pid) continue;
            if (te.th32ThreadID == our_tid)        continue;

            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!h) continue;

            DWORD prev = SuspendThread(h);
            if (prev == static_cast<DWORD>(-1)) {
                CloseHandle(h);
                partial_failure = true;
                continue;
            }
            g_suspended_handles.push_back(h);
            ++count;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    g_suspended = true;
    duk_push_int(ctx, partial_failure ? -1 : count);
    return 1;
}

static duk_ret_t js_resumeAll(duk_context* ctx) {
    std::lock_guard<std::mutex> lock(g_freeze_mtx);
    int count = static_cast<int>(g_suspended_handles.size());
    for (HANDLE h : g_suspended_handles) {
        ResumeThread(h);
        CloseHandle(h);
    }
    g_suspended_handles.clear();
    g_suspended = false;
    duk_push_int(ctx, count);
    return 1;
}

void register_freeze_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_suspendAll, 0);
    duk_put_prop_string(ctx, ns_idx, "_suspendAll");
    duk_push_c_function(ctx, js_resumeAll, 0);
    duk_put_prop_string(ctx, ns_idx, "_resumeAll");
}

} // namespace marrow
