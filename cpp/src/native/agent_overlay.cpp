// agent_overlay.cpp — OpenGL/GLFW frame-presentation discovery and frame counter.
//
// Exposes three JS bindings on the Marrow namespace:
//   _glDiscover()    — returns {glfwSwapBuffers, wglSwapBuffers, lwjglModules}
//   _glHookFrames()  — installs inline hook via Marrow._inlineHook; returns hookId
//   _glFrameCount()  — delegates to Marrow._inlineHookCount(hookId)
//
// The hook is installed by routing through the existing inline-hook engine in
// agent_inlhook.cpp (which owns the length-disassembler and trampoline logic).
// _glHookFrames retrieves Marrow._inlineHook from the Duktape global object
// and calls it with the swap-buffer address as a hex string.  The returned
// hookId is cached in g_hook_id for subsequent _glFrameCount queries.

#include "agent_modules.hpp"
#include "duktape.h"

#include <windows.h>
#include <psapi.h>

#include <cstdio>
#include <cstring>

namespace marrow {
namespace {

void*  g_glfw_swap   = nullptr;   // glfwSwapBuffers in glfw.dll
void*  g_opengl_swap = nullptr;   // wglSwapBuffers  in opengl32.dll
bool   g_hooked      = false;
int    g_hook_id     = -1;        // hookId returned by _inlineHook, -1 = not installed

// Populate g_glfw_swap / g_opengl_swap from the modules already loaded in
// this process.  Safe to call repeatedly; only overwrites if found.
static void discover_swap_ptrs() {
    HMODULE glfw = GetModuleHandleA("glfw.dll");
    HMODULE gl   = GetModuleHandleA("opengl32.dll");
    if (glfw && !g_glfw_swap)
        g_glfw_swap = reinterpret_cast<void*>(
            GetProcAddress(glfw, "glfwSwapBuffers"));
    if (gl && !g_opengl_swap)
        g_opengl_swap = reinterpret_cast<void*>(
            GetProcAddress(gl, "wglSwapBuffers"));
}

// _glDiscover() -> object
//   {
//     glfwSwapBuffers : "0x<addr>" | null,
//     wglSwapBuffers  : "0x<addr>" | null,
//     lwjglModules    : ["lwjgl_glfw.dll", ...]
//   }
duk_ret_t js_glDiscover(duk_context* ctx) {
    discover_swap_ptrs();

    duk_idx_t obj = duk_push_object(ctx);

    char buf[32];
    if (g_glfw_swap) {
        std::snprintf(buf, sizeof(buf), "0x%llx",
            static_cast<unsigned long long>(
                reinterpret_cast<uintptr_t>(g_glfw_swap)));
        duk_push_string(ctx, buf);
    } else {
        duk_push_null(ctx);
    }
    duk_put_prop_string(ctx, obj, "glfwSwapBuffers");

    if (g_opengl_swap) {
        std::snprintf(buf, sizeof(buf), "0x%llx",
            static_cast<unsigned long long>(
                reinterpret_cast<uintptr_t>(g_opengl_swap)));
        duk_push_string(ctx, buf);
    } else {
        duk_push_null(ctx);
    }
    duk_put_prop_string(ctx, obj, "wglSwapBuffers");

    // Collect every lwjgl*.dll currently mapped in this process.
    duk_idx_t arr = duk_push_array(ctx);
    HMODULE   mods[1024];
    DWORD     needed = 0;
    duk_uarridx_t idx = 0;
    if (EnumProcessModules(GetCurrentProcess(),
                           mods, sizeof(mods), &needed)) {
        size_t n = needed / sizeof(HMODULE);
        for (size_t k = 0; k < n; ++k) {
            char name[MAX_PATH];
            if (GetModuleBaseNameA(GetCurrentProcess(),
                                   mods[k], name, sizeof(name))) {
                if (_strnicmp(name, "lwjgl", 5) == 0) {
                    duk_push_string(ctx, name);
                    duk_put_prop_index(ctx, arr, idx++);
                }
            }
        }
    }
    duk_put_prop_string(ctx, obj, "lwjglModules");

    return 1; // leaves obj on stack
}

// _glHookFrames() -> hookId (int) on success, false on failure.
//   Installs an inline hook on glfwSwapBuffers or wglSwapBuffers via the
//   Marrow._inlineHook binding (which owns the length-disassembler and
//   all trampoline logic).  Re-runs discovery if the swap pointer is still
//   null (handles LWJGL lazy-loading glfw.dll after agent attach).
duk_ret_t js_glHookFrames(duk_context* ctx) {
    // Already installed — return the existing hookId.
    if (g_hook_id >= 0) {
        duk_push_int(ctx, g_hook_id);
        return 1;
    }

    // Re-attempt discovery in case LWJGL loaded glfw.dll after attach.
    if (!g_glfw_swap && !g_opengl_swap)
        discover_swap_ptrs();

    if (!g_glfw_swap && !g_opengl_swap) {
        duk_push_false(ctx);
        return 1;
    }

    // Resolve target address (prefer glfwSwapBuffers).
    void* swap_target = g_glfw_swap ? g_glfw_swap : g_opengl_swap;

    // Retrieve Marrow._inlineHook from the global object.
    // Both overlay and inlhook bindings are registered by install_bindings()
    // before any JS can invoke _glHookFrames, so this lookup always succeeds
    // at call time.
    duk_get_global_string(ctx, "Marrow");
    if (!duk_is_object(ctx, -1)) {
        duk_pop(ctx);
        duk_push_false(ctx);
        return 1;
    }
    duk_get_prop_string(ctx, -1, "_inlineHook");
    if (!duk_is_function(ctx, -1)) {
        duk_pop_2(ctx);
        duk_push_false(ctx);
        return 1;
    }

    // Call Marrow._inlineHook("0x<addr>").
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
        static_cast<unsigned long long>(
            reinterpret_cast<uintptr_t>(swap_target)));
    duk_push_string(ctx, buf);
    if (duk_pcall(ctx, 1) != DUK_EXEC_SUCCESS) {
        // _inlineHook threw — clean up [error, Marrow].
        duk_pop_2(ctx);
        duk_push_false(ctx);
        return 1;
    }

    // Stack: [Marrow, result]
    if (!duk_is_number(ctx, -1)) {
        duk_pop_2(ctx);
        duk_push_false(ctx);
        return 1;
    }
    int hook_id = duk_get_int(ctx, -1);
    duk_pop(ctx);   // pop result

    if (hook_id < 0) {
        duk_pop(ctx);   // pop Marrow
        duk_push_false(ctx);
        return 1;
    }

    g_hook_id = hook_id;
    g_hooked  = true;

    // Emit a log via Marrow.log (best-effort; ignore failures).
    duk_get_prop_string(ctx, -1, "log");
    if (duk_is_function(ctx, -1)) {
        char msg[128];
        std::snprintf(msg, sizeof(msg),
            "[overlay] glfwSwapBuffers hooked at %s -> hookId %d", buf, hook_id);
        duk_push_string(ctx, msg);
        duk_pcall(ctx, 1);
        duk_pop(ctx);   // pop log result
    } else {
        duk_pop(ctx);   // pop non-function
    }

    duk_pop(ctx);   // pop Marrow
    duk_push_int(ctx, hook_id);
    return 1;
}

// _glFrameCount() -> number
//   Delegates to Marrow._inlineHookCount(g_hook_id); returns 0 if hook
//   is not yet installed.
duk_ret_t js_glFrameCount(duk_context* ctx) {
    if (g_hook_id < 0) {
        duk_push_number(ctx, 0.0);
        return 1;
    }

    duk_get_global_string(ctx, "Marrow");
    duk_get_prop_string(ctx, -1, "_inlineHookCount");
    duk_push_int(ctx, g_hook_id);
    if (duk_pcall(ctx, 1) != DUK_EXEC_SUCCESS) {
        duk_pop_2(ctx);
        duk_push_number(ctx, 0.0);
        return 1;
    }
    double n = duk_get_number_default(ctx, -1, 0.0);
    duk_pop_2(ctx);   // pop result + Marrow
    duk_push_number(ctx, n);
    return 1;
}

} // anonymous namespace

void register_overlay_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);

    duk_push_c_function(ctx, js_glDiscover, 0);
    duk_put_prop_string(ctx, ns_idx, "_glDiscover");

    duk_push_c_function(ctx, js_glHookFrames, 0);
    duk_put_prop_string(ctx, ns_idx, "_glHookFrames");

    duk_push_c_function(ctx, js_glFrameCount, 0);
    duk_put_prop_string(ctx, ns_idx, "_glFrameCount");
}

} // namespace marrow
