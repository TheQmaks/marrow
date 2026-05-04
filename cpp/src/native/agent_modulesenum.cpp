#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdlib>

namespace marrow {
namespace {

duk_ret_t js_modules(duk_context* c) {
    HMODULE mods[1024];
    DWORD needed = 0;
    duk_idx_t arr = duk_push_array(c);
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
        return 1;
    size_t n = needed / sizeof(HMODULE);
    duk_uarridx_t out_i = 0;
    for (size_t i = 0; i < n; ++i) {
        char name[MAX_PATH] = {};
        GetModuleBaseNameA(GetCurrentProcess(), mods[i], name, sizeof(name));
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi)))
            continue;
        duk_idx_t o = duk_push_object(c);
        duk_push_string(c, name); duk_put_prop_string(c, o, "name");
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)mi.lpBaseOfDll);
        duk_push_string(c, buf); duk_put_prop_string(c, o, "base");
        duk_push_uint(c, mi.SizeOfImage); duk_put_prop_string(c, o, "size");
        duk_put_prop_index(c, arr, out_i++);
    }
    return 1;
}

duk_ret_t js_moduleAt(duk_context* c) {
    const char* va_hex = duk_require_string(c, 0);
    uint64_t va = strtoull(va_hex, nullptr, 0);
    if (!va) { duk_push_null(c); return 1; }

    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        duk_push_null(c); return 1;
    }
    size_t n = needed / sizeof(HMODULE);
    for (size_t i = 0; i < n; ++i) {
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi)))
            continue;
        uint64_t base = (uint64_t)mi.lpBaseOfDll;
        uint64_t end  = base + mi.SizeOfImage;
        if (va >= base && va < end) {
            char name[MAX_PATH] = {};
            GetModuleBaseNameA(GetCurrentProcess(), mods[i], name, sizeof(name));
            duk_idx_t o = duk_push_object(c);
            duk_push_string(c, name); duk_put_prop_string(c, o, "name");
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)base);
            duk_push_string(c, buf); duk_put_prop_string(c, o, "base");
            duk_push_uint(c, mi.SizeOfImage); duk_put_prop_string(c, o, "size");
            std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)(va - base));
            duk_push_string(c, buf); duk_put_prop_string(c, o, "offset");
            return 1;
        }
    }
    duk_push_null(c);
    return 1;
}

duk_ret_t js_symbolAt(duk_context* c) {
    const char* mod = duk_require_string(c, 0);
    const char* sym = duk_require_string(c, 1);
    HMODULE h = GetModuleHandleA(mod);
    if (!h) { duk_push_null(c); return 1; }
    void* addr = reinterpret_cast<void*>(GetProcAddress(h, sym));
    if (!addr) { duk_push_null(c); return 1; }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)addr);
    duk_push_string(c, buf);
    return 1;
}

} // anon

void register_modulesenum_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_modules, 0);
    duk_put_prop_string(ctx, ns_idx, "modules");
    duk_push_c_function(ctx, js_moduleAt, 1);
    duk_put_prop_string(ctx, ns_idx, "moduleAt");
    duk_push_c_function(ctx, js_symbolAt, 2);
    duk_put_prop_string(ctx, ns_idx, "symbolAt");
}

} // namespace marrow
