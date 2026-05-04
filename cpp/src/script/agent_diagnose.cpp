#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "agent_js.hpp"
#include "vm_meta.hpp"
#include "walker.hpp"
#include "oop_reader.hpp"
#include "zgc.hpp"
#include "duktape.h"
#include <windows.h>
#include <psapi.h>
#include <cstdio>

namespace marrow {

namespace {

duk_ret_t js_diagnose(duk_context* c) {
    auto* vm = current_vm(c);
    auto* host = current_host(c);
    duk_idx_t o = duk_push_object(c);

    if (vm) {
        duk_push_int(c, (int)vm->types().size());
        duk_put_prop_string(c, o, "vmTypes");
    }

    HMODULE jvm = GetModuleHandleA("jvm.dll");
    if (jvm) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)jvm);
        duk_push_string(c, buf); duk_put_prop_string(c, o, "jvmDll");
        MODULEINFO mi{};
        if (GetModuleInformation(GetCurrentProcess(), jvm, &mi, sizeof(mi))) {
            duk_push_uint(c, mi.SizeOfImage);
            duk_put_prop_string(c, o, "jvmDllSize");
        }
    }

    if (host) {
        auto* dec = static_cast<OopDecoder*>(host->dec_);
        auto* zgc = static_cast<ZGCDecoder*>(host->zgc_);
        if (dec) {
            duk_push_boolean(c, dec->oops_are_compressed());
            duk_put_prop_string(c, o, "oopsCompressed");
            duk_push_boolean(c, dec->compressed_klass());
            duk_put_prop_string(c, o, "klassCompressed");
        }
        if (zgc) {
            duk_push_boolean(c, zgc->is_active());
            duk_put_prop_string(c, o, "zgcActive");
        }
    }

    if (vm) {
        try {
            ClassWalker cw(vm);
            auto klasses = cw.list();
            duk_push_int(c, (int)klasses.size());
            duk_put_prop_string(c, o, "loadedClasses");
        } catch (...) {
            duk_push_int(c, -1);
            duk_put_prop_string(c, o, "loadedClasses");
        }
    }

    // Modules — first 16
    HMODULE mods[64]; DWORD needed = 0;
    duk_idx_t arr = duk_push_array(c);
    duk_uarridx_t i = 0;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        size_t n = needed / sizeof(HMODULE);
        if (n > 16) n = 16;
        for (size_t k = 0; k < n; ++k) {
            char name[MAX_PATH] = {};
            GetModuleBaseNameA(GetCurrentProcess(), mods[k], name, sizeof(name));
            MODULEINFO mi{};
            if (!GetModuleInformation(GetCurrentProcess(), mods[k], &mi, sizeof(mi)))
                continue;
            duk_idx_t mo = duk_push_object(c);
            duk_push_string(c, name); duk_put_prop_string(c, mo, "name");
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)mi.lpBaseOfDll);
            duk_push_string(c, buf); duk_put_prop_string(c, mo, "base");
            duk_push_uint(c, mi.SizeOfImage); duk_put_prop_string(c, mo, "size");
            duk_put_prop_index(c, arr, i++);
        }
    }
    duk_put_prop_string(c, o, "modules");

    duk_push_string(c, "marrow-2026-04-26");
    duk_put_prop_string(c, o, "buildId");
    return 1;
}

// Marrow.vmFieldOffset(typeName, fieldName) -> int | null
// Resolves a field offset within a HotSpot type via vmStructs metadata.
// Returns null if either the type or field is unknown.
duk_ret_t js_vmFieldOffset(duk_context* c) {
    const char* type_name  = duk_require_string(c, 0);
    const char* field_name = duk_require_string(c, 1);
    auto* vm = current_vm(c);
    if (!vm) { duk_push_null(c); return 1; }
    const TypeInfo* t = vm->type(type_name);
    if (!t) { duk_push_null(c); return 1; }
    const FieldInfo* f = t->field(field_name);
    if (!f) { duk_push_null(c); return 1; }
    duk_push_uint(c, (duk_uint_t)f->offset);
    return 1;
}

} // anon

void register_diagnose_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_diagnose, 0);
    duk_put_prop_string(ctx, ns_idx, "diagnose");
    duk_push_c_function(ctx, js_vmFieldOffset, 2);
    duk_put_prop_string(ctx, ns_idx, "vmFieldOffset");
}

} // namespace marrow
