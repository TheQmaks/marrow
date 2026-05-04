#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

namespace marrow {
namespace {

bool parse_pattern(const char* pat, std::vector<uint8_t>& bytes, std::vector<uint8_t>& mask) {
    while (*pat) {
        while (*pat == ' ' || *pat == '\t') ++pat;
        if (!*pat) break;
        if (pat[0] == '?' && pat[1] == '?') {
            bytes.push_back(0);
            mask.push_back(0);
            pat += 2;
        } else if (isxdigit((unsigned char)pat[0]) && isxdigit((unsigned char)pat[1])) {
            char buf[3] = {pat[0], pat[1], 0};
            bytes.push_back((uint8_t)strtoul(buf, nullptr, 16));
            mask.push_back(1);
            pat += 2;
        } else {
            return false;
        }
    }
    return !bytes.empty();
}

__declspec(noinline) bool seh_memmem(const uint8_t* hay, size_t hay_size,
                                     const std::vector<uint8_t>* bytes,
                                     const std::vector<uint8_t>* mask,
                                     size_t* out_offset, size_t start) {
    __try {
        if (start + bytes->size() > hay_size) return false;
        for (size_t i = start; i + bytes->size() <= hay_size; ++i) {
            bool ok = true;
            for (size_t j = 0; j < bytes->size(); ++j) {
                if ((*mask)[j] && hay[i+j] != (*bytes)[j]) { ok = false; break; }
            }
            if (ok) { *out_offset = i; return true; }
        }
        return false;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

duk_ret_t js_memscan(duk_context* c) {
    const char* mod_name = duk_get_string_default(c, 0, "");
    const char* pattern  = duk_require_string(c, 1);
    int limit = duk_get_int_default(c, 2, 32);
    if (limit > 256) limit = 256;
    duk_idx_t arr = duk_push_array(c);

    std::vector<uint8_t> bytes, mask;
    if (!parse_pattern(pattern, bytes, mask)) return 1;

    HMODULE mods[1024]; DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) return 1;
    size_t n = needed / sizeof(HMODULE);

    duk_uarridx_t out_i = 0;
    for (size_t k = 0; k < n && (int)out_i < limit; ++k) {
        char name[MAX_PATH] = {};
        GetModuleBaseNameA(GetCurrentProcess(), mods[k], name, sizeof(name));
        if (mod_name && *mod_name && _stricmp(name, mod_name) != 0) continue;
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mods[k], &mi, sizeof(mi))) continue;
        const uint8_t* base = (const uint8_t*)mi.lpBaseOfDll;
        size_t size = mi.SizeOfImage;
        size_t pos = 0;
        while (pos + bytes.size() <= size && (int)out_i < limit) {
            size_t found = 0;
            if (!seh_memmem(base, size, &bytes, &mask, &found, pos)) break;
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)(base + found));
            duk_push_string(c, buf);
            duk_put_prop_index(c, arr, out_i++);
            pos = found + 1;
        }
    }
    return 1;
}

} // anon

void register_memscan_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_memscan, 3);
    duk_put_prop_string(ctx, ns_idx, "_memscan");
}

} // namespace marrow
