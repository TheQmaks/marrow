#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "duktape.h"
#include <windows.h>
#include <cstdlib>
#include <cstring>

namespace marrow {
namespace {

DWORD parse_prot(const char* s) {
    if (!s) return 0;
    if (!std::strcmp(s, "r"))    return PAGE_READONLY;
    if (!std::strcmp(s, "rw"))   return PAGE_READWRITE;
    if (!std::strcmp(s, "rx"))   return PAGE_EXECUTE_READ;
    if (!std::strcmp(s, "rwx"))  return PAGE_EXECUTE_READWRITE;
    if (!std::strcmp(s, "none")) return PAGE_NOACCESS;
    return 0;
}

const char* prot_to_str(DWORD p) {
    switch (p & 0xff) {
        case PAGE_NOACCESS:          return "none";
        case PAGE_READONLY:          return "r";
        case PAGE_READWRITE:         return "rw";
        case PAGE_EXECUTE_READ:      return "rx";
        case PAGE_EXECUTE_READWRITE: return "rwx";
        case PAGE_EXECUTE:           return "x";
        default:                     return "?";
    }
}

duk_ret_t js_memProtect(duk_context* c) {
    const char* addr_hex = duk_require_string(c, 0);
    int size = duk_require_int(c, 1);
    const char* prot_str = duk_require_string(c, 2);
    if (size <= 0 || size > (1 << 20)) { duk_push_null(c); return 1; }
    DWORD prot = parse_prot(prot_str);
    if (!prot) { duk_push_null(c); return 1; }
    uint64_t addr = std::strtoull(addr_hex, nullptr, 0);
    if (!addr) { duk_push_null(c); return 1; }
    DWORD old_prot = 0;
    BOOL ok = VirtualProtect(reinterpret_cast<void*>(addr), (SIZE_T)size, prot, &old_prot);
    if (!ok) { duk_push_null(c); return 1; }
    duk_push_string(c, prot_to_str(old_prot));
    return 1;
}

} // anon

void register_memprotect_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_memProtect, 3);
    duk_put_prop_string(ctx, ns_idx, "_memProtect");
}

} // namespace marrow
