#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace marrow {
namespace {

__declspec(noinline) static bool seh_memcpy_write(void* dst, const void* src, size_t n) {
    __try {
        std::memcpy(dst, src, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

duk_ret_t js_writeMem(duk_context* c) {
    const char* addr_hex = duk_require_string(c, 0);
    if (!duk_is_array(c, 1)) { duk_push_false(c); return 1; }
    uint64_t addr = std::strtoull(addr_hex, nullptr, 0);
    if (!addr) { duk_push_false(c); return 1; }

    duk_size_t n = duk_get_length(c, 1);
    if (n == 0 || n > 1 << 20) { duk_push_false(c); return 1; }  // sanity cap 1 MB

    std::vector<uint8_t> buf(n);
    for (duk_size_t i = 0; i < n; ++i) {
        duk_get_prop_index(c, 1, (duk_uarridx_t)i);
        buf[i] = (uint8_t)duk_get_int_default(c, -1, 0);
        duk_pop(c);
    }

    bool ok = seh_memcpy_write(reinterpret_cast<void*>(addr), buf.data(), n);
    duk_push_boolean(c, ok);
    return 1;
}

} // anon

void register_writemem_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_writeMem, 2);
    duk_put_prop_string(ctx, ns_idx, "_writeMem");
}

} // namespace marrow
