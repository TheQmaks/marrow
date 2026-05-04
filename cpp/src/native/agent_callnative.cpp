// agent_callnative.cpp — Win x64 native-function caller for the Marrow agent.
//
// Limitations:
//   - Float/double args (XMM0-3) are NOT supported; integer path only.
//   - C++ exceptions thrown by the callee are NOT caught (only Win SEH / AV).
//   - Assumes Win x64 ABI (__fastcall). Non-standard calling conventions won't work.
#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace marrow {

namespace {

uint64_t arg_to_u64(duk_context* c, duk_idx_t arr, int slot) {
    duk_get_prop_index(c, arr, (duk_uarridx_t)slot);
    uint64_t v = 0;
    if (duk_is_number(c, -1)) {
        v = (uint64_t)(int64_t)duk_get_number(c, -1);
    } else if (duk_is_string(c, -1)) {
        const char* s = duk_get_string(c, -1);
        v = strtoull(s, nullptr, 0);
    }
    duk_pop(c);
    return v;
}

duk_ret_t js_callNative(duk_context* c) {
    const char* va_hex = duk_require_string(c, 0);
    uint64_t va = strtoull(va_hex, nullptr, 0);
    if (!va) { duk_push_null(c); return 1; }

    uint64_t a[6] = {0, 0, 0, 0, 0, 0};
    if (duk_is_array(c, 1)) {
        duk_size_t n = duk_get_length(c, 1);
        for (duk_size_t i = 0; i < n && i < 6; ++i) {
            a[i] = arg_to_u64(c, 1, (int)i);
        }
    }

    typedef uint64_t (*NativeFn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    NativeFn fn = reinterpret_cast<NativeFn>(va);
    uint64_t result = 0;
    __try {
        result = fn(a[0], a[1], a[2], a[3], a[4], a[5]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        duk_push_null(c);
        return 1;
    }

    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)result);
    duk_push_string(c, buf);
    return 1;
}

} // anonymous namespace

void register_callnative_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_callNative, 2);
    duk_put_prop_string(ctx, ns_idx, "_callNative");
}

} // namespace marrow
