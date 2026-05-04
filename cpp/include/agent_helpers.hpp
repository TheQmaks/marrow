#pragma once
#include "vm_meta.hpp"
#include "agent_js.hpp"
#include "duktape.h"
#include <cstdint>

namespace marrow {

// Pull VMMeta* from the Duktape global stash (set by JsHost::bind).
VMMeta* current_vm(duk_context* c);

// Pull JsHost* (with cached dec/zgc/sr) from the stash.
JsHost* current_host(duk_context* c);

// Read .addr property from a JS object {addr:"0x..."} at stack idx -> uint64.
uint64_t obj_addr(duk_context* c, duk_idx_t idx);

// Plausibility check: pointer looks like a metaspace/heap address.
inline bool plausible_metaspace(uint64_t p) {
    return p >= 0x1000ULL && (p & 7u) == 0 && p < 0x800000000000ULL;
}

} // namespace marrow
