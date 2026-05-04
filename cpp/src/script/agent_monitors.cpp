#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "walker.hpp"
#include "duktape.h"
#include <cstdio>
#include <cstdlib>

namespace marrow {
namespace {

duk_ret_t js_monitorState(duk_context* c) {
    const char* oop_hex = duk_require_string(c, 0);
    uint64_t oop = strtoull(oop_hex, nullptr, 0);
    auto* vm = current_vm(c);
    duk_idx_t o = duk_push_object(c);
    if (!vm || !oop) {
        duk_push_string(c, "invalid"); duk_put_prop_string(c, o, "state");
        return 1;
    }

    uint64_t mark = 0;
    try { mark = vm->reader()->read_u64(oop); }
    catch (...) {
        duk_push_string(c, "unreadable"); duk_put_prop_string(c, o, "state");
        return 1;
    }

    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)mark);
    duk_push_string(c, buf); duk_put_prop_string(c, o, "mark");

    int state_bits = mark & 3;
    const char* state = "?";
    uint64_t owner = 0;

    if (state_bits == 1) {
        state = "unlocked";
    } else if (state_bits == 0) {
        // Stack-locked: BasicLock* in upper bits.
        state = "stack";
        uint64_t basic_lock = mark & ~uint64_t(3);
        // Walk JavaThreads, find which thread's stack contains this address.
        try {
            auto* threads_t = vm->type("Threads");
            auto* jt_t = vm->type("JavaThread");
            if (threads_t && jt_t) {
                uint64_t cur = vm->reader()->read_u64(threads_t->field("_thread_list")->address);
                size_t next_off = jt_t->field("_next")->offset;
                int safety = 0;
                while (cur && safety++ < 256) {
                    auto* sb_f = jt_t->field("_stack_base");
                    auto* sz_f = jt_t->field("_stack_size");
                    if (sb_f && sz_f) {
                        uint64_t base = vm->reader()->read_u64(cur + sb_f->offset);
                        uint64_t size = vm->reader()->read_u64(cur + sz_f->offset);
                        if (basic_lock >= base - size && basic_lock < base) {
                            owner = cur;
                            break;
                        }
                    }
                    cur = vm->reader()->read_u64(cur + next_off);
                }
            }
        } catch (...) {}
    } else if (state_bits == 2) {
        // Inflated: ObjectMonitor* in upper bits.
        state = "inflated";
        uint64_t monitor = mark & ~uint64_t(3);
        try {
            auto* om_t = vm->type("ObjectMonitor");
            if (om_t) {
                auto* owner_f = om_t->field("_owner");
                if (owner_f) {
                    owner = vm->reader()->read_u64(monitor + owner_f->offset);
                }
            }
        } catch (...) {}
    } else {
        state = "gc";
    }

    duk_push_string(c, state); duk_put_prop_string(c, o, "state");
    if (owner) {
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)owner);
        duk_push_string(c, buf);
    } else {
        duk_push_null(c);
    }
    duk_put_prop_string(c, o, "owner");
    return 1;
}

} // anon

void register_monitors_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_monitorState, 1);
    duk_put_prop_string(ctx, ns_idx, "_monitorState");
}

} // namespace marrow
