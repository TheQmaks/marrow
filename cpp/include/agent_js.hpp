#pragma once
// Embedded JS scripting host for the agent.
//
// Wraps a single Duktape context with bindings for the marrow_core
// API. The context can be accessed from multiple threads (IPC dispatcher
// AND JVM threads firing sync hooks) — all callers must hold `mu_` while
// touching duk_*. mu_ is recursive so a JS handler that re-enters via
// callOriginal/Java.use doesn't deadlock against itself.
//
// The exposed JS API (rough):
//
//   Marrow.findClass(name)            -> klass*
//   Marrow.findMethod(klass, name)    -> method*
//   Marrow.readField(mirror, name)    -> u64 raw value
//   Marrow.writeField(mirror, name, val)
//   Marrow.hookCount(klass, name, cookie)  -> count incrementing
//                                                while hook is live
//   Marrow.log(msg)                    -> writes to agent log
//   print(...)                           -> alias for log

#include "vm_meta.hpp"
#include <cstdint>
#include <mutex>
#include <string>

namespace marrow {

class JsHost {
public:
    JsHost();
    ~JsHost();

    void bind(VMMeta* vm);

    // Eval `script`, capture last expression. Returns 0 on success, sets
    // `out` to the result-as-string (or error text on failure). Acquires
    // mu_ internally — callers that already hold it must use raw_ctx().
    int eval(const char* script, std::string& out);

    // Public access for sync hook handlers — they run on JVM threads and
    // need to call into the JS context. Lock mu_ before any duk_* call.
    void* raw_ctx() { return ctx_; }
    std::recursive_mutex& mu() { return mu_; }

    // Cached helpers (lazily constructed on first bind).
    void* dec_ = nullptr;     // OopDecoder*
    void* zgc_ = nullptr;     // ZGCDecoder*
    void* sr_ = nullptr;      // StringReader*
    VMMeta* vm_ = nullptr;

private:
    void* ctx_ = nullptr;   // duk_context* (opaque to keep header light)
    std::recursive_mutex mu_;
};

// Global JsHost pointer — set by agent_main.cpp at bind time. Sync hook
// dispatch reads it to find the JS context.
extern JsHost* g_js_host;

} // namespace marrow
