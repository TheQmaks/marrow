// marrow_agent.dll — injected into a JVM process.
//
// Phase 1: POC that the existing marrow_core library works in-process
// via InProcessReader instead of RemoteReader. Spawns a worker thread
// that, once a second, rewrites `Target.displayName` to a timestamped
// string, proving every layer of the stack works without RPM/WPM.
//
// Later phases add QuickJS, hook callbacks, OpenGL overlay, etc.

#include "inproc_reader.hpp"
#include "vm_meta.hpp"
#include "walker.hpp"
#include "oop_reader.hpp"
#include "field_reader.hpp"
#include "string_reader.hpp"
#include "zgc.hpp"
#include "tlab.hpp"
#include "method_walker.hpp"
#include "hooks.hpp"
#include "agent_ipc.hpp"
#include "agent_js.hpp"

#include <array>
#include <mutex>
#include <unordered_map>

#include <windows.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <sstream>

namespace {

std::thread g_worker;
std::atomic<bool> g_stop{false};

FILE* g_log = nullptr;
void log_init() {
    // Log file in target's working dir — easy to find after run.
    fopen_s(&g_log, "marrow_agent.log", "w");
}
void log(const char* fmt, ...) {
    if (!g_log) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}
} // namespace

// Exposed externally so agent_js.cpp can call back into our log.
namespace marrow {
void agent_log(const char* fmt, ...) {
    if (!g_log) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}
}

namespace {

uint64_t find_klass(marrow::VMMeta& vm, const char* name) {
    marrow::ClassWalker cw(&vm);
    for (auto& k : cw.list())
        if (k.name == name) return k.address;
    return 0;
}

std::atomic<uint64_t> g_tick_count{0};

void on_target_tick(marrow::HookContext* /*ctx*/) {
    g_tick_count.fetch_add(1, std::memory_order_relaxed);
}
} // namespace

namespace marrow {

// Forward decl — defined in agent_watch.cpp; called from DllMain detach
// to drop active HW watchpoints before unload.
void agent_watch_unwatch_all();

// Generic per-hook counter map keyed by `userdata` cookie. Worker thread
// looks these up on ReadHookCount requests.
std::mutex g_hook_counters_mu;
std::unordered_map<uint64_t, std::atomic<uint64_t>> g_hook_counters;

// Worker-owned helpers, shared with IPC dispatcher / JS host so neither
// thread does heavy ClassWalker init inline.
OopDecoder*  g_dec = nullptr;
ZGCDecoder*  g_zgc = nullptr;
StringReader* g_sr = nullptr;

// Generic counting callback — keyed off ctx->userdata cookie chosen by
// installer. Must be safe from any JavaThread.
void on_counting_hook(HookContext* ctx) {
    auto it = g_hook_counters.find(ctx->userdata);
    if (it != g_hook_counters.end())
        it->second.fetch_add(1, std::memory_order_relaxed);
}

} // namespace marrow

namespace {

uint64_t mirror_of(marrow::VMMeta& vm, uint64_t klass,
                    marrow::ZGCDecoder* zgc) {
    auto* mf = vm.type("Klass")->field("_java_mirror");
    uint64_t raw = vm.reader()->read_u64(klass + mf->offset);
    uint64_t mirror = mf->type_string == "OopHandle"
        ? vm.reader()->read_u64(raw) : raw;
    return (zgc && zgc->is_active()) ? zgc->decode(mirror) : mirror;
}

// ------------------------------- IPC --------------------------------

struct IpcServer {
    HANDLE mapping = nullptr;
    marrow::AgentIpcBlock* block = nullptr;
    marrow::VMMeta* vm = nullptr;

    bool open(DWORD pid) {
        char name[128];
        _snprintf_s(name, sizeof(name), _TRUNCATE,
                    "Local\\marrow-agent-%lu", (unsigned long)pid);
        mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr,
                                      PAGE_READWRITE, 0,
                                      marrow::AGENT_IPC_SIZE, name);
        if (!mapping) return false;
        block = static_cast<marrow::AgentIpcBlock*>(
            MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                           marrow::AGENT_IPC_SIZE));
        if (!block) return false;
        // Initialize (zero + magic). A client attaching will read this.
        ZeroMemory(block, marrow::AGENT_IPC_SIZE);
        block->magic = marrow::AGENT_IPC_MAGIC;
        block->state = static_cast<uint32_t>(marrow::IpcState::Idle);
        return true;
    }

    void reply(uint32_t status, const char* msg = nullptr,
               std::initializer_list<uint64_t> results = {}) {
        block->status = status;
        size_t i = 0;
        for (uint64_t v : results) {
            if (i < 16) block->result[i++] = v;
        }
        if (msg) {
            size_t len = strlen(msg);
            if (len > marrow::AGENT_IPC_MSG_MAX - 1)
                len = marrow::AGENT_IPC_MSG_MAX - 1;
            memcpy(block->msg, msg, len);
            block->msg[len] = 0;
            block->msg_len = uint32_t(len);
        } else {
            block->msg_len = 0;
        }
        block->state = static_cast<uint32_t>(marrow::IpcState::Reply);
    }

    // Dispatch one command. Pre-condition: state == Request.
    void dispatch() {
        using namespace marrow;
        block->state = uint32_t(IpcState::Processing);
        auto cmd = CommandId(block->cmd);
        try {
            switch (cmd) {
                case CommandId::Ping:
                    reply(0, "pong");
                    break;
                case CommandId::FindClass: {
                    const char* name = block->msg;
                    if (!vm) { reply(1, "vm not ready"); break; }
                    ClassWalker cw(vm);
                    uint64_t addr = 0;
                    for (auto& k : cw.list())
                        if (k.name == name) { addr = k.address; break; }
                    if (addr) reply(0, nullptr, {addr});
                    else reply(2, "class not found");
                    break;
                }
                case CommandId::HookMethod: {
                    uint64_t klass = block->args[0];
                    const char* mname = block->msg;
                    uint64_t cookie = block->args[2];
                    auto m = find_method(vm, klass, mname);
                    if (!m) { reply(3, "method not found"); break; }
                    {
                        std::lock_guard<std::mutex> g(marrow::g_hook_counters_mu);
                        marrow::g_hook_counters[cookie].store(0);
                    }
                    install_callback_hook(vm, *m, &marrow::on_counting_hook, cookie);
                    reply(0, nullptr, {m->address});
                    break;
                }
                case CommandId::ReadHookCount: {
                    uint64_t cookie = block->args[0];
                    uint64_t n = 0;
                    auto it = marrow::g_hook_counters.find(cookie);
                    if (it != marrow::g_hook_counters.end())
                        n = it->second.load(std::memory_order_relaxed);
                    reply(0, nullptr, {n});
                    break;
                }
                case CommandId::Eval: {
                    static marrow::JsHost s_js;
                    static bool bound = false;
                    if (!bound) {
                        // Reuse worker's pre-warmed helpers — avoids
                        // a second heavy ClassWalker scan on this thread.
                        s_js.dec_ = marrow::g_dec;
                        s_js.zgc_ = marrow::g_zgc;
                        s_js.sr_  = marrow::g_sr;
                        s_js.bind(vm);
                        bound = true;
                    }
                    std::string out;
                    int rc = s_js.eval(block->msg, out);
                    reply(uint32_t(rc), out.c_str());
                    break;
                }
                case CommandId::Shutdown:
                    reply(0, "bye");
                    g_stop = true;
                    break;
                default:
                    reply(99, "unknown command");
            }
        } catch (const std::exception& e) {
            reply(1000, e.what());
        }
    }

    void serve(marrow::VMMeta* vm_) {
        vm = vm_;
        while (!g_stop.load()) {
            if (block->state == uint32_t(marrow::IpcState::Request))
                dispatch();
            else
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
};

IpcServer g_ipc;

void worker_loop() {
    log("agent: worker started, initializing VMMeta");
    try {
        marrow::InProcessReader reader("jvm.dll");
        marrow::VMMeta vm(&reader);
        log("agent: VMMeta loaded, %zu types", vm.types().size());

        // Open IPC channel named after our PID so external CLI can find us.
        if (g_ipc.open(GetCurrentProcessId())) {
            log("agent: IPC mapping ready (pid=%lu)",
                (unsigned long)GetCurrentProcessId());
            std::thread([&]{ g_ipc.serve(&vm); }).detach();
        } else {
            log("agent: IPC mapping FAILED");
        }

        log("agent: constructing OopDecoder");
        marrow::OopDecoder dec(&vm);
        log("agent: OopDecoder done (oops_compressed=%d, klass_compressed=%d)",
            dec.oops_are_compressed(), dec.compressed_klass());

        log("agent: detecting ZGC");
        marrow::ZGCDecoder zgc = marrow::ZGCDecoder::detect(&vm);
        log("agent: ZGC done (active=%d)", zgc.is_active());

        // Publish for IPC / JS host before they need them.
        marrow::g_dec = &dec;
        marrow::g_zgc = &zgc;

        log("agent: finding Target klass");
        uint64_t target = find_klass(vm, "Target");
        if (!target) {
            log("agent: Target klass not found — agent stays alive for IPC");
            // Park the worker so vm/dec/zgc stay live for the IPC thread,
            // which holds raw pointers to them. Returning here would free
            // the stack frame and the next eval would dereference dangling
            // VMMeta — that's the bug we hit on non-Target JVMs.
            while (!g_stop.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            return;
        }
        log("agent: Target klass @ %llx", (unsigned long long)target);

        log("agent: resolving mirror");
        uint64_t mirror = mirror_of(vm, target, &zgc);
        log("agent: mirror @ %llx", (unsigned long long)mirror);

        log("agent: locating displayName");
        auto disp = marrow::find_field(&vm, target, "displayName");
        log("agent: displayName %s", disp ? "found" : "MISSING");
        log("agent: locating lastMessage");
        auto last = marrow::find_field(&vm, target, "lastMessage");
        log("agent: lastMessage %s", last ? "found" : "MISSING");
        if (!disp || !last) {
            log("agent: field not found — agent stays alive for IPC");
            while (!g_stop.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            return;
        }

        // StringReader: pre-resolved klass constructor exists but the
        // SECOND racy step (find_field reading the live String CP) still
        // crashes when class-loading mutates CP slots concurrently. Off
        // by default; users can construct via JS once the JVM quiesces.
        // log("agent: constructing StringReader");
        // marrow::StringReader sr(&vm, &dec, &zgc, string_klass);
        // marrow::g_sr = &sr;

        // Install callback hook on Target.tick(I)V.
        auto tick = marrow::find_method(&vm, target, "tick");
        if (tick) {
            log("agent: installing callback hook on tick() @ %llx",
                (unsigned long long)tick->address);
            auto hk = marrow::install_callback_hook(&vm, *tick, &on_target_tick, 0);
            log("agent: hook installed, trampoline @ %llx",
                (unsigned long long)hk.trampoline_addr);
        } else {
            log("agent: tick method not found");
        }

        // Proof of life: copy `lastMessage` oop into `displayName` once
        // per second. Exercises read, decode, write, card-mark pathways
        // — all through marrow_core, entirely in-process.
        uint64_t disp_slot = mirror + disp->offset;
        uint64_t last_slot = mirror + last->offset;

        uint64_t prev_ticks = 0;
        while (!g_stop.load()) {
            if (zgc.is_active()) {
                uint64_t raw = reader.read_u64(last_slot);
                reader.write(disp_slot, &raw, 8);
            } else if (dec.oops_are_compressed()) {
                uint32_t n = reader.read_u32(last_slot);
                reader.write(disp_slot, &n, 4);
            } else {
                uint64_t w = reader.read_u64(last_slot);
                reader.write(disp_slot, &w, 8);
            }
            uint64_t cur = g_tick_count.load(std::memory_order_relaxed);
            if (cur != prev_ticks) {
                log("agent: callback fires observed = %llu (delta %llu)",
                    (unsigned long long)cur, (unsigned long long)(cur - prev_ticks));
                prev_ticks = cur;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    } catch (const std::exception& e) {
        log("agent: exception %s", e.what());
    }
    log("agent: worker stopped");
}

} // namespace

extern "C" __declspec(dllexport)
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            log_init();
            log("agent: DLL_PROCESS_ATTACH");
            g_worker = std::thread(worker_loop);
            g_worker.detach();
            break;
        case DLL_PROCESS_DETACH: {
            marrow::agent_watch_unwatch_all();
            log("agent: DLL_PROCESS_DETACH");
            g_stop = true;
            if (g_log) { fclose(g_log); g_log = nullptr; }
            break;
        }
    }
    return TRUE;
}
