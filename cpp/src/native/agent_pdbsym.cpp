// agent_pdbsym.cpp — PDB-backed native symbol resolver via DbgHelp.
//
// The agent's existing Marrow.symbolAt() only does GetProcAddress —
// exports only. HotSpot's internal symbols (JavaCalls::call_static,
// SystemDictionary::*, CompileBroker::*, etc.) are NOT exported but ARE
// in the PDB shipped with debug images.
//
// JS surface:
//   Marrow.pdbSymbolAt(moduleName, mangledOrDecorated) -> hex VA | null
//   Marrow.pdbSymbolsLike(moduleName, prefix, max?)    -> [{name,addr},...]
//
// Implementation: dynamic-link dbghelp.dll on first use, SymInitialize
// (lazy-non-invasive), SymLoadModuleEx for the target module, then
// SymFromName / SymEnumSymbols.

#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace marrow {
namespace {

// DbgHelp dynamic dispatch table. We avoid linking to dbghelp.lib so the
// agent works on systems where DbgHelp is locked or replaced.
struct Dbg {
    HMODULE                          h{nullptr};
    decltype(&SymInitialize)         SymInitialize{nullptr};
    decltype(&SymLoadModuleEx)       SymLoadModuleEx{nullptr};
    decltype(&SymFromName)           SymFromName{nullptr};
    decltype(&SymEnumSymbols)        SymEnumSymbols{nullptr};
    decltype(&SymSetOptions)         SymSetOptions{nullptr};
    decltype(&SymGetOptions)         SymGetOptions{nullptr};
    bool                             initialized{false};
    std::mutex                       mu;
};
static Dbg g_dbg;

bool ensure_dbg() {
    std::lock_guard<std::mutex> lk(g_dbg.mu);
    if (g_dbg.initialized) return g_dbg.h != nullptr;
    g_dbg.initialized = true;

    g_dbg.h = LoadLibraryA("dbghelp.dll");
    if (!g_dbg.h) return false;
    auto sym = [&](const char* n){ return GetProcAddress(g_dbg.h, n); };
    g_dbg.SymInitialize    = (decltype(&SymInitialize))   sym("SymInitialize");
    g_dbg.SymLoadModuleEx  = (decltype(&SymLoadModuleEx)) sym("SymLoadModuleEx");
    g_dbg.SymFromName      = (decltype(&SymFromName))     sym("SymFromName");
    g_dbg.SymEnumSymbols   = (decltype(&SymEnumSymbols))  sym("SymEnumSymbols");
    g_dbg.SymSetOptions    = (decltype(&SymSetOptions))   sym("SymSetOptions");
    g_dbg.SymGetOptions    = (decltype(&SymGetOptions))   sym("SymGetOptions");
    if (!g_dbg.SymInitialize || !g_dbg.SymLoadModuleEx ||
        !g_dbg.SymFromName   || !g_dbg.SymEnumSymbols)
        return false;

    // SYMOPT_UNDNAME: undecorate names so callers can use C++ source-form.
    // SYMOPT_DEFERRED_LOADS: fast init; symbols loaded on first reference.
    // SYMOPT_ALLOW_ABSOLUTE_SYMBOLS: tolerate odd PDBs.
    DWORD opts = g_dbg.SymGetOptions ? g_dbg.SymGetOptions() : 0;
    opts |= SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES;
    if (g_dbg.SymSetOptions) g_dbg.SymSetOptions(opts);

    // Non-invasive init (FALSE = don't enumerate all loaded modules now).
    if (!g_dbg.SymInitialize(GetCurrentProcess(), nullptr, FALSE))
        return false;
    return true;
}

// Find module base + path by name (case-insensitive). Returns false if
// the module isn't loaded in the current process.
bool find_module(const char* name, uint64_t* out_base, size_t* out_size,
                 std::string* out_path) {
    HMODULE mods[1024]; DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
        return false;
    size_t n = needed / sizeof(HMODULE);
    for (size_t i = 0; i < n; ++i) {
        char base_name[MAX_PATH] = {};
        GetModuleBaseNameA(GetCurrentProcess(), mods[i], base_name, sizeof(base_name));
        if (_stricmp(base_name, name) != 0) continue;
        char full_path[MAX_PATH] = {};
        GetModuleFileNameExA(GetCurrentProcess(), mods[i], full_path, sizeof(full_path));
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi)))
            return false;
        *out_base = (uint64_t)mi.lpBaseOfDll;
        *out_size = mi.SizeOfImage;
        *out_path = full_path;
        return true;
    }
    return false;
}

// Ensure PDB for the given module is loaded into the DbgHelp session.
// Cached per-module so repeated calls are cheap.
static std::mutex                g_loaded_mu;
static std::vector<std::string>  g_loaded_modules;

bool ensure_module_loaded(const char* name) {
    {
        std::lock_guard<std::mutex> lk(g_loaded_mu);
        for (auto& m : g_loaded_modules)
            if (_stricmp(m.c_str(), name) == 0) return true;
    }
    if (!ensure_dbg()) return false;

    uint64_t base = 0; size_t sz = 0; std::string path;
    if (!find_module(name, &base, &sz, &path)) return false;

    DWORD64 loaded = g_dbg.SymLoadModuleEx(
        GetCurrentProcess(), nullptr, path.c_str(), nullptr, base,
        (DWORD)sz, nullptr, 0);
    if (!loaded) return false;

    std::lock_guard<std::mutex> lk(g_loaded_mu);
    g_loaded_modules.emplace_back(name);
    return true;
}

// Diagnostic: returns JSON string describing each step of PDB loading.
duk_ret_t js_pdbDiag(duk_context* c) {
    const char* mod = duk_require_string(c, 0);
    char buf[1024];
    int  off = 0;
    auto sn = [&](const char* fmt, auto... a) {
        int n = std::snprintf(buf + off, sizeof(buf) - off, fmt, a...);
        if (n > 0) off += n;
    };

    sn("dbg_loaded=%d ", ensure_dbg() ? 1 : 0);
    if (!g_dbg.h) { sn("no_dbghelp"); duk_push_string(c, buf); return 1; }

    uint64_t base = 0; size_t sz = 0; std::string path;
    bool found = find_module(mod, &base, &sz, &path);
    sn("module_found=%d base=0x%llx size=%zu path=%s ",
       found ? 1 : 0, (unsigned long long)base, sz, path.c_str());
    if (!found) { duk_push_string(c, buf); return 1; }

    DWORD64 loaded = g_dbg.SymLoadModuleEx(
        GetCurrentProcess(), nullptr, path.c_str(), nullptr, base,
        (DWORD)sz, nullptr, 0);
    DWORD err = GetLastError();
    sn("SymLoadModuleEx=0x%llx GetLastError=%lu",
       (unsigned long long)loaded, err);

    duk_push_string(c, buf);
    return 1;
}

duk_ret_t js_pdbSymbolAt(duk_context* c) {
    const char* mod = duk_require_string(c, 0);
    const char* sym = duk_require_string(c, 1);
    if (!ensure_module_loaded(mod)) { duk_push_null(c); return 1; }

    // SYMBOL_INFO is variable-sized: alloc with extra room for the name.
    char buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
    auto* info = reinterpret_cast<SYMBOL_INFO*>(buf);
    std::memset(info, 0, sizeof(SYMBOL_INFO));
    info->SizeOfStruct = sizeof(SYMBOL_INFO);
    info->MaxNameLen   = MAX_SYM_NAME;

    if (!g_dbg.SymFromName(GetCurrentProcess(), sym, info)) {
        duk_push_null(c); return 1;
    }
    char addr[32];
    std::snprintf(addr, sizeof(addr), "0x%llx",
                  static_cast<unsigned long long>(info->Address));
    duk_push_string(c, addr);
    return 1;
}

struct EnumState {
    duk_context* c;
    duk_idx_t    arr;
    duk_uarridx_t idx;
    int          max_n;
};

static BOOL CALLBACK enum_cb(SYMBOL_INFO* info, ULONG, PVOID userctx) {
    auto* st = static_cast<EnumState*>(userctx);
    if (static_cast<int>(st->idx) >= st->max_n) return FALSE;
    duk_idx_t o = duk_push_object(st->c);
    duk_push_string(st->c, info->Name);
    duk_put_prop_string(st->c, o, "name");
    char addr[32];
    std::snprintf(addr, sizeof(addr), "0x%llx",
                  static_cast<unsigned long long>(info->Address));
    duk_push_string(st->c, addr);
    duk_put_prop_string(st->c, o, "addr");
    duk_put_prop_index(st->c, st->arr, st->idx++);
    return TRUE;
}

duk_ret_t js_pdbSymbolsLike(duk_context* c) {
    const char* mod    = duk_require_string(c, 0);
    const char* prefix = duk_require_string(c, 1);
    int         max_n  = duk_get_int_default(c, 2, 64);
    if (max_n <= 0 || max_n > 1024) max_n = 64;

    duk_idx_t arr = duk_push_array(c);
    if (!ensure_module_loaded(mod)) return 1;

    // Resolve module base to scope the enumeration (otherwise DbgHelp scans
    // every loaded module — slow on a JVM with 100+ DLLs).
    uint64_t base = 0; size_t sz = 0; std::string path;
    if (!find_module(mod, &base, &sz, &path)) return 1;

    // SymEnumSymbols treats the Mask arg as a wildcard pattern; "<prefix>*"
    // matches everything starting with the prefix.
    std::string mask = std::string(prefix) + "*";
    EnumState st{ c, arr, 0, max_n };
    g_dbg.SymEnumSymbols(GetCurrentProcess(), base, mask.c_str(), enum_cb, &st);
    return 1;
}

} // anon

void register_pdbsym_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_pdbSymbolAt, 2);
    duk_put_prop_string(ctx, ns_idx, "pdbSymbolAt");
    duk_push_c_function(ctx, js_pdbSymbolsLike, 3);
    duk_put_prop_string(ctx, ns_idx, "pdbSymbolsLike");
    duk_push_c_function(ctx, js_pdbDiag, 1);
    duk_put_prop_string(ctx, ns_idx, "pdbDiag");
}

} // namespace marrow
