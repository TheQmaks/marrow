// agent_pattern_registry.cpp — symbol→pattern registry that backs
// resolve_symbol() when no debug-image PDB is available.
//
// Workflow on a machine WITH PDB:
//   1) JS calls Marrow._extractRawBytes("JVM_DefineClass", 32) →
//      returns hex of the function's first 32 bytes.
//   2) User reviews the hex, replaces immediates/displacements with "??",
//      calls Marrow._registerSymbolPattern("JVM_DefineClass", "<pat>").
//   3) Saved patterns can be embedded into bootstrap.js for replay.
//
// Workflow on a machine WITHOUT PDB:
//   1) bootstrap.js (or user JS) calls _registerSymbolPattern() with the
//      patterns it has on file.
//   2) resolve_symbol(name) calls into pattern_registry_resolve(name) when
//      DbgHelp can't find the symbol; returns first match in jvm.dll.
//
// Patterns use the same grammar as agent_pattern.cpp: hex bytes, "??"
// wildcards, optional whitespace.

#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace marrow {

// External: forward decl of DbgHelp init from agent_javacall.cpp. Reused so
// we don't initialise SymInitialize twice.
extern void init_dbghelp();
extern uint64_t resolve_symbol(const char* name);   // PDB-only; we add
                                                    // the registry fallback
                                                    // below as a separate fn.

namespace {

static std::mutex                          g_reg_mu;
static std::map<std::string, std::string>  g_reg;   // name → pattern hex

// --- Pattern parser (grammar matches agent_pattern.cpp) ---------------
static bool parse_pattern(const char* s,
                          std::vector<uint8_t>& bytes,
                          std::vector<uint8_t>& mask)
{
    bytes.clear(); mask.clear();
    while (*s) {
        while (*s == ' ' || *s == '\t') ++s;
        if (!*s) break;
        if (s[0] == '?' && s[1] == '?') {
            bytes.push_back(0); mask.push_back(0); s += 2;
        } else {
            auto hx = [](char c)->int {
                if (c>='0'&&c<='9') return c-'0';
                if (c>='a'&&c<='f') return c-'a'+10;
                if (c>='A'&&c<='F') return c-'A'+10;
                return -1;
            };
            int hi = hx(s[0]), lo = (s[0] ? hx(s[1]) : -1);
            if (hi < 0 || lo < 0) return false;
            bytes.push_back(uint8_t((hi<<4)|lo));
            mask.push_back(0xFF);
            s += 2;
        }
    }
    return !bytes.empty();
}

// --- Section enumeration (pull jvm.dll executable sections) -----------
struct SecSnap { uint64_t base; std::vector<uint8_t> data; };

static std::vector<SecSnap> snap_jvm_code() {
    std::vector<SecSnap> out;
    HMODULE jvm = GetModuleHandleA("jvm.dll");
    if (!jvm) return out;
    auto base = reinterpret_cast<uint8_t*>(jvm);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (sec->Misc.VirtualSize == 0) continue;
        SecSnap s;
        s.base = uint64_t(base) + sec->VirtualAddress;
        s.data.assign(reinterpret_cast<uint8_t*>(s.base),
                      reinterpret_cast<uint8_t*>(s.base) + sec->Misc.VirtualSize);
        out.push_back(std::move(s));
    }
    return out;
}

// Scan a snapshot for ALL matches at 16-byte aligned addresses.
// Used by the JC::call resolver when the simple JC body pattern isn't unique.
std::vector<uint64_t> pattern_registry_scan_all_aligned(const char* pat) {
    std::vector<uint64_t> out;
    std::vector<uint8_t> bytes, mask;
    if (!parse_pattern(pat, bytes, mask)) return out;
    auto sections = snap_jvm_code();
    for (const auto& s : sections) {
        if (bytes.size() > s.data.size()) continue;
        const auto* p = s.data.data();
        const size_t end = s.data.size() - bytes.size();
        size_t start = (s.base & 0xF) ? (16 - (s.base & 0xF)) : 0;
        for (size_t i = start; i <= end; i += 16) {
            bool ok = true;
            for (size_t j = 0; j < bytes.size(); ++j) {
                if (mask[j] && p[i + j] != bytes[j]) { ok = false; break; }
            }
            if (ok) out.push_back(s.base + i);
        }
    }
    return out;
}

// --- Scan a snapshot for the best match -------------------------------
// Two-pass strategy:
//   1) Prefer matches at 16-byte aligned addresses (function entries are
//      almost always 16-byte aligned by the linker).
//   2) Fall back to the first match at any offset if no aligned match
//      exists (covers patterns that target data or mid-function bytes).
// This avoids returning a mid-function byte collision when a function-
// aligned match exists deeper in the section.
static uint64_t scan_first(const std::vector<SecSnap>& sections,
                           const std::vector<uint8_t>& bytes,
                           const std::vector<uint8_t>& mask)
{
    auto match_at = [&](const uint8_t* p, size_t i) -> bool {
        for (size_t j = 0; j < bytes.size(); ++j) {
            if (mask[j] && p[i + j] != bytes[j]) return false;
        }
        return true;
    };
    // Pass 1: 16-byte aligned matches.
    for (const auto& s : sections) {
        if (bytes.size() > s.data.size()) continue;
        const auto* p = s.data.data();
        const size_t end = s.data.size() - bytes.size();
        size_t step = 16;
        size_t start = (s.base & 0xF) ? (16 - (s.base & 0xF)) : 0;
        for (size_t i = start; i <= end; i += step) {
            if (match_at(p, i)) return s.base + i;
        }
    }
    // Pass 2: any offset.
    for (const auto& s : sections) {
        if (bytes.size() > s.data.size()) continue;
        const auto* p = s.data.data();
        const size_t end = s.data.size() - bytes.size();
        for (size_t i = 0; i <= end; ++i) {
            if (match_at(p, i)) return s.base + i;
        }
    }
    return 0;
}

} // anon

// Public: resolve via registry. Called from agent_javacall.cpp::resolve_symbol
// AFTER PDB resolution fails. Returns 0 if no pattern registered or no match.
uint64_t pattern_registry_resolve(const char* name) {
    if (!name) return 0;
    std::string pat;
    {
        std::lock_guard<std::mutex> lk(g_reg_mu);
        auto it = g_reg.find(name);
        if (it == g_reg.end()) return 0;
        pat = it->second;
    }
    std::vector<uint8_t> bytes, mask;
    if (!parse_pattern(pat.c_str(), bytes, mask)) return 0;
    auto sections = snap_jvm_code();
    return scan_first(sections, bytes, mask);
}

namespace {

// JS: Marrow._scanAllAligned(pattern) -> [hex, hex, ...]
// Returns ALL 16-byte aligned VAs in jvm.dll executable section that
// match the pattern. Useful for enumerating function-aligned candidates
// when the prefix isn't unique.
static duk_ret_t js_scan_all_aligned(duk_context* c) {
    const char* pat = duk_require_string(c, 0);
    auto matches = pattern_registry_scan_all_aligned(pat);
    duk_idx_t arr = duk_push_array(c);
    for (size_t i = 0; i < matches.size(); ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)matches[i]);
        duk_push_string(c, buf);
        duk_put_prop_index(c, arr, (duk_uarridx_t)i);
    }
    return 1;
}

// JS: Marrow._registerSymbolPattern(name, pattern) → true/false
static duk_ret_t js_register_pattern(duk_context* c) {
    const char* name = duk_require_string(c, 0);
    const char* pat  = duk_require_string(c, 1);
    std::vector<uint8_t> b, m;
    if (!parse_pattern(pat, b, m)) { duk_push_false(c); return 1; }
    std::lock_guard<std::mutex> lk(g_reg_mu);
    g_reg[name] = pat;
    duk_push_true(c);
    return 1;
}

// JS: Marrow._listSymbolPatterns() → ["name1","name2",...]
static duk_ret_t js_list_patterns(duk_context* c) {
    duk_idx_t arr = duk_push_array(c);
    std::lock_guard<std::mutex> lk(g_reg_mu);
    duk_uarridx_t i = 0;
    for (const auto& kv : g_reg) {
        duk_push_string(c, kv.first.c_str());
        duk_put_prop_index(c, arr, i++);
    }
    return 1;
}

// JS: Marrow._resolveSymbol(name) → hex VA | null. Tries PDB then registry.
static duk_ret_t js_resolve_symbol(duk_context* c) {
    const char* name = duk_require_string(c, 0);
    init_dbghelp();
    uint64_t va = resolve_symbol(name);
    if (!va) va = pattern_registry_resolve(name);
    if (!va) { duk_push_null(c); return 1; }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)va);
    duk_push_string(c, buf);
    return 1;
}

// JS: Marrow._extractRawBytes(name, len) → hex string | null.
// Resolves `name` via PDB and reads the first `len` bytes (1..256). Used
// from a debug-image machine to author patterns that other machines load.
static duk_ret_t js_extract_raw_bytes(duk_context* c) {
    const char* name = duk_require_string(c, 0);
    int len = duk_get_int_default(c, 1, 32);
    if (len < 1 || len > 256) len = 32;
    init_dbghelp();
    uint64_t va = resolve_symbol(name);
    if (!va) { duk_push_null(c); return 1; }
    std::string out;
    out.reserve((size_t)len * 3);
    auto* p = reinterpret_cast<const uint8_t*>(va);
    char hb[4];
    for (int i = 0; i < len; ++i) {
        std::snprintf(hb, sizeof(hb), "%02x", p[i]);
        if (i) out.push_back(' ');
        out.append(hb);
    }
    duk_push_string(c, out.c_str());
    return 1;
}

} // anon

void register_pattern_registry_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_register_pattern, 2);
    duk_put_prop_string(ctx, ns_idx, "_registerSymbolPattern");
    duk_push_c_function(ctx, js_list_patterns, 0);
    duk_put_prop_string(ctx, ns_idx, "_listSymbolPatterns");
    duk_push_c_function(ctx, js_resolve_symbol, 1);
    duk_put_prop_string(ctx, ns_idx, "_resolveSymbol");
    duk_push_c_function(ctx, js_extract_raw_bytes, 2);
    duk_put_prop_string(ctx, ns_idx, "_extractRawBytes");
    duk_push_c_function(ctx, js_scan_all_aligned, 1);
    duk_put_prop_string(ctx, ns_idx, "_scanAllAligned");
}

} // namespace marrow
