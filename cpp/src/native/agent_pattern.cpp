// agent_pattern.cpp — byte-pattern scanner for resolving HotSpot
// internal function addresses without PDB.
//
// Symbols like JavaCalls::call, attach_current_thread, JVM_DefineClass
// aren't exported from jvm.dll. Without a debug-image PDB we can't
// SymFromName them. Pattern scanning matches each function by its
// distinctive prologue bytes — works on any HotSpot build that compiles
// the same instructions, even when offsets / globals differ.
//
// Pattern grammar:
//   "48 8B 05 ?? ?? ?? ?? FF E0"
// Each byte is two hex chars. `??` is a wildcard (any byte). Whitespace
// between bytes is optional.
//
// JS surface:
//   Marrow.findPattern(moduleName, patternHex) -> hex VA | null
//   Marrow.findPatterns(moduleName, patternHex, max?) -> [hex, ...]

#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstring>
#include <vector>

namespace marrow {
namespace {

// Parse "48 ?? FF E0" into (bytes[], mask[]). mask[i]==0 means wildcard.
static bool parse_pattern(const char* s,
                          std::vector<uint8_t>& bytes,
                          std::vector<uint8_t>& mask)
{
    bytes.clear();
    mask.clear();
    while (*s) {
        while (*s == ' ' || *s == '\t') ++s;
        if (!*s) break;
        if (s[0] == '?' && s[1] == '?') {
            bytes.push_back(0);
            mask.push_back(0);
            s += 2;
        } else {
            auto hex = [](char c)->int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hi = hex(s[0]);
            int lo = hex(s[1]);
            if (hi < 0 || lo < 0) return false;
            bytes.push_back(uint8_t((hi << 4) | lo));
            mask.push_back(0xFF);
            s += 2;
        }
    }
    return !bytes.empty();
}

// Find executable + readable code sections of `mod` and copy them into a
// flat buffer. Returns the buffer + a map of (buffer offset → VA).
struct Section { uint64_t base; size_t size; std::vector<uint8_t> data; };

static std::vector<Section> read_code_sections(HMODULE mod) {
    std::vector<Section> out;
    if (!mod) return out;
    auto ImageBase = reinterpret_cast<uint8_t*>(mod);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(ImageBase);
    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(ImageBase + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (sec->Misc.VirtualSize == 0) continue;
        Section s;
        s.base = uint64_t(ImageBase) + sec->VirtualAddress;
        s.size = sec->Misc.VirtualSize;
        // Read into local buffer for fast scanning (cache-friendly).
        s.data.assign(reinterpret_cast<uint8_t*>(s.base),
                      reinterpret_cast<uint8_t*>(s.base) + s.size);
        out.push_back(std::move(s));
    }
    return out;
}

// Scan one section's buffer; return all match offsets.
static void scan_one(const Section& s,
                     const std::vector<uint8_t>& bytes,
                     const std::vector<uint8_t>& mask,
                     size_t max_results,
                     std::vector<uint64_t>& out)
{
    if (bytes.size() > s.data.size()) return;
    const auto* p = s.data.data();
    const size_t end = s.data.size() - bytes.size();
    for (size_t i = 0; i <= end; ++i) {
        bool ok = true;
        for (size_t j = 0; j < bytes.size(); ++j) {
            if (mask[j] && p[i + j] != bytes[j]) { ok = false; break; }
        }
        if (ok) {
            out.push_back(s.base + i);
            if (out.size() >= max_results) return;
        }
    }
}

duk_ret_t js_findPattern(duk_context* c) {
    const char* mod_name = duk_require_string(c, 0);
    const char* pat      = duk_require_string(c, 1);
    HMODULE mod = GetModuleHandleA(mod_name);
    if (!mod) { duk_push_null(c); return 1; }
    std::vector<uint8_t> bytes, mask;
    if (!parse_pattern(pat, bytes, mask)) { duk_push_null(c); return 1; }
    auto sections = read_code_sections(mod);
    std::vector<uint64_t> hits;
    for (auto& s : sections) {
        scan_one(s, bytes, mask, 1, hits);
        if (!hits.empty()) break;
    }
    if (hits.empty()) { duk_push_null(c); return 1; }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)hits[0]);
    duk_push_string(c, buf);
    return 1;
}

duk_ret_t js_findPatterns(duk_context* c) {
    const char* mod_name = duk_require_string(c, 0);
    const char* pat      = duk_require_string(c, 1);
    int max_n            = duk_get_int_default(c, 2, 16);
    if (max_n <= 0 || max_n > 1024) max_n = 16;
    duk_idx_t arr = duk_push_array(c);
    HMODULE mod = GetModuleHandleA(mod_name);
    if (!mod) return 1;
    std::vector<uint8_t> bytes, mask;
    if (!parse_pattern(pat, bytes, mask)) return 1;
    auto sections = read_code_sections(mod);
    std::vector<uint64_t> hits;
    for (auto& s : sections) {
        if (hits.size() >= size_t(max_n)) break;
        scan_one(s, bytes, mask, size_t(max_n) - hits.size(), hits);
    }
    char buf[32];
    for (size_t i = 0; i < hits.size(); ++i) {
        std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)hits[i]);
        duk_push_string(c, buf);
        duk_put_prop_index(c, arr, duk_uarridx_t(i));
    }
    return 1;
}

} // anon

void register_pattern_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_findPattern, 2);
    duk_put_prop_string(ctx, ns_idx, "findPattern");
    duk_push_c_function(ctx, js_findPatterns, 3);
    duk_put_prop_string(ctx, ns_idx, "findPatterns");
}

} // namespace marrow
