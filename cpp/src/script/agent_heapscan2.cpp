#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "agent_js.hpp"
#include "vm_meta.hpp"
#include "walker.hpp"
#include "oop_reader.hpp"
#include "duktape.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace marrow {
namespace {

bool icontains(const std::string& s, const char* sub) {
    if (!sub || !*sub) return true;
    return s.find(sub) != std::string::npos;
}

duk_ret_t js_heapScanByName(duk_context* c) {
    const char* needle = duk_require_string(c, 0);
    int max_oops = duk_get_int_default(c, 1, 100);
    if (max_oops > 5000) max_oops = 5000;
    auto* vm = current_vm(c);
    auto* host = current_host(c);
    duk_idx_t arr = duk_push_array(c);
    if (!vm || !host) return 1;

    auto* dec = static_cast<OopDecoder*>(host->dec_);

    // Build narrow->klass map (mirror js_snapshotHeap)
    ClassWalker cw(vm);
    auto klasses = cw.list();
    std::unordered_map<uint32_t, std::pair<uint64_t, std::string>> narrow_map;
    const auto& kp = dec->klass_params;
    for (auto& k : klasses) {
        if (!icontains(k.name, needle)) continue;
        uint32_t narrow;
        if (!kp.enabled()) narrow = (uint32_t)k.address;
        else narrow = (uint32_t)((k.address - kp.base) >> kp.shift);
        narrow_map[narrow] = {k.address, k.name};
    }
    if (narrow_map.empty()) return 1;

    // Single sweep of writable regions, find matching oops
    Reader* r = vm->reader();
    constexpr size_t CHUNK = 4 * 1024 * 1024;
    duk_uarridx_t out_i = 0;
    for (auto& region : r->enumerate_regions(true)) {
        if ((int)out_i >= max_oops) break;
        if (region.size < 64 * 1024) continue;
        for (uint64_t off = 0; off < region.size && (int)out_i < max_oops; off += CHUNK) {
            size_t part = (size_t)std::min<uint64_t>(CHUNK, region.size - off);
            std::vector<uint8_t> buf;
            try { buf = r->read(region.base + off, part); }
            catch (...) { continue; }
            for (size_t pos = 0; pos + 12 <= buf.size() && (int)out_i < max_oops; pos += 8) {
                uint32_t narrow;
                std::memcpy(&narrow, buf.data() + pos + 8, 4);
                auto it = narrow_map.find(narrow);
                if (it == narrow_map.end()) continue;
                uint64_t oop = region.base + off + pos;

                duk_idx_t o = duk_push_object(c);
                char hex[32];
                std::snprintf(hex, sizeof(hex), "0x%llx", (unsigned long long)oop);
                duk_push_string(c, hex); duk_put_prop_string(c, o, "oop");
                std::snprintf(hex, sizeof(hex), "0x%llx", (unsigned long long)it->second.first);
                duk_push_string(c, hex); duk_put_prop_string(c, o, "klass");
                duk_push_string(c, it->second.second.c_str());
                duk_put_prop_string(c, o, "klassName");
                duk_put_prop_index(c, arr, out_i++);
            }
        }
    }
    return 1;
}

} // anon

void register_heapscan2_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_heapScanByName, 2);
    duk_put_prop_string(ctx, ns_idx, "_heapScanByName");
}

} // namespace marrow
