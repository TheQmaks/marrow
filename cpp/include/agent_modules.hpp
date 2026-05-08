#pragma once
// Forward declarations for per-module Duktape binding registrars.
// Each module lives in its own .cpp under src/agent_*.cpp and exposes a
// single `register_<name>_bindings(duk_context*, VMMeta*)` function that
// adds its bindings to the Marrow namespace and the Java bootstrap.
//
// The main agent_js.cpp's install_bindings() calls each registrar.

#include "vm_meta.hpp"

namespace marrow {

// Each registrar takes the void* (duk_context*) so we don't drag the
// duktape.h header into every consumer; the .cpp casts back as needed.
// VMMeta is fetched from the global stash inside each binding via the
// current_vm(ctx) helper, identical to other bindings in agent_js.cpp.
//
// Called from install_bindings() AFTER the Marrow namespace object is
// already on the value stack at index `ns`. Each registrar is expected
// to push c_functions with `duk_push_c_function` and `duk_put_prop_string(
// ctx, ns, "name")` to attach them under Marrow.
void register_invoke_bindings(void* duk_ctx, int ns_idx);
void register_freeze_bindings(void* duk_ctx, int ns_idx);
void register_arrays_bindings(void* duk_ctx, int ns_idx);
void register_mouse_bindings(void* duk_ctx, int ns_idx);
void register_bytecode_bindings(void* duk_ctx, int ns_idx);
void register_jit_force_bindings(void* duk_ctx, int ns_idx);
void register_toast_bindings(void* duk_ctx, int ns_idx);
void register_string_bindings(void* duk_ctx, int ns_idx);
// register_jni_bindings REMOVED — see CMakeLists.txt comment.
void register_overlay_bindings(void* duk_ctx, int ns_idx);
void register_window_bindings(void* duk_ctx, int ns_idx);
void register_cursor_bindings(void* duk_ctx, int ns_idx);
void register_heapfilter_bindings(void* duk_ctx, int ns_idx);
void register_disasm_bindings(void* duk_ctx, int ns_idx);
void register_symtab_bindings(void* duk_ctx, int ns_idx);
void register_events_bindings(void* duk_ctx, int ns_idx);
void register_inlhook_bindings(void* duk_ctx, int ns_idx);
void register_nmdump_bindings(void* duk_ctx, int ns_idx);
void register_stackwalk_bindings(void* duk_ctx, int ns_idx);
void register_cpdump_bindings(void* duk_ctx, int ns_idx);
void register_memlog_bindings(void* duk_ctx, int ns_idx);
void register_klassinfo_bindings(void* duk_ctx, int ns_idx);
void register_alloc_bindings(void* duk_ctx, int ns_idx);
void register_modulesenum_bindings(void* duk_ctx, int ns_idx);
void register_callnative_bindings(void* duk_ctx, int ns_idx);
void register_diagnose_bindings(void* duk_ctx, int ns_idx);
void register_codecache_bindings(void* duk_ctx, int ns_idx);
void register_klassfields_bindings(void* duk_ctx, int ns_idx);
void register_threads_bindings(void* duk_ctx, int ns_idx);
void register_mhdump_bindings(void* duk_ctx, int ns_idx);
void register_hwwatch_ext_bindings(void* duk_ctx, int ns_idx);
void register_opstack_bindings(void* duk_ctx, int ns_idx);
void register_monitors_bindings(void* duk_ctx, int ns_idx);
void register_inlhook_cb_bindings(void* duk_ctx, int ns_idx);
void register_explorer_bindings(void* duk_ctx, int ns_idx);
void register_masstracer_bindings(void* duk_ctx, int ns_idx);
void register_backtrace_bindings(void* duk_ctx, int ns_idx);
void register_hooklist_bindings(void* duk_ctx, int ns_idx);
void register_threadname_bindings(void* duk_ctx, int ns_idx);
void register_sysinfo_bindings(void* duk_ctx, int ns_idx);
void register_gcmap_bindings(void* duk_ctx, int ns_idx);
void register_heapscan2_bindings(void* duk_ctx, int ns_idx);
void register_memscan_bindings(void* duk_ctx, int ns_idx);
void register_redefine_bindings(void* duk_ctx, int ns_idx);
void register_writemem_bindings(void* duk_ctx, int ns_idx);
void register_methsym_bindings(void* duk_ctx, int ns_idx);
void register_memprotect_bindings(void* duk_ctx, int ns_idx);
void register_javacall_bindings(void* duk_ctx, int ns_idx);
void register_pattern_bindings(void* duk_ctx, int ns_idx);
void register_pattern_registry_bindings(void* duk_ctx, int ns_idx);
// PDB-less fallback used by agent_javacall.cpp::resolve_symbol.
uint64_t pattern_registry_resolve(const char* name);

void register_xref_bindings(void* duk_ctx, int ns_idx);
// x64 walker — extracts CALL targets + RIP-relative loads from a function body.
struct XrefScan;
XrefScan xref_scan(uint64_t va, size_t max_insns);
// Per-symbol dynamic resolvers: walks an exported function to find the
// callee/global address. Returns 0 on failure.
uint64_t dynamic_xref_resolve(const char* name);

} // namespace marrow
