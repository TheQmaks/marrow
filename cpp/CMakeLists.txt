cmake_minimum_required(VERSION 3.15)
project(marrow CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /permissive- /EHsc /Zc:__cplusplus)
    add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
endif()

# ---------------------------------------------------------------------------
# Source layout (post 2026-04-27 reorg):
#   src/jvm/     — pure HotSpot core lib (vmStructs, walkers, decoders).
#                  Linked into both the CLI and the agent.
#   src/native/  — Win32 / OS primitives: inline hook engine, disasm,
#                  symbols, modules, HW watchpoints, input devices.
#                  Each file may register Duktape JS bindings, but the
#                  underlying mechanism is OS-level, not JVM-domain.
#   src/script/  — JS engine glue (agent_js, agent_bootstrap) and per-
#                  feature bindings that operate on JVM objects (invoke,
#                  freeze, klass dumps, heap walks, bytecode).
#   src/main.cpp — CLI entry point (out-of-process injector + streamer).
# ---------------------------------------------------------------------------

add_library(marrow_core STATIC
    src/jvm/reader.cpp
    src/jvm/vm_meta.cpp
    src/jvm/walker.cpp
    src/jvm/oop_reader.cpp
    src/jvm/field_reader.cpp
    src/jvm/string_reader.cpp
    src/jvm/zgc.cpp
    src/jvm/heap_walker.cpp
    src/jvm/barriers.cpp
    src/jvm/satb.cpp
    src/jvm/signature.cpp
    src/jvm/metaspace.cpp
    src/jvm/cpcache.cpp
    src/jvm/method_walker.cpp
    src/jvm/tlab.cpp
    src/jvm/hooks.cpp
    src/jvm/injector.cpp
    src/jvm/klass_cloner.cpp
    src/jvm/dict_analyzer.cpp
    src/jvm/sysdict_hook.cpp
    src/jvm/inproc_reader.cpp
)
target_include_directories(marrow_core PUBLIC include)
target_link_libraries(marrow_core PUBLIC psapi)

add_executable(marrow src/main.cpp)
target_link_libraries(marrow PRIVATE marrow_core)

# Vendored Duktape — embedded ECMAScript engine for the agent. Single-file
# amalgamation lives under third_party/duktape/.
add_library(duktape STATIC third_party/duktape/duktape.c)
target_include_directories(duktape PUBLIC third_party/duktape)
set_target_properties(duktape PROPERTIES LINKER_LANGUAGE C)
# Suppress noisy MSVC warnings inside Duktape's amalgamation.
if(MSVC)
    target_compile_options(duktape PRIVATE /wd4244 /wd4267 /wd4146 /wd4838 /wd4996)
endif()

# Injectable agent DLL — links the same core, gets an InProcessReader
# instead of a RemoteReader once loaded into the target.
add_library(marrow_agent SHARED
    agent/agent_main.cpp

    # ---- script/ : JS engine + JVM-domain bindings -----------------------
    src/script/agent_js.cpp
    src/script/agent_bootstrap.cpp
    src/script/agent_helpers.cpp
    src/script/agent_freeze.cpp
    src/script/agent_invoke.cpp
    src/script/agent_arrays.cpp
    src/script/agent_bytecode.cpp
    src/script/agent_jit_force.cpp
    src/script/agent_string.cpp
    src/script/agent_heapfilter.cpp
    src/script/agent_alloc.cpp
    src/script/agent_klassinfo.cpp
    src/script/agent_klassfields.cpp
    src/script/agent_explorer.cpp
    src/script/agent_diagnose.cpp
    src/script/agent_codecache.cpp
    src/script/agent_redefine.cpp
    src/script/agent_methsym.cpp
    src/script/agent_mhdump.cpp
    src/script/agent_opstack.cpp
    src/script/agent_monitors.cpp
    src/script/agent_masstracer.cpp
    src/script/agent_hooklist.cpp
    src/script/agent_gcmap.cpp
    src/script/agent_heapscan2.cpp
    src/script/agent_events.cpp
    src/script/agent_nmdump.cpp
    src/script/agent_cpdump.cpp
    src/script/agent_threads.cpp
    src/script/agent_backtrace.cpp
    src/script/agent_stackwalk.cpp
    src/script/agent_javacall.cpp

    # ---- native/ : Win32 / OS primitives ---------------------------------
    # agent_jni.cpp REMOVED — JNI violates the project's "pure memory
    # manipulation, no JVM-blessed APIs" philosophy. Keep agent_invoke.cpp's
    # asm-thunk approach and fix its c2i adapter path properly.
    src/native/agent_disasm.cpp
    src/native/agent_symtab.cpp
    src/native/agent_inlhook.cpp
    src/native/agent_inlhook_cb.cpp
    src/native/agent_modulesenum.cpp
    src/native/agent_callnative.cpp
    src/native/agent_memprotect.cpp
    src/native/agent_memscan.cpp
    src/native/agent_memlog.cpp
    src/native/agent_writemem.cpp
    src/native/agent_window.cpp
    src/native/agent_cursor.cpp
    src/native/agent_mouse.cpp
    src/native/agent_overlay.cpp
    src/native/agent_toast.cpp
    src/native/agent_threadname.cpp
    src/native/agent_sysinfo.cpp
    src/native/agent_watch.cpp
    src/native/agent_hwwatch_ext.cpp
    src/native/agent_pattern.cpp
    src/native/agent_pattern_registry.cpp
    src/native/agent_xref.cpp
    src/native/agent_xref_resolvers.cpp
)
target_link_libraries(marrow_agent PRIVATE marrow_core duktape)
target_compile_features(marrow_agent PRIVATE cxx_std_17)
