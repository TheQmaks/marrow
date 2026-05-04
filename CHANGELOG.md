# Changelog

All notable changes are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] — 2026-05-04

Frida-parity polish for `Java.use` / `Java.cast` / `.overload`. Real-world
Android instrumentation scripts (SSL repinning, certificate pinning bypass,
WebView hooks, etc.) now copy-paste with minimal adaptation — generally
just substituting `Marrow.*` for `JvmProbe.*` references if any.

### Added

- `.overload(typeStr1, typeStr2, ...)` variadic Frida-style. Accepts a list
  of Java type names (`"int"`, `"java.lang.String"`,
  `"[Ljavax.net.ssl.KeyManager;"`) and resolves to the matching overload by
  argument list. The existing `.overload("(II)V")` JVM-internal-sig form
  still works.
- L-typed return auto-cast. `var s = Integer.toString(42)` now returns a
  `Java.cast` proxy with direct field access (`s.value`,
  `Java.toString(s.$oop)`), instead of a raw oop hex string. Threaded
  through `Java.invoke`, `Java.invokeStatic`, `_makeSingle`, and
  `_bindMethod` via the new `_returnClassFromSig` helper.
- `Java.cast(oop, ClassRef)` accepts a `Java.use(...)` handle as the
  second argument (not only a class name string). Frida scripts often
  write `Java.cast(oop, X509Certificate)` — that now works.

### Fixed

- Documentation: `docs/GETTING_STARTED.md` scenario 5 was using the
  low-level `Marrow.readField` primitive on an L-typed handler arg. That
  code would fail at runtime — auto-cast on `.implementation` already
  yields a proxy, so `arg.length` is the correct usage. Doc now matches
  what the engine actually does.

### Verified

- `tests/verify_frida_parity.py` — covers all three new behaviours.
- `tests/verify_autocast.py` — regression guard for sync handler L-arg
  cast.
- `agent_smoke 24/24 PASS · smoke_extended 22/22 PASS` on JDK 8/11/17/21/25.

## [0.1.0] — 2026-05-04

First public release.

### Added — Out-of-process (Python)

- Cross-JDK vmStructs reader (`vm_meta.py`) — works on JDK 8/11/17/21/25
  with no per-version branches.
- Class dictionary walker (`walker.py`), including a JDK 8-specific path
  that walks the legacy `_dictionary` buckets, primitive array klasses,
  and `_array_klasses` chains.
- Field reader (`field_reader.py`) and method walker (`method_walker.py`).
- Oop decoder (`oop_reader.py`) with compressed/wide oop independence.
- String reader (`string_reader.py`) for both compact (Latin-1) and UTF-16
  storage.
- ZGC colour-pointer decoder (`zgc.py`) covering single-gen and generational.
- Constant pool inspector (`cpcache.py`, `cp_scanner.py`).
- Heap walker, TLAB walker, metaspace walker.
- Remote injection (`injector.py`) and IPC (`remote.py`).

### Added — In-process agent (C++ + JS)

- `marrow.exe` CLI: `inject`, `agent eval`, `read-string`, `write-ref`,
  `methods`, `classes`, `threads`, `instances`, `alloc-ba`, `clone-class`,
  `hook`, and ~20 more commands.
- `marrow_agent.dll` with embedded Duktape JS engine.
- Frida-compatible `Java.*` API: `use`, `choose`, `cast`, `reload`,
  `traceClass`, `watchField`, `onNative`, `onKey`, `drain`, `tickNative`.
- `Java.use(...).method.implementation = fn` (sync replacement, return value
  populates `replace_rax` in the trampoline).
- `Java.use(...).method.attach(fn)` (async observation, MHz-scale overhead).
- `callOriginal` from inside `.implementation`, including auto-routing:
  `Cls.method(args)` from inside the handler is detected via per-cookie
  reentry counter and dispatched to the original.
- 108-byte register-capturing trampoline with proper 16-byte alignment;
  full GPR + xmm + stack snapshot.
- JIT'd-caller detour — `install_callback_hook_full` also patches
  `nmethod::_verified_entry_point` so already-resolved JIT call sites
  hit the hook.
- Inline hook engine (x64 LDE + 14-byte JMP detour) for arbitrary native
  addresses; verified on `jvm.dll!JVM_GC`.
- PDB-less JavaCalls bootstrap — calls JavaVM vtable
  `AttachCurrentThread` to register the agent thread; per-thread
  `JavaThread*` derivation from `JNIEnv*`.
- PDB-less `JavaCalls::call` identification via 5-JNI-vtable triangulation
  + structural filter + firing disambiguator. `_invokeJC` works on JRE
  without PDB.
- JNI surface route (`_invokeJNI`) — calls Java methods through JNIEnv
  vtable so smoke tests work even when `JavaCalls::call` cannot be
  resolved.
- `setTimeout` / `console` shims so SSL-pinning-style scripts run with
  minimal adaptation from Frida.

### Verified

- `agent_smoke 24/24 PASS` and `smoke_extended 22/22 PASS` on every
  supported JDK.
- Matrix smoke covers G1, Parallel, Serial, Shenandoah, and ZGC across
  compressed and wide oops on JDK 11/17/21/25 (8 has the GCs available
  to it).

### Known limitations

- Windows x64 only.
- ZGC on JDK 21 requires `-XX:+ZGenerational`.
- `Class.forName` reachability for injected (cloned) classes blocked
  on JDK 21+ pending per-version `SystemDictionary` offset RE.

[Unreleased]: ../../compare/v0.1.0...HEAD
[0.1.0]: ../../releases/tag/v0.1.0
