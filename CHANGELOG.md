# Changelog

All notable changes are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.3] — 2026-05-04

Drops the last two known Frida-parity holes from the v0.1.1 release notes:
**array auto-proxy** and **JS-string -> Java-String implicit allocation in
arg position**. Plus a real bug: multi-overload methods on a `Java.use`
class were objects (not callable functions), so `s.split(...)` /
`s.getBytes()` only worked through explicit `.overload(...)` chains —
fixed via auto arg-shape dispatch.

### Added

- `Java.cast` and method invocations now auto-decode array returns into
  enhanced JS arrays. `s.getBytes()` returns a `[N1, N2, ...]` whose
  `length` works, `[i]` works, plus `$oop`/`$elementSig`/`$truncated` are
  set so the same array can be passed back to another Java method
  unchanged. Object arrays decode each element via `Java.cast`. Eager
  decode capped at 4096 elements to keep huge byte[] payloads from
  blowing duktape memory; beyond that the array is truncated and
  `$truncated=true`.
- JS-string arguments to Java method calls now auto-allocate a Java
  String. Previously you had to wrap with `Java._jstring("hello")`
  manually; now `keyStore.setCertificateEntry("ca", ca)` works as in a
  vanilla Frida script. `_coerceArg` first tries `_jstring`; if the
  JavaCalls path isn't reachable, the original JS string is left
  unchanged so the C++ side can surface a useful error.
- Multi-overload methods (5+ overloads on `String`, `StringBuilder`, etc.)
  are now directly callable. Calling `Cls.method(args)` resolves through
  `_pickOverload` based on JS arg shapes and routes to the matching
  signature. Explicit `.overload("(I)V")` still works.
  `.implementation =` on a multi-overload handle throws with a clear
  error message ("pick one explicitly: Cls.method.overload(\"sig\")")
  because replacing all overloads at once is ambiguous.

### Fixed

- `_unwrap` now correctly decodes array returns when the JNI/JC C++
  surface emits T_OBJECT (type=12) for them, not just T_ARRAY (type=13)
  which is no longer produced by the underlying invoke paths. Cases 12
  and 13 share dispatch keyed off the return-type signature's leading
  `[`.

### Verified

- `tests/verify_array_and_strarg.py` — covers the new behaviours.
- `tests/verify_frida_parity.py` — v0.1.1 gaps still PASS.
- `tests/verify_autocast.py` — handler-side L-arg cast still PASS.
- `agent_smoke 24/24 PASS · smoke_extended 22/22 PASS` on JDK 8/11/17/21/25.

## [0.1.2] — 2026-05-04

Performance fix for the v0.1.1 L-return auto-cast: `Java.cast` now caches
its proxy *prototype* per class instead of rebuilding the field-accessor
table on every cast. Real-world Frida hot hooks no longer pay a 51x
slowdown for proxy construction.

### Changed

- `Java.cast` rewritten around a shared `_castProtoCache[className]`.
  Per-class field accessors and bound methods now live on a prototype
  object built once at first use; each subsequent `Java.cast(oop,
  className)` is `Object.create(proto) + 3 own-prop assigns` instead of
  N `defineProperty` calls.
- New `_bindMethodOnThis(handle)` — variant of `_bindMethod` that reads
  the receiver from `this.$oop` at call time (lets a single bound
  function live on the shared prototype).

### Performance (measured on JDK 17, x64 Release agent)

| Path                      | Before (v0.1.1) | After (v0.1.2) | Change |
|---------------------------|-----------------|----------------|--------|
| Per-cast overhead         | ~419 μs         | ~35 μs         | **12x** |
| L-return auto-cast tput   | 2 341 calls/s   | 23 041 calls/s | **10x** |
| Primitive baseline (ref)  | 119 048 calls/s | 113 636 calls/s | unchanged |

### Behavioural note

Mutating `instance.$oop = otherOop` on an existing cast proxy now
redirects subsequent field reads/writes to the new oop (accessors read
`this.$oop` instead of a captured value). Previously each instance was
locked to its construction-time oop. Realistic Frida usage doesn't
mutate `$oop` after cast, so this is a non-breaking semantics change in
practice.

### Verified

- `tests/bench_autocast.py` — microbenchmark used to drive the change.
- `tests/verify_frida_parity.py` — all 3 gaps still PASS.
- `agent_smoke 24/24 PASS · smoke_extended 22/22 PASS` on JDK 8/11/17/21/25.

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
