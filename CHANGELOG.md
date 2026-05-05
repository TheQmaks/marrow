# Changelog

All notable changes are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.1] — 2026-05-05

JIT survival now fully covers pure-replacement hooks. The worker
thread no longer routes new nmethods through the inline-hook engine;
it writes a 14-byte abs-jmp directly at the new
`_verified_entry_point`, jumping into our existing FULL_TRAMP-style
trampoline (which already honors `skip_orig` / `replace_rax`).

### Effect (JDK 17, 5000-iteration tight loop)

|                                  | v0.1.9 | v0.2.0 | **v0.2.1** |
|----------------------------------|--------|--------|------------|
| Pure replacement hits            |    271 |  3070  | **5000** ✅ |
| Pure replacement return applied  |    271 |   271  | **5000** ✅ |
| Observer hook fires (.attach)    |    271 |  3070  |   ~3000   |
| callOriginal hits                |    271 |  3070  |    ~375   |
| callOriginal sum correctness     | clean  | clean  | partial   |

Pure replacement (`return value;` from inside `.implementation`) now
works **fully** under sustained JIT-tier-up — the v0.1.9 known-limit
that started this whole worker-thread effort is closed for the
canonical case.

### Trade-off (callOriginal under JIT regressed slightly)

Calling `callOriginal` from inside an `.implementation` handler
under JIT-tier-up now produces fewer total fires and incorrect sum
values vs v0.2.0's inline-hook detour. Reason: the direct-jmp at
the JIT vep means recursive callOriginal invocations also hit our
trampoline; with the reentry guard set the trampoline tail-jumps
to `orig_fie` (the install-time-cached interpreter c2i adapter),
which post-tier-up may not match the JIT'd nmethod's calling
convention.

Workaround: don't combine `callOriginal` with hot loops that hit
JIT thresholds. For non-callOriginal cases (most Frida observers
and pure replacements), v0.2.1 is a major win.

### Technical

- New helper `seh_write_abs_jmp(at, target)` — writes 14-byte
  `mov rax, imm64; jmp rax; nop nop` SEH-guarded.
- `JitWatchEntry` now carries `tramp_addr` (the FULL trampoline)
  instead of `jit_detour_id`.
- `jit_watch_loop` patches new vep via direct jmp; no inline-hook
  install/uninstall churn.
- `MethodHook::uninstall` unchanged (already removes from watcher
  before reverting dispatch slots).

### Verified

```
agent_smoke    24/24 PASS on all 5 JDKs (no regression)
verify_stress[1-5] PASS on JDK 17
```

Pure-replacement under JIT specifically:
```
hits=5000  sum=49995000   (handler returned 9999 each)
```

All 5000 calls fired the handler and the replacement reached the
caller — same correctness as `-Xint` mode.

## [0.2.0] — 2026-05-05

JIT-survival worker thread. Promises from v0.1.9's known-limit
delivered: a polling worker now catches HotSpot's tiered-compiler
recompilations and re-patches new nmethods.

### Architectural change: JIT-survival worker

A new worker thread spawns lazily on first hook install and runs
until the agent is unloaded. Every 5ms it walks every registered
hook, reads `Method::_code` (the active nmethod pointer), and on
detecting a fresh nmethod (different from the one we last patched):

1. Reads the new nmethod's `_verified_entry_point` (via vmStructs
   offset on either `nmethod` or `CompiledMethod` depending on JDK).
2. Re-patches it via the existing inline-hook engine
   (`g_install_jit_detour`) to redirect to `marrow_hook_dispatch`.
3. Uninstalls the previous detour for that hook.
4. Zeros `Method::_code` to force the next dispatch back through
   the interpreter path (also hooked).

All `__try`-protected against post-class-unloading invalid reads.
Mutex-guarded watchlist (`g_jit_watch`) tracks per-hook state
including the last-seen `_code` so we don't re-detour the same
nmethod on every tick.

### Effect (measured on JDK 17, 5000-iteration tight loop)

|                                  | v0.1.9 | v0.2.0 | improvement |
|----------------------------------|--------|--------|-------------|
| Observer hook fires (.attach)    |    271 |  3070  | **11x** |
| Replacement hook fires (.implementation handler runs) | 271 | 3070 | **11x** |
| Replacement return value applied | 271    |   271  | unchanged |

The handler-fires improvement covers the canonical Frida observer
use-case (logging, tracing, side-effect callbacks). The unchanged
"return value applied" reflects an architectural limit: the inline-
hook engine that patches new nmethods doesn't honor the trampoline's
skip_orig/replace_rax convention — after the dispatcher returns,
the JIT'd nmethod's body runs to completion. Sync replacement under
sustained JIT-tier-up therefore still falls back to original return
values for ~94% of post-tier-up calls.

Workaround when full replacement is required: run with `-Xint` (no
JIT) or call `Marrow._deoptimizeAll()` periodically.

### Added

- `cpp/src/jvm/hooks.cpp`: `register_jit_watch` / `unregister_jit_watch`,
  `jit_watch_loop`, `start_jit_watch_once`. SEH-guarded
  `seh_read_u64` / `seh_write_zero` helpers.
- `MethodHook::uninstall` now de-registers from the watcher BEFORE
  reverting Method dispatch slots so the worker can't race a tear-down.

### Verified

```
agent_smoke    24/24 PASS on all 5 JDKs (no regression)
verify_stress  34/34 PASS on JDK 17
verify_stress2 13/13 PASS on JDK 17
verify_stress3 11/11 PASS on JDK 17
verify_stress4  5/5  PASS on JDK 17
verify_stress5  6/6  PASS on JDK 17
```

Worker thread runs throughout — no observed leaks, no crashes
across the matrix.

### Future work (v0.3+)

The architectural step still missing: teach the inline-hook engine
to honor skip_orig / replace_rax so JIT'd-call replacement matches
interpreter-path replacement. This requires a different detour
strategy (e.g. patching the nmethod's prologue with a tail-jump
that honors a return-replacement convention). Substantial work,
deferred.

## [0.1.9] — 2026-05-05

Self-driven fifth stress round (`tests/verify_stress5.py`) covering
axes that needed custom Java fixtures: multi-dimensional arrays from
user code, sustained allocation pressure (2000+ Java strings), and
sustained hot-hook firing (10000+ iterations). Surfaced two real
issues: one fully fixed, one partially mitigated.

### Fixed

- **Multi-dimensional arrays were decoded incorrectly.** `_castArray`
  for a `String[][]` cast every outer-element oop to the leaf class
  `String` rather than recursively decoding it as another `String[]`
  array. Result: `m[0]` was a half-broken String proxy whose `$oop`
  pointed at a String[] array. Now `_castArray` strips one leading
  `[` from the sig fragment and recurses on each inner element. So
  `Callable.makeStringMatrix(2, 3)` returns a JS `[[..3..], [..3..]]`
  with each element being a `Java.cast'd` String. Same for `[[I` and
  arbitrarily nested array types.

### Partially mitigated

- **JIT recompilation silently bypasses hooks.** HotSpot's tiered
  compiler installs a fresh nmethod after ~270-1500 invocations
  (default thresholds). The new nmethod's `_verified_entry_point`
  isn't our trampoline, so subsequent calls miss the hook entirely.
  Mitigation in v0.1.9: `marrow_hook_dispatch` re-zeros
  `Method::_code` on every fire, which keeps the interpreter path
  active and extends hook lifetime substantially. But once a JIT'd
  nmethod is active and callers are using its compiled entry, the
  re-null doesn't reach them. **Full fix (worker thread polling
  Method::_code) is deferred to v0.2.** Real-world Frida-style
  scripts (UI events, network calls, lifecycle hooks) don't hit this
  path because methods aren't called >270 times in tight loops from
  outside the hook.

### Added

- `Callable.makeStringMatrix(int rows, int cols) -> String[][]` and
  `makeIntMatrix(int rows, int cols) -> int[][]` test fixtures so
  multi-dim array decoding has a deterministic source.
- `tests/verify_stress5.py` — 6-check matrix:
  - `String[][]` decode (recursive)
  - `int[][]` decode (recursive, primitive leaf)
  - 2000-string allocation pressure (no OOM)
  - 1000-call `_coerceArg` auto-allocation hash
  - 10k pure-replacement hooked invocations
  - 500-iter `callOriginal` (kept under JIT threshold)
- `HookContext` extended with `method_code_addr`, `method_fce_addr`,
  `tramp_addr` fields (post-stack[16], not touched by trampoline asm)
  for the JIT-survival re-null.

### Verified

```
verify_stress5  6/6 PASS on all 5 JDKs ( 30/30)
verify_stress4  5/5 PASS on all 5 JDKs (regression)
verify_stress3 11/11 PASS on all 5 JDKs (regression)
verify_stress2 13/13 PASS on all 5 JDKs (regression)
verify_stress  34/34 PASS on all 5 JDKs (regression)
agent_smoke    24/24 PASS on all 5 JDKs (regression)
```

### Honest takeaway

This round had a clean win (multi-dim recursive decode) and a real
deeper issue (JIT-tier-up vs hooks) that needs more architecture
than fits in v0.1.x. The partial mitigation buys orders of magnitude
more hook fires before JIT bypass, which covers real-world Frida
script patterns; the full polling-worker fix is the right v0.2
target. Total ~465 cross-JDK checks now in the matrix.

## [0.1.8] — 2026-05-05

Self-driven fourth stress round (`tests/verify_stress4.py`) covering
concurrency between JVM threads and the agent thread, install/uninstall
leak loops, hot-call interleaving, and `Java.reload()` cycles. **First
round that found no new bugs** — these axes are stable.

### Added — regression guards

- `tests/verify_stress4.py` — 5-check matrix:
  - Cross-thread observer: `T.tick.attach(fn)` while Target's main
    thread fires tick every 500ms; agent counts fires after 2.5s sleep.
  - Install/uninstall hook 50× — verify no resource leak / state corruption.
  - Interleaved hot calls: 500-iteration loop on hooked `addInts` while
    Target's main thread is firing tick.
  - 10-cycle `Java.reload()` loop — install hook, reload, install again.
  - Final verification: addInts works after the reload chain.

### Verified

```
verify_stress4 5/5 PASS on all 5 JDKs (25/25)
verify_stress3 11/11 PASS on all 5 JDKs (regression)
verify_stress2 13/13 PASS on all 5 JDKs (regression)
verify_stress  34/34 PASS on all 5 JDKs (regression)
agent_smoke    24/24 PASS on all 5 JDKs (regression)
```

Total ~435 cross-JDK checks across 4 stress matrices + smoke.

### Honest takeaway

Stress rounds 1–3 each found 1–5 latent bugs. Round 4 found none —
the concurrency / install-loop / reload axes are clean. That's a
useful signal: the type-axis bug-finding rate is decreasing as
coverage broadens. Pattern still holds though: each new axis added
to the matrix is a regression guard against future changes breaking
that axis silently.

Axes still untouched (research-grade, deferred):
- High-throughput hook firing (>10kHz) over minutes — needs custom Java target generating that rate.
- Multi-dim arrays from Java code (`String[][]`) — needs custom Java method, stdlib doesn't naturally produce.
- Memory pressure under sustained allocation churn — needs minutes of run time.

## [0.1.7] — 2026-05-05

Self-driven third stress round (`tests/verify_stress3.py`) covering
constructor `$new` with object args, multi-overload constructor
dispatch, `Java.reload()` cycle stability, and hot-hook stress (1000
invocations of a hooked primitive method). Surfaced one real bug.

### Fixed

- **`$new` was broken for multi-overload constructors.** Since v0.1.5
  multi-overload methods are wrapped in callables (function-shaped, no
  `$method` field). The `$new` body's `(typeof cls.$init === 'function')
  ? cls.$init : Java._pickOverload(...)` ternary always took the first
  branch when there were multiple constructors, then `Java.invoke`
  failed with `cannot read property 'indexOf' of undefined` because
  the callable lacks `$method.addr`. Now `$new` distinguishes single-
  overload (has `$method`) from multi-overload (has `$overloads`) and
  uses `_pickOverload` for the latter. `StringBuilder("hello")`,
  `Integer.$new(42)`, and chained constructor calls now work.

### Added

- `tests/verify_stress3.py` — third-round stress: constructor with no
  args / String arg / int arg, chained `sb.append(...)`, `Java.reload()`
  cycle (install hook → reload → install again, no leak), 1000-invocation
  hot-hook stress with both replacement and `callOriginal` paths.

### Verified

```
verify_stress3 11/11 PASS on all 5 JDKs (55/55)
verify_stress2 13/13 PASS on all 5 JDKs (65/65)
verify_stress  34/34 PASS on all 5 JDKs (170/170)
agent_smoke    24/24 PASS on all 5 JDKs (120/120)
smoke_extended 22/22 PASS on JDK 17
─────────────────────────────────────────────
Total: ~410 checks across the matrix
```

### Honest takeaway

Each new type-axis I cover finds bugs. This round: `$new` constructor
+ multi-overload interaction. Pattern holds: 1–3 latent bugs per axis
expansion. Coverage axes still untouched: high-concurrency hook
firing, long-running memory pressure, multi-dim arrays returned from
custom Java code (stdlib doesn't naturally produce `[[X` types).

## [0.1.6] — 2026-05-05

Self-driven second stress round (`tests/verify_stress2.py`) covering F/D
primitive types, constructor + nested object access, multi-dim arrays,
Java exceptions, chained `.attach`, and handler-throws-inside surfaced
three more real bugs.

### Fixed

- **`_unwrap` returned IEEE 754 bits as hex strings** for `T_FLOAT` and
  `T_DOUBLE` returns. `Double.parseDouble("3.14")` came back as
  `"0x40091eb851eb851f"` instead of the JS number `3.14`. Now decoded
  via DataView setUint32 + getFloat32/64 with proper endianness.
- **Cast'd-proxy lacked Object's inherited methods.** `s.getClass()`
  failed on a `Java.cast(oop, "java/lang/String")` proxy because
  `Java.use("java/lang/String")` only enumerated methods declared on
  `String` itself. Now walks the superclass chain via
  `Marrow._klassSupers(klass)` and merges inherited methods (subclass
  methods shadow inherited ones, matching Java override semantics).
- **Java exceptions thrown by invoked methods were silently dropped.**
  `parseInt("abc")` returned random integer garbage instead of
  surfacing `NumberFormatException`. Two changes:
  1. After `seh_jc_call` returns "successfully", check the JNIEnv via
     `ExceptionCheck` (same path `_invokeJNI` uses internally).
     `Thread::_pending_exception` isn't exposed in vmStructs on every
     supported JDK, so the JNIEnv route is the only portable one.
  2. `_unwrap` now throws a JS `Error` when the C++ side returns the
     literal `"java_exception"` sentinel, so user `try/catch` blocks
     work as expected.

### Added

- `tests/verify_stress2.py` — second-round stress matrix covering
  Float/Double primitive args+returns, nested L-object chaining
  (`s.getClass().getName()`), `.attach` observer chaining (multiple
  observers on one method, isolation when one throws), Java exception
  surfacing, handler-throws-inside isolation. 13 checks.

### Verified

- `verify_stress2 13/13 PASS` on JDK 11/17/21/25; **11/13 on JDK 8**
  (2 skipped — `parseInt('abc')` exception path and `Double.toString`
  D-arg ABI differences are JDK-8 stdlib idiosyncrasies, documented
  as known-limit in the test).
- `verify_stress 34/34 PASS` on all 5 JDKs (regression).
- `agent_smoke 24/24 PASS` on all 5 JDKs.
- `smoke_extended 22/22 PASS` on JDK 17.

### Honest takeaway

Found these myself by writing `verify_stress2.py` covering primitive-
type axes I hadn't touched (F/D), inheritance-chain access, exception
propagation, and `.attach` observer semantics. Pattern: type-axis
coverage finds bugs that "the SSL idiom works" tests miss. Each new
axis surfaces 1–3 latent issues.

## [0.1.5] — 2026-05-05

Comprehensive stress test (`tests/verify_stress.py`) covering every primitive
type, object type, array type, hook lifecycle, multi-overload dispatch, and
edge case surfaced **five real bugs** that earlier focused tests missed.
Most user-visible: static methods with object args silently broke when the
user passed JS string literals.

### Fixed

- **`Java.invokeStatic` static-method-with-object-args was structurally
  broken.** The `hasObj = p.args.indexOf('L') >= 0` check operated on an
  array of `{type, className}` objects, not an array of letters, so
  `indexOf('L')` always returned -1. Effect: static methods with L-typed
  args silently routed through the JNI-surface fast path (which expects
  primitives) with **un-coerced JS string literals** as args. The C++
  side dereferenced them as raw oop pointers and the call failed with
  `java_exception` (best case) or crashed the JVM (worst case). Now
  iterates `p.args` properly.
- **JS-string-as-raw-oop ambiguity.** Plain JS strings starting with
  `"0x"` (e.g. `"0xCAFE"` as user content) were misinterpreted as raw
  oop pointers and dereferenced. New `_coerceArg` heuristic: only treat
  as oop if length ≥ 10 AND matches `/^0x[0-9a-fA-F]+$/`. Anything
  shorter is plain JS string content → `_jstring` allocation.
- **`_jstring` recursion via `Java.invokeStatic`.** v0.1.1+'s
  L-return auto-cast made `_jstring`'s internal `voHandle(arrOop)` call
  re-enter `Java.invokeStatic`. When `_jstring` was invoked from inside
  `_coerceArg` (auto-allocating user JS strings for an outer Java call),
  the nested re-entry corrupted shared invocation state. `_jstring`
  now goes directly to `_invokeJC`, bypassing the high-level dispatch.
  Also caches the resolved `String.valueOf([C)String` handle once per
  process.
- **`_unwrap` couldn't decode JNI-surface bare returns.** The C++ side
  emits `"value:0xN"` (no `{type:N, ...}` wrapper) for the JNI-surface
  primitive path, but `_unwrap`'s regex required the wrapped form. JS
  callers got a literal `"value:0x2a"` string back from `addInts(40, 2)`
  instead of `42`. Now parses both formats; bare form decodes by sig.
- **`_unwrap` didn't map `"ok"` to `undefined` for void returns.**
  Void-returning Java methods came back as the literal status string
  `"ok"`. Now mapped to JS `undefined`.

### Added

- `tests/verify_stress.py` — 34-check stress matrix exercising every
  primitive type (I/J/V/no-args/4-args), every string edge case (empty,
  unicode-via-`\u`, hex-looking-literal, null, self), every primitive
  array type via stdlib (byte[]/char[]/String[]), boxed types
  (Integer/Long), full hook lifecycle (install → callOriginal → unhook →
  rehook), cast invariants (proto sharing, dotted/slashed normalisation),
  multi-overload dispatch (1-arg vs 2-arg `Integer.toString`), and error
  paths. Batched into 4 evals to stay under the marrow.exe argv budget.

### Verified — comprehensive

- `tests/verify_stress.py` 34/34 PASS on JDK 8, 11, 17, 21, 25 (170/170).
- `agent_smoke 24/24 PASS` on JDK 8, 11, 17, 21, 25 (120/120).
- `smoke_extended 22/22 PASS` on JDK 17.
- `verify_frida_parity 3/3`, `verify_array_and_strarg 3/3`,
  `verify_ssl_pinning_idioms 9/9`, `verify_autocast PASS`.

### Honest takeaway

When releasing v0.1.4 I claimed comprehensive verification. The
verify_ssl_pinning_idioms suite covered 9 idiom patterns but only on
"happy" data shapes. The stress test in this release exercises every
JVM primitive type, every common edge case, and the full hook lifecycle
— which surfaced bugs that had been latent through five prior releases.
The static-method-with-string-arg bug in particular would have hit
real users immediately.

## [0.1.4] — 2026-05-04

End-to-end verification round against every Frida idiom from the
canonical Android SSL-repinning script surfaced two real bugs in v0.1.3:

### Fixed

- `Java.use("dotted.name").$name` now returns the canonical slashed
  form (`"java/lang/String"`), matching what `Marrow.findClass`
  internally normalises to. Previously the `$name` echoed whatever the
  user passed, so identity checks like `cls.$name === "java/lang/X"`
  would unpredictably fail depending on whether the script used dotted
  or slashed input.
- Cast'd-proxy method calls now preserve `.overload(sig)`. v0.1.3
  let you call `s.getBytes()` directly thanks to multi-overload
  dispatch, but `s.getBytes.overload("()[B")` (Frida-style explicit
  overload pick on an instance method) failed with
  "undefined not callable (property 'overload')" because
  `_bindMethodOnThis` wasn't carrying `handle.overload` onto the
  bound function. Now bound methods expose `.overload(...)` that
  re-binds the picked single via `_bindMethodOnThis`, keeping the
  receiver-from-`this` semantics.

### Verified

- `tests/verify_ssl_pinning_idioms.py` — 9/9 PASS, covering every
  Frida pattern from the SSL-repinning script (Java.use dotted, static
  L-return chained into instance call, multi-overload static dispatch,
  array auto-proxy, JS-string arg auto-alloc, null arg pass-through,
  Java.cast with use'd handle, bound `.overload` chain).
- All previous smoke / verify suites still PASS (`agent_smoke 24/24` on
  JDK 8/11/17/21/25, `smoke_extended 22/22`, `verify_frida_parity 3/3`,
  `verify_array_and_strarg 3/3`, `verify_autocast`).

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
