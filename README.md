# Marrow

> Crack the JVM open. Read its bones.

A Frida-equivalent dynamic instrumentation toolkit for HotSpot. Read fields,
hook methods, replace return values, watch variables with hardware breakpoints,
clone classes — all from JS scripts you push live into a running JVM.

**No JNI. No JVMTI. No `-agentpath`. No `-XX:+UnlockDiagnosticVMOptions`.**

Marrow drives HotSpot the way HotSpot's own Serviceability Agent does: by
reading the exported `gHotSpotVMTypes` / `gHotSpotVMStructEntries` arrays at
runtime and walking memory directly. Every field offset, every method entry,
every Klass layout is resolved from the JVM you have, not from a baked-in
table. That's how a single binary works on JDK 8 through JDK 25.

---

## Status

- **Platform.** Windows x64. Linux/macOS not on the roadmap.
- **Compatibility.** HotSpot JDK 8, 11, 17, 21, 25 — both JDK and JRE
  distributions, on every supported GC (G1, Parallel, Serial,
  Shenandoah, ZGC).
- **Maturity.** v0.5.0 — every test suite passes strict mode on every
  supported runtime. **60/60 (test-suite × runtime) configurations
  green** as of release. APIs are settling; breaking changes from here
  on get a clear changelog entry.

---

## What it does

Marrow has two surfaces, both backed by the same vmStructs metadata:

**Out-of-process (Python).** `ReadProcessMemory`/`WriteProcessMemory` against
a target JVM. Walk the class dictionary, decode oops, dump strings, snapshot
the heap. No code runs in the target — useful for forensics and post-mortem.

**In-process (C++ agent + JS).** Inject `marrow_agent.dll` into the target,
push JS scripts to it via named pipe. The agent embeds Duktape and exposes a
Frida-compatible `Java.*` API plus a lower-level `Marrow.*` primitive layer.
Hook methods, replace return values, call methods on real instances, walk the
live heap, install hardware-breakpoint field watches.

The same script can be hot-reloaded as many times as you want. `Java.reload()`
tears down all previous hooks and re-evaluates the bootstrap.

---

## Why not just use Frida?

Frida targets native code and treats the JVM as opaque. Marrow understands
HotSpot natively:

|                            | Frida                       | Marrow                                    |
|----------------------------|-----------------------------|-------------------------------------------|
| Java method hooks          | through Java.use() (via JNI) | direct: patch `Method::_i2i_entry`        |
| Field reads/writes         | via JNI                     | vmStructs offset + raw memory             |
| Hardware field watch       | no                          | yes — DR0–DR3 watchpoints                 |
| Heap class histogram       | no                          | yes — walks GC regions                    |
| Klass cloning              | no                          | yes — register clone with SystemDictionary |
| Bytecode rewrite           | no                          | yes — full method body swap               |
| Out-of-process reader      | no — must inject            | yes — Python `RemoteReader`               |
| JVMTI/Attach required      | sometimes                   | never                                     |
| Stripped JVMs (no PDB)     | limited                     | works — vmStructs is exported, not symbol-dependent |

The tradeoff: Marrow is HotSpot-only and Windows-only. Frida is multi-platform.
Pick based on what you actually need.

---

## Quickstart

### 1. Build

You need MSVC 2022 + CMake 3.15+. Visual Studio 2022 Build Tools is enough.

```powershell
cd jvm-probe/cpp
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Produces:

- `cpp/build/Release/marrow.exe` — CLI (injector + script streamer)
- `cpp/build/Release/marrow_agent.dll` — agent loaded into the target

### 2. Launch a target JVM

```powershell
cd tests/target
javac -d build *.java
java -cp build Target
# Target PID: 12345
# tick=0
# tick=1
# ...
```

### 3. Hook a method

`hello.js`:

```js
// Observe every Target.tick(n) call without changing its behaviour.
Java.use('Target').tick.attach(function(n) {
    Marrow.log('tick observed: n=' + n);
});

// Replace Callable.addInts so it always returns 1234, regardless of args.
Java.use('Callable').addInts.implementation = function(a, b) {
    Marrow.log('addInts(' + a + ',' + b + ') hijacked');
    return 1234;
};
```

Push it:

```powershell
$exe = "cpp\build\Release\marrow.exe"
$dll = "cpp\build\Release\marrow_agent.dll"
& $exe inject 12345 $dll
& $exe agent  12345 eval (Get-Content hello.js -Raw)
```

The observer fires on every tick the target makes; the replacement is
synchronous — when anything in the JVM calls `Callable.addInts(a, b)`, the
handler runs from the calling thread and the JVM receives `1234`. No JVM
restart, no agent flag.

### 4. Out-of-process — no injection at all

```python
from vm_meta import VMMeta
from walker import ClassWalker
from string_reader import StringReader
from oop_reader import OopDecoder

vm  = VMMeta.from_pid(12345)
dec = OopDecoder(vm)
sr  = StringReader(vm, dec)

target_klass = next(k for k in ClassWalker(vm) if k.name == 'Target')
print(f'Target loaded at {target_klass.address:#x}')
```

Same metadata, no DLL ever entered the target.

---

## How a hook fires

```
JS: T.tick.implementation = fn
        │
        ▼
  ┌─────────────────────────────────────────────┐
  │ Agent allocates 108-byte trampoline in RWX  │
  │   - saves all GPRs + xmm0..3                │
  │   - copies arg slots from native stack      │
  │   - calls the agent thread with snapshot    │
  │   - if handler returned a value:            │
  │       loads RAX from snapshot.replace_rax   │
  │       RETs to the caller                    │
  │   - else jumps to original _i2i_entry       │
  └─────────────────────────────────────────────┘
        │
        ▼
  Patches Method::_i2i_entry → trampoline
  Patches nmethod::_verified_entry_point if JIT'd
        │
        ▼
  Handler runs synchronously from the JVM thread,
  under a recursive Duktape mutex. Reentry guard
  per cookie lets the handler call the same method
  on itself (Frida-style auto callOriginal).
```

`callOriginal`, `setReturn`, `.attach` (async observer), `Java.choose` (live
instance enumeration), and `Java.cast` (proxy onto an arbitrary oop) all build
on this primitive.

---

## JIT survival

The hard problem with JS-driven JVM instrumentation is HotSpot's tiered
compiler: install a hook on a hot method, and after a few hundred
invocations HotSpot publishes a fresh nmethod whose verified entry point
your trampoline doesn't cover. From v0.3 honest documentation (~7%
hit-rate on sustained `callOriginal` hot loops) to v0.5 closure:

- **Disable JIT for hooked methods at install time.** v0.4 sets the
  `NOT_C1_COMPILABLE | NOT_C2_COMPILABLE | NOT_C2_OSR_COMPILABLE` bits
  on `Method::_access_flags` (JDK 8/11/17). HotSpot's
  `CompilationPolicy::can_be_compiled()` returns false → no nmethod
  ever gets published → no publish/patch race for `callOriginal` to
  lose.
- **JDK 21+ relocated those bits** to a separate
  `Method::_compiler_flags` field that current vmStructs mainline
  doesn't expose. v0.5 finds it empirically — walks Method's exposed
  fields, sorts by offset, identifies the unique 4-byte gap; that's
  `_compiler_flags`. Verified via read-back; access_flags fallback
  still fires in case the heuristic is wrong on a future JDK layout.

Result: **5000/5000 hits** on sustained hot-loop `callOriginal`
instrumentation, same as `-Xint` baseline, on every JDK 8 through 25.
No JVMTI, no Attach API, no per-JDK hardcoded offsets in source code.

---

## Cross-JDK matrix

`tests/agent_smoke.py` covers every CLI/agent command on every supported
JDK and GC combination. v0.5 also runs five stress suites strict mode
across the full matrix (no flaky-test acceptance).

| JDK | G1 | Parallel | Serial | Shenandoah | ZGC | wide oops |
|-----|----|----------|--------|------------|-----|-----------|
| 8   | ✓  | ✓        | ✓      | (n/a)      | (n/a) | ✓ |
| 11  | ✓  | ✓        | ✓      | ✓          | (Win: 14+) | ✓ |
| 17  | ✓  | ✓        | ✓      | ✓          | ✓   | ✓ |
| 21  | ✓  | ✓        | ✓      | ✓          | ✓ generational | ✓ |
| 25  | ✓  | ✓        | ✓      | ✓          | ✓   | ✓ |

**v0.5 strict-mode regression matrix.** Six test suites × ten runtimes
(JDK 8/11/17/21/25 + JRE 8/11/17/21/25) = **60/60 PASS**:

| Suite          | JDK 8/11/17/21/25 | JRE 8/11/17/21/25 |
|----------------|-------------------|-------------------|
| agent_smoke    | 24/24 ×5          | 24/24 ×5          |
| verify_stress  | 34/34 ×5          | 34/34 ×5          |
| verify_stress2 | 13/13 ×5          | 13/13 ×5          |
| verify_stress3 | 11/11 ×5          | 11/11 ×5          |
| verify_stress4 | 5/5 ×5            | 5/5 ×5            |
| verify_stress5 | 6/6 ×5            | 6/6 ×5            |

Run the matrix yourself:

```powershell
# Single JDK
$env:MARROW_TEST_JDK = "17"
python tests/agent_smoke.py
foreach ($s in @('','2','3','4','5')) { python "tests/verify_stress$s.py" }

# JRE flavor — same tests, $MARROW_TEST_RUNTIME picks the runtime
$env:MARROW_TEST_RUNTIME = "jre"
python tests/agent_smoke.py

# Out-of-process Python API matrix
python tests/matrix_smoke.py        # ReadProcessMemory layer
python tests/matrix_cpp_smoke.py    # CLI + injected agent
```

---

## Examples

Real Java programs paired with Marrow scripts that defeat them. Each directory
has `App.java` plus one or more `.js` scripts:

| Demo                              | Primitive demonstrated                  |
|-----------------------------------|-----------------------------------------|
| `examples/01_license_bypass`      | `T.method.setReturn(value)`             |
| `examples/02_password_sniff`      | `T.method.implementation = fn`          |
| `examples/03_game_score`          | `Java.choose` + field setter            |
| `examples/04_profile`             | `Java.traceClass` + counters            |
| `examples/05_crypto`              | hook `Cipher.doFinal`, decode args      |
| `examples/06_leak`                | heap diff snapshots                     |
| `examples/07_field_watch`         | `Java.watchField` (DR0–DR3)             |
| `examples/08_network`             | hook `URL` / `HttpURLConnection`        |
| `examples/09_native_recv`         | `Java.onNative('ws2_32.dll', 'recv')`   |
| `examples/10_hotkey_toggle`       | `Java.onKey` + static field flip        |
| `examples/11_object_arg`          | hook fn, `Java.cast(argOop, 'Klass')`   |
| `examples/12_object_inspect`      | walk arg tree, decode nested Strings    |
| `examples/13_ergonomic_cheat`     | full UI: hotkey toggles cheat suite     |
| `examples/14_hotloop_survival`    | 50K-iter callOriginal under JIT — 100% |
| `examples/15_tls_trust_bypass`    | Defeat pinned X509TrustManager          |
| `examples/16_request_observer`    | Async `.attach` HTTP request log        |
| `examples/17_auth_intercept`      | Force login + log creds                 |

For the **out-of-process Python API** (no DLL injection, just
`ReadProcessMemory`/`WriteProcessMemory`), see `examples/python/`. 18 standalone
scripts covering class walking, heap inspection, ConstantPool surgery,
hardware watchpoints, ZGC decoding, and more.

---

## Performance

Numbers from `tests/bench_hooks.py` on JDK 17, Windows x64, default
GC. Workload: tight loop calling a static `addInts(int,int)` method
through Marrow's JS proxy.

| Variant                          | Per-op |
|----------------------------------|--------|
| Baseline (no hook, JS+JNI dispatch) | ~21 μs |
| `.implementation = fn` overhead  | +0.3 μs |
| Install latency (HookScopedSuspend) | ~450 ms per install/uninstall |

The 21 μs baseline is dominated by Marrow's JS-side dispatch path
(JNI surface vtable lookup + arg conversion); native Java calls
without Marrow are sub-microsecond. The install latency reflects
the SuspendThread/ResumeThread dance Marrow does around the entry-
pointer patches; once installed, runtime overhead is negligible.

For high-throughput observability, prefer `.attach` (async) over
`.implementation` (sync); the async path writes to a per-cookie
ring buffer and the JS handler runs at drain time, not on every
fire.

---

## API stability (v1.0+)

Marrow follows [Semantic Versioning](https://semver.org/) starting
from v1.0.0. The public surface that's guaranteed stable:

- **JS Frida-compat API**: `Java.use`, `Java.cast`, `Java.choose`,
  `Java.invoke`, `Java.invokeStatic`, `Java.toString`, `Java.drain`,
  `.implementation = fn`, `.attach(fn)`, `.callOriginal`, `.setReturn`.
- **JS Marrow primitives**: `Marrow.log`, `Marrow._defineClassNative`,
  `Marrow._invokeJC`, `Marrow._invokeJNI` and their argument shapes.
- **CLI**: `marrow.exe inject`, `marrow.exe agent <pid> eval <js>`,
  `marrow.exe dump`, `marrow.exe threads`, `marrow.exe classes`.
- **Out-of-process Python API**: `VMMeta`, `Reader`, `ClassWalker`,
  `OopDecoder`, `StringReader`.

NOT covered by semver:
- Internal C++ symbols (`marrow_hook_dispatch` ABI, `HookContext`
  layout, trampoline ASM encoding) — these have changed across v0.4 →
  v0.6 → v0.7 and may again.
- Diagnostic helpers (`Marrow._dbg*`, internal probe scripts).
- Empirical heuristics (e.g. `_compiler_flags` gap detection) — they
  may pick a different offset on a future JDK without warning, but
  the user-facing semantics ("hook stays valid under JIT") stays
  guaranteed.

Breaking changes to the stable surface trigger a major version bump.

---

## Limitations

- Windows x64 only. No Linux, no macOS.
- HotSpot only — no OpenJ9, no GraalVM Native Image.
- ZGC on Windows requires JDK 14+ (Temurin 11 doesn't ship it).
- ZGC on JDK 21 requires `-XX:+ZGenerational` (legacy single-gen has no
  exported colour masks we can decode).
- `Class.forName` reachability for cloned classes is blocked on JDK 21+
  pending per-version offset RE — it's the one feature not yet
  data-driven.
- Stripped `jvm.dll` works for everything (we don't need PDBs).
  JRE-only distributions are fully supported as of v0.5 — the same
  test matrix passes strict on every JRE we ship against.

---

## Documentation

- [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) — 15-minute hands-on tour.
- [docs/API.md](docs/API.md) — full reference of `Java.*` and `Marrow.*`.
- [examples/](examples/) — annotated demos with Java source + JS scripts.
- [CHANGELOG.md](CHANGELOG.md) — version history.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to build, test, contribute.

---

## License

[Apache License 2.0](LICENSE).

Marrow embeds [Duktape](https://github.com/svaarala/duktape) (MIT licence)
inside its agent.

---

## Acknowledgements

Marrow stands on the shoulders of HotSpot's own Serviceability Agent — the
exported `gHotSpotVMTypes` / `gHotSpotVMStructEntries` arrays are what make
PDB-free, version-agnostic introspection possible at all. Inspiration also
from [Frida](https://frida.re) (the JS API we deliberately stay compatible
with) and the JVM-Native-Classdumping research line.
