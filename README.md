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
- **Compatibility.** HotSpot JDK 8, 11, 17, 21, 25.
- **Maturity.** v0.1.0 — research-grade. Smoke tests green on all five JDKs;
  APIs may still shift.

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

## Cross-JDK matrix

`tests/agent_smoke.py <jdk>` covers every command on every supported JDK:

| JDK | G1 | Parallel | Serial | Shenandoah | ZGC | wide oops |
|-----|----|----------|--------|------------|-----|-----------|
| 8   | ✓  | ✓        | ✓      | (n/a)      | (n/a) | ✓ |
| 11  | ✓  | ✓        | ✓      | ✓          | (Win: 14+) | ✓ |
| 17  | ✓  | ✓        | ✓      | ✓          | ✓   | ✓ |
| 21  | ✓  | ✓        | ✓      | ✓          | ✓ generational | ✓ |
| 25  | ✓  | ✓        | ✓      | ✓          | ✓   | ✓ |

Result on each: `agent_smoke 24/24 PASS · smoke_extended 22/22 PASS`.

Run the matrix yourself:

```powershell
python tests/matrix_smoke.py        # Python out-of-process API
python tests/matrix_cpp_smoke.py    # C++ CLI + injected agent
```

The matrix loops over (JDK × GC × compressed-oops) and verifies that read,
write, hook, alloc, clone-class, and instance enumeration all work in every
combination.

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

For the **out-of-process Python API** (no DLL injection, just
`ReadProcessMemory`/`WriteProcessMemory`), see `examples/python/`. 18 standalone
scripts covering class walking, heap inspection, ConstantPool surgery,
hardware watchpoints, ZGC decoding, and more.

---

## Limitations

- Windows x64 only. No Linux, no macOS.
- HotSpot only — no OpenJ9, no GraalVM Native Image.
- ZGC on Windows requires JDK 14+ (Temurin 11 doesn't ship it).
- ZGC on JDK 21 requires `-XX:+ZGenerational` (legacy single-gen has no
  exported colour masks we can decode).
- `Class.forName` reachability for cloned classes is blocked on JDK 21+
  pending per-version offset RE.
- Stripped `jvm.dll` works for everything (we don't need PDBs), but on JRE-only
  builds a few JNI-routed paths fall back through the public JNI vtable.

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
