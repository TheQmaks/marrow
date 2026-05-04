# Getting Started with Marrow

A 15-minute tour from "I have a running JVM" to "I'm rewriting its behavior live".

Marrow is a Frida-equivalent for HotSpot. It works by **injecting a DLL** that
contains an embedded Duktape JS engine, then **streaming user scripts** to it
over a named-pipe IPC. Unlike Frida, it never goes through JNI or JVMTI — every
operation reads vmStructs offsets and pokes raw memory.

> **Platform.** Windows x64 only. HotSpot JDK 8 through 25. No JFR/JVMTI agent
> arguments needed on the target — vanilla `java MyApp` is enough.

---

## 0. Build

You need MSVC 2022 + CMake 3.15+. Visual Studio Build Tools is fine.

```powershell
cd cpp
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Outputs (paths relative to `cpp/`):

- `build/Release/marrow.exe` — CLI (injector + script streamer)
- `build/Release/marrow_agent.dll` — agent that lives inside the target JVM

Quick sanity check:

```powershell
.\build\Release\marrow.exe --help
```

---

## 1. Five-minute scenarios

Each scenario assumes you have a `java.exe` running your code and you know its
PID (`tasklist | findstr java` or Process Hacker). From the repo root:

```powershell
$PID_   = 12345                                 # your target's PID
$PROBE  = "cpp\build\Release\marrow.exe"
$AGENT  = "cpp\build\Release\marrow_agent.dll"
```

Then for **every** scenario the flow is:

```powershell
& $PROBE inject $PID_ $AGENT                    # one-time per JVM lifetime
& $PROBE agent  $PID_ eval (Get-Content my_script.js -Raw)
```

The agent stays loaded until the JVM exits. You can `eval` as many scripts as
you want against the same agent.

---

### Scenario 1 — License bypass (1 line of JS)

Example: `examples/01_license_bypass/`. The Java program checks `licenseValid()`
every 500 ms and prints either "trial mode" or "PREMIUM FEATURE UNLOCKED".

```js
// attack.js
var App = Java.use('App');
App.licenseValid.setReturn(1);          // force boolean true
Marrow.log('licenseValid() now always returns true');
```

Run:

```bash
$PROBE agent $PID eval "$(cat attack.js)"
```

Output of the target program flips on the next iteration. No file touched, no
restart, no JNI agent flag.

**What's happening.** `Java.use('App')` finds the InstanceKlass via
SystemDictionary, builds a method handle for `licenseValid`. `setReturn(1)`
emits a tiny `mov rax, 1; ret` thunk and patches the method's `_i2i_entry` to
point at it.

---

### Scenario 2 — Field watch via CPU debug registers

Example: `examples/07_field_watch/`. `App.counter` is mutated from three threads.
Classic "who's writing to this field?" mystery.

```js
// watch.js — install once, then poll for events
var cookie = Java.watchField('App', 'counter', 4);   // 4 bytes for an int
Marrow.log('watching App.counter (cookie=' + cookie + ')');

// Re-run this part every few seconds:
var events = Java.drainWatches();
events.forEach(function(e) {
    var mod = Marrow.moduleAt(e.faultRip);
    Marrow.log('write @ rip=' + e.faultRip +
                 (mod ? ' module=' + mod.name + '+' + mod.offset : ''));
});
```

Each line of output is the RIP that touched the field. Inside the JIT-compiled
code of `incA`/`incB`/`mainThreadInc` you'll see distinct call sites.

**Why this is special.** Frida can't do this. We use DR0–DR3 (CPU hardware
watchpoints, 1 instruction overhead while not writing). Anywhere up to 4
fields can be watched simultaneously across the whole JVM.

---

### Scenario 3 — Native call sniffing (`ws2_32!recv`)

Example: `examples/09_native_recv/`. Read every TCP packet the JVM receives,
including SSL-wrapped traffic post-decryption (it still flows through
`recv` first).

```js
// hook.js
var recvAddr = Marrow.symbolAt('ws2_32.dll', 'recv');
Marrow.log('ws2_32!recv @ ' + recvAddr);

Java.onNative(recvAddr, function(rcx, rdx, r8, r9) {
    Marrow.log('[recv] socket=' + rcx + ' buf=' + rdx + ' len=' + r8);
});

// Periodically (or on a timer in your driver script):
Java.tickNative();
```

`tickNative` drains a lock-free ring buffer of capture events and fires the JS
callback for each. The hook itself is a 32-byte inline trampoline at the
function prologue; capture-and-resume runs in a few nanoseconds.

---

### Scenario 4 — Method profiling

Example: `examples/04_profile/`. Find the hot method without source access.

```js
var trace = Java.traceClass('App', 0xC0DE0000);
Marrow.log('installed ' + trace.installed + ' counters');

// ...let the workload run for a bit, then:
var stats = Java.readTraces(trace);
stats.forEach(function(s) {
    Marrow.log('  ' + s.name + s.sig + ' = ' + s.count);
});
```

`traceClass` patches every method's bytecode prologue with a 5-byte counter
increment that writes into a shared region anchored at the magic address
(`0xC0DE0000`). No allocations, no JNI. Counters survive JIT — when the method
gets compiled, the JIT sees the patched bytecode.

---

### Scenario 5 — Hot-reload dev cycle

The killer feature. Edit your script, push it again, all hooks from the
previous push are torn down automatically before the new one is evaluated.

```js
// dev.js — first version. `packet` is auto-cast to a Java.cast proxy
// for L-typed args, so field access is direct: packet.length, no
// readField boilerplate.
Java.use('App').handlePacket.implementation = function(packet) {
    Marrow.log('packet len=' + packet.length);
};
```

Push it:

```bash
$PROBE agent $PID eval "$(cat dev.js)"
```

Now edit `dev.js` and push again — but first call `Java.reload()` so old hooks
clear:

```bash
$PROBE agent $PID eval "Java.reload(); $(cat dev.js)"
```

Or wrap that pattern in a shell function. Result: zero-overhead iteration —
no JVM restart, no leftover trampolines, no rehook conflicts.

**Under the hood.** `Java.reload()` walks the global hook registry, calls
`MethodHook::uninstall()` for each entry (restores original `_i2i_entry`),
then re-evaluates the bootstrap which redefines `Java = {...}` from scratch.

---

## 2. Mental model

`Java.*` is the **high-level API** — Frida-style ergonomics. Start here.

`Marrow.*` is the **primitive layer** that everything in `Java.*` is built
on. Reach for it when:

- you need to read raw memory (`Marrow.readMem`)
- you want to call a Win32 API (`Marrow.callNative`)
- you're walking unfamiliar HotSpot internals (`Marrow.vmType`,
  `Marrow.vmField`)

There is **no JNI in the call chain**. Every field read is `ReadProcessMemory`
(out-of-process) or a direct dereference (in-agent). Every method invocation
is an asm thunk that calls into the existing interpreter/JIT entry. This is
why nothing in the API takes a `JNIEnv*` and why we work on stripped JVMs
without `-XX:+UnlockDiagnosticVMOptions`.

---

## 3. Where to look next

- **`docs/API.md`** — full reference of all `Java.*` and `Marrow.*` bindings.
- **`examples/`** — 13 real-world demos. Each is `App.java` + one or more
  `.js` scripts. See `examples/README.md` for the index.
- **`cpp/src/script/agent_*.cpp`** and **`cpp/src/native/agent_*.cpp`** —
  one file per binding family. The registrar function at the bottom shows
  exactly which JS names map to which C++ handler. This is the source of
  truth when API.md drifts.
- **`CONTRIBUTING.md`** — design rules: empirical-first, no JNI/JVMTI, no
  hardcoded offsets.

---

## 4. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `inject` hangs | Target is paused in debugger | resume it; injection uses `CreateRemoteThread` |
| `agent: pipe not found` | Agent not yet ready | wait 1 s after inject and retry |
| `Java.use returned null` | Class not loaded yet | call after the class is referenced; or use `Marrow.classWalk` to confirm |
| Crash inside `_allocStats` | Klass pointer was unloaded | known limitation — re-snapshot via `Java.choose` |
| `LNK1104 marrow_agent.dll` while building | Old JVM still has the DLL mapped | `taskkill /f /im java.exe` then rebuild |

If something breaks unrecoverably, the JVM is still alive — agent failures are
SEH-translated and surface as JS exceptions. You won't crash the process by a
bad script.
