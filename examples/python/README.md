# Python out-of-process demos

These demos exercise Marrow's **Python API** — the out-of-process surface that
reads/writes a target JVM via `ReadProcessMemory`/`WriteProcessMemory`.
**No DLL is injected** — the target keeps running unmodified, we just inspect
and mutate its memory from outside.

Compare with `examples/01_*/`..`examples/13_*/` which exercise the **in-process
agent** (DLL injection + JS scripts).

## Run pattern

Each demo launches `tests/target/build/Target` itself (auto-detects JDK from
`../../jdks/temurin-{8,11,17,21,25}-jdk/`), so all you need is:

```powershell
cd ..\..                   # repo root
python examples/python/demo_classes.py
```

The target's PID is read from its first line of stdout; the demo then attaches
out-of-process and exercises whatever primitive it's demonstrating.

JDK lookup order:
1. `$env:MARROW_JDKS` (env var override)
2. `<repo>/../jdks/temurin-{N}-jdk/...` (sibling-of-repo dev layout)

## Index

| Script | What it shows |
|--------|---------------|
| `demo_classes.py` | Enumerate every loaded Klass with its name (CLDG + SystemDictionary walks) |
| `demo_threads.py` | List every JavaThread with state/id |
| `demo_heap_walk.py` | Find every instance of a given class |
| `demo_alloc.py` | Construct a brand-new Java String from outside the JVM |
| `demo_write.py` | Write a static `int` field |
| `demo_ref_write.py` | Replace a live Java reference field |
| `demo_zgc.py` | Read fields from a target running under ZGC |
| `demo_zgc_write.py` | Overwrite a reference field under generational ZGC |
| `demo_invoke.py` | Execute our own code inside the target by bytecode rewrite |
| `demo_hooks.py` | Install a native counting hook on `Target.tick(I)V` |
| `demo_watchers.py` | Live-watch two static fields across 5 JDKs |
| `demo_hw_watch.py` | Hardware-assisted field watcher via VEH + VirtualProtect (legacy) |
| `demo_hw_watch_dr.py` | Byte-level hardware watchpoint via CPU DR0-DR3 |
| `demo_cp_clone.py` | Clone Target's ConstantPool into our own page |
| `demo_cp_extend.py` | Extend Target's ConstantPool with extra slots |
| `demo_cp_invoke.py` | Extend CP with a Methodref that duplicates an existing one |
| `demo_cp_invoke_new_cache.py` | Extend CPCache with a brand-new entry |
| `demo_cp_invoke_synthesized.py` | Invoke using a cache entry whose `_flags` were synthesised |

## Why Python here?

The Python API was Marrow's original surface — it predates the C++ agent and
was used to validate every vmStructs path before the in-process port. It's
still useful when:

- You don't want to inject anything (forensics / post-mortem).
- You want to scriptable repro of a JVM bug from a one-off shell.
- You're learning the layout — Python's `vm_meta` is very direct and easy to
  step through in an REPL.

For interactive instrumentation (hooks, JS scripts, hot-reload), use the C++
agent demos in `../01_license_bypass/`..`../13_ergonomic_cheat/`.
