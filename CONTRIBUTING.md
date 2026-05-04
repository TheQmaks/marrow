# Contributing to Marrow

Thanks for taking a look. Marrow is a small, opinionated codebase — please
read this before opening a non-trivial PR so we stay aligned.

## Ground rules

1. **No JNI, no JVMTI, no Attach API.** Marrow is one level below the public
   APIs by design. Every field offset comes from `gHotSpotVMTypes`/
   `gHotSpotVMStructEntries` at runtime. If you find yourself reaching for
   `jvmti.h` or `jni.h` on the *target* side, you're solving the wrong
   problem. (We do call into JNI vtable thunks from the agent for routing,
   but never as a metadata source.)

2. **No hardcoded offsets.** No literals, no per-JDK branches in the field
   path. If a layout changes between JDKs, the answer is "look it up in
   vmStructs", not `if (jdk >= 17) offset += 8`.

3. **Empirical first.** Verify any layout claim against an actual vmStructs
   dump from the JDK in question before writing code that depends on it.

4. **Surgical changes.** Don't rewrite neighbouring code. Don't reformat.
   Don't "improve" things that aren't part of your task. Each diff line
   should follow directly from the change you're making.

5. **Simplicity first.** No premature abstractions. No "flexibility" if
   nobody asked for it. Three similar lines beats a configurable helper.

## Build

You need MSVC 2022 + CMake 3.15+.

```powershell
cd cpp
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Outputs land in `cpp/build/Release/`.

If you get `LNK1104 marrow_agent.dll`, an old JVM still has the DLL
mapped — `taskkill /f /im java.exe` and rebuild.

## Tests

Smoke tests live in `tests/`. Most need at least one JDK installed under
`%MARROW_JDKS%` (or `../jdks/temurin-{N}-jdk/...` relative to repo root).

```powershell
python tests/agent_smoke.py 17           # in-process agent on JDK 17
python tests/smoke_extended.py 17        # extended in-process battery
python tests/matrix_smoke.py             # out-of-process Python API across JDKs
python tests/matrix_cpp_smoke.py         # CLI commands across JDKs/GCs
```

A change that touches the agent or a vmStructs path **must** keep
`agent_smoke 24/24` and `smoke_extended 22/22` green on every supported
JDK before review. If you don't have all five JDKs locally, say so in the
PR and we'll cover the gap.

## Adding a new JS binding

1. Implement the C++ handler in `cpp/src/script/agent_*.cpp` (one file per
   binding family — pick the existing one that fits, or add a new file
   following the same pattern).
2. Register it in the `register_*_bindings` function at the bottom of that
   file.
3. Add a smoke check to `tests/agent_smoke.py` so we won't silently break
   it later.
4. Document it in `docs/API.md`.

Name JS bindings using the existing convention:
- `Java.*` for high-level Frida-style ergonomics.
- `Marrow.*` for primitives (memory I/O, native calls, vmStructs lookups).

## Cross-JDK discipline

When you add code that depends on a structure layout, ask:

- Has this field existed since JDK 8?
- Has its name changed across versions?
- Does its type change with `-UseCompressedOops`? With `-UseCompressedClassPointers`?
- Does ZGC colour the pointer? Generational ZGC colour it differently?

The answers all live in the running JVM's vmStructs. Read them from there;
if a field is missing on a given JDK, fall back gracefully and surface the
fact in a smoke check, not in production.

## Commit style

- Short imperative subject (under 70 chars), present tense.
- Body explains the **why** (reason / past incident / constraint), not the
  what — the diff is the what.
- One logical change per commit. Separate refactor commits from behaviour
  changes.

## Reporting bugs

Include:

- JVM vendor + version (`java -version`).
- GC flag (`-XX:+UseG1GC` etc.).
- `-XX:+UseCompressedOops` / `-XX:-UseCompressedOops` if relevant.
- Marrow commit SHA.
- Minimal repro: a `.java` source plus the `.js` script you ran.
- The exact CLI invocation and its full stdout/stderr.

## Licence

By contributing, you agree your contribution is licensed under
[Apache 2.0](LICENSE).
