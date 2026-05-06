# 14_hotloop_survival — JIT-survival demo

Demonstrates v0.5's JIT-suppression at install time: a hooked method
stays interpreter-only forever, so the trampoline survives even under
sustained 50,000-iteration tight loops where HotSpot would normally
tier-up to C1/C2 and publish nmethods that bypass the hook.

## Run

```bash
javac App.java
"$JAVA_HOME/bin/java.exe" App &
PID=<pid_from_App_output>

# Inject + push the hook
"../../cpp/build/Release/marrow.exe" inject $PID \
    "../../cpp/build/Release/marrow_agent.dll"
"../../cpp/build/Release/marrow.exe" agent $PID \
    eval "$(cat attack.js)"

# (App now runs its 50,000-iter loop; takes ~50ms)

# After loop completes, drain the stats:
"../../cpp/build/Release/marrow.exe" agent $PID eval \
    '(function(){return JSON.stringify({hits:hits,misses:misses,lastSeen:lastSeen});})()'
```

## Expected output (v0.5)

```
{"hits":50000,"misses":0,"lastSeen":49999}
```

Every single one of the 50,000 calls hit the JS handler. The handler
called `callOriginal` 50,000 times. No JVMTI, no Attach API.

## Pre-v0.4 baseline (for context)

On v0.3 — the version that documented the "JVMTI-free ceiling" — the
same script returned approximately:

```
{"hits":3500,"misses":46500,"lastSeen":49999}
```

7% hit rate. The 93% miss is the JIT publishing a fresh nmethod
whose verified entry point bypasses the patched
`Method::_from_compiled_entry`.

## What changed

v0.4 sets `NOT_C1_COMPILABLE | NOT_C2_COMPILABLE | NOT_C2_OSR_COMPILABLE`
bits in `Method::_access_flags` at install time → HotSpot's
`CompilationPolicy::can_be_compiled()` returns false → no nmethod
ever published → the publish/patch race that the polling-based
v0.2 / v0.3 worker chased disappears.

v0.5 extends this to JDK 21+ where those bits relocated to
`Method::_compiler_flags` (a vmStructs-hidden field): empirical layout
detection finds the unique 4-byte gap between exposed Method fields
and writes there, with read-back verification.

See `CHANGELOG.md` v0.4.0 / v0.5.0 entries for the full story.
