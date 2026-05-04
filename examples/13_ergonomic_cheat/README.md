# Demo 13 — Ergonomic cheat

Showcases the post-refactor agent API: Frida-style proxies, auto-typed
field accessors, JS-string → Java-String allocation, and instance method
binding via `this` in hooks.

## Run

```bash
# in one shell — start the existing Target program
java -Xmx256m -cp ../../tests/target/build Target

# in another shell — note its PID
PID=<pid>
PROBE=../../cpp/build/Release/marrow.exe
AGENT=../../cpp/build/Release/marrow_agent.dll

$PROBE inject $PID $AGENT
$PROBE agent  $PID eval "$(cat cheat.js)"
```

## Expected output

The Target's stdout should change from

```
tick=20 ... greeting=hello from Target  displayName=tick #19
```

to

```
tick=40 ... greeting=OWNED by marrow  displayName=tick #39
```

within one tick after the eval lands.

## What the script demonstrates

| API | Code |
|---|---|
| Class proxy with cached method handles | `var T = Java.use('Target')` |
| `Java.choose` onMatch with cast'd instance | `Java.choose('Target', {onMatch: fn})` |
| Field read (int) | `t.tag` → JS number |
| Field read (String, auto-decoded) | `t.greeting` → JS string |
| Field read (long) | `t.ticks` → hex string `"0xN"` |
| Field write (int) | `t.tag = 0xCAFEBABE` |
| Field write (JS string → Java String) | `t.greeting = "OWNED"` |

## Requirements

* JDK 21 (Temurin temurin-21-jdk + matching `temurin-21-debugimage`).
  The JS-string allocator uses JavaCalls which depends on PDB symbols
  from the debug image being placed alongside `bin/server/jvm.dll`.
* Other JDKs: int/string field writes still work via legacy primitives,
  but `t.greeting = "JS literal"` will throw — pass an oop hex instead.
