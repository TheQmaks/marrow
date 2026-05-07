# 15_tls_trust_bypass — disable cert pinning

A pinned `X509TrustManager` rejects every server cert by throwing
`SecurityException("CERT_PINNED")`. Marrow hooks the validator's
`checkServerTrusted` method to no-op, defeating the pinning at
runtime — no re-build, no re-sign, no patch on the binary.

This is the vanilla-JVM equivalent of the Frida "SSL re-pinning"
recipe used on Android.

## Run

```bash
javac App.java
"$JAVA_HOME/bin/java.exe" App &
PID=<pid_from_App_output>

"../../cpp/build/Release/marrow.exe" inject $PID \
    "../../cpp/build/Release/marrow_agent.dll"
"../../cpp/build/Release/marrow.exe" agent $PID \
    eval "$(cat attack.js)"
```

## Expected output

Without marrow:

```
App PID: 12345
App ready - inject marrow now.
PINNED: CERT_PINNED
```

With marrow injected before the App's 3-second wait window expires:

```
App PID: 12345
App ready - inject marrow now.
[js] TLS pinning bypassed (chain.length=0)
BYPASSED
```

## Primitive demonstrated

`Java.use(class).method.implementation = fn` with a void return type:

- Sync mode: handler runs from the caller's JVM thread.
- Handler has no return statement (void method) — trampoline takes
  the skip_orig path and RETs to caller without executing the
  original body.
- No `callOriginal` — we want the original to NOT run.

This pattern works on any method with a void or boolean return that
acts as a security check: certificate validators, license validators,
debugger detectors, DRM guards, etc.
