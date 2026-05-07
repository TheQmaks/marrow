# 17_auth_intercept — bypass login + log credentials

App calls `login("guest", "wrong-pwd")`. The real check returns false
(only `admin` / `s3cret` succeeds). Marrow hooks `login` and forces
a `true` return regardless of args, while logging the attempted
credentials to the agent's log.

Combines two primitives in one hook: arg inspection + return value
replacement. Vanilla-JVM analogue of Frida's "force-login" recipe.

## Run

```bash
javac App.java
"$JAVA_HOME/bin/java.exe" App &
PID=<pid>

"../../cpp/build/Release/marrow.exe" inject $PID \
    "../../cpp/build/Release/marrow_agent.dll"
"../../cpp/build/Release/marrow.exe" agent $PID \
    eval "$(cat attack.js)"
```

## Expected output

App output (with marrow):
```
App PID: 12345
App ready - inject marrow now.
login result: true
```

Marrow log:
```
[js] hook installed: App.login -> always true + log creds
[js] login attempt: user=guest pass=wrong-pwd -> FORCED true
```

Without marrow the output would be `login result: false`.

## Primitive demonstrated

`Java.use(class).method.implementation = fn` returning a boolean:

- Sync mode: handler runs from caller's JVM thread.
- Handler reads args (`user`, `pass`) — Marrow auto-converts JNI
  string handles to JS strings via `Java.toString`.
- Handler returns `true`. Trampoline's skip_orig path loads
  replace_rax = 1 into rax and returns to caller. Original method
  body never runs.
- Combine with `T.method.callOriginal(args)` if you want to log
  but still let the real check decide (just don't replace the return).

Pattern works on any boolean check — license, feature flag, device
attestation, role-check. Substitute the right class+method.
