# 16_request_observer — passive request logger

App processes 5 mock HTTP requests through `handle(String)`. Marrow
attaches a passive observer that logs every request as it goes
through the handler — without modifying the response or stalling
the JVM thread.

Vanilla-JVM equivalent of Frida's "log every Activity call" recipe.

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

Marrow log:
```
[js] observer attached: App.handle
[js] observed 5 requests:
[js]   [0] GET /
[js]   [1] POST /api/login
[js]   [2] DELETE /user/42
[js]   [3] PUT /config
[js]   [4] GET /health
```

App output (unchanged — observer is passive):
```
[handler] OK: 5 bytes
[handler] OK: 16 bytes
[handler] OK: 14 bytes
[handler] OK: 10 bytes
[handler] OK: 11 bytes
```

## Primitive demonstrated

`Java.use(class).method.attach(fn)`:

- Async mode: handler arg snapshots written to a per-cookie ring
  buffer (1024 slots after v0.4); drained later via `Java.drain()`.
- Original method runs unchanged — observer doesn't block.
- Safe on hot methods at MHz-rate fires; ring overwrites old
  events if drain rate doesn't keep up.

For a TCP/HTTP middleware, swap `App.handle` with the framework's
real entry point — Servlet's `service()`, Netty's `channelRead()`,
HttpServer's `HttpHandler.handle()`, etc.
