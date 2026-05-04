"""Verify Frida-compatible auto-callOriginal: `Cls.method(args)` from
inside `.implementation` automatically routes to original."""
import os
import subprocess
import time
import json
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java


JS = r"""(function(){
    var T = Java.use("Callable");
    var log = [];

    function call(a, b) {
        return Marrow._invokeJNI("Callable", "addInts", "(II)I", "I", [a, b]);
    }
    function unwrap(r) {
        var m = String(r).match(/value:0x([0-9a-f]+)/);
        return m ? parseInt(m[1], 16) : ("raw:" + r);
    }

    log.push("[1] baseline addInts(7,11) = " + unwrap(call(7, 11)));

    // Frida-style: just call T.addInts(a, b) from inside the handler.
    // Should auto-route to original (no infinite recursion).
    T.addInts.implementation = function(a, b) {
        var orig = T.addInts(a * 10, b * 10);   // <-- NO callOriginal!
        return orig;
    };
    log.push("[2] T.addInts(a*10,b*10) inside .impl, addInts(7,11) = " +
             unwrap(call(7, 11)));

    // Same with arg pass-through.
    T.addInts.implementation = function(a, b) { return T.addInts(a, b) + 1000; };
    log.push("[3] T.addInts + 1000 inside .impl, addInts(3,4) = " +
             unwrap(call(3, 4)));

    // Verify outside-handler invocation still fires the hook.
    T.addInts.implementation = function(a, b) { return 42; };
    log.push("[4] outside-handler T.addInts(7,11) hooked-to-42 = " +
             unwrap(call(7, 11)));

    // Frida convention: this.method(args) inside handler.
    T.addInts.implementation = function(a, b) {
        return this(a + 1, b + 1);   // `this` is the handle itself
    };
    log.push("[5] this(a+1, b+1) inside .impl, addInts(7,11) = " +
             unwrap(call(7, 11)));

    // Cleanup.
    T.addInts.implementation = null;
    log.push("[6] after unhook addInts(7,11) = " + unwrap(call(7, 11)));

    return JSON.stringify(log);
})()"""


def main():
    java = find_java("17")
    if not java: print("[SKIP] no JDK 17 installed"); return
    p = subprocess.Popen([java, "-Xmx256m", "-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        line = p.stdout.readline()
        if line.startswith("Target PID:"):
            pid = int(line.split(":", 1)[1].strip()); break
    print(f"Target PID: {pid}")

    subprocess.run([PROBE, "inject", str(pid), AGENT],
                   capture_output=True, timeout=15)
    time.sleep(1.5)

    r = subprocess.run([PROBE, "agent", str(pid), "eval", JS],
                       capture_output=True, text=True, timeout=30)
    log = None
    for L in r.stdout.splitlines():
        if "[agent.reply]" in L and "msg=" in L:
            after = L.split("msg=", 1)[1]
            try: log = json.loads(after); break
            except Exception: continue

    print()
    print("=" * 72)
    print("FRIDA-COMPAT AUTO-CALL-ORIGINAL DEMO")
    print("=" * 72)
    if log is None:
        print(r.stdout[:600])
    else:
        for line in log: print(line)
    print("=" * 72)
    p.kill()


if __name__ == "__main__":
    main()
