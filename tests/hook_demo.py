"""Frida-style hook demo: hooks Callable.addInts and shows different
hook modes firing.

What you'll see:
  1) Baseline — invoke addInts(7, 11) -> 18 (real method body runs)
  2) .attach(fn) observer — invoke addInts(7, 11), observer fires, original
     still runs, returns 18
  3) .implementation = fn (sync replace) — invoke addInts(7, 11), handler
     fires synchronously and REPLACES the return value with 999
  4) callOriginal from inside replacer — handler calls the original method
     with modified args (a*10, b*10), returns 7*10+11*10 = 180
  5) Unhook (.implementation = null) — invoke addInts(7, 11) -> 18 again

This demonstrates:
  - Hook installation/removal at runtime, no JVM restart
  - Sync handler runs from the JVM thread under Duktape mutex
  - Handler return value populates the trampoline's `replace_rax`
  - Original method reachable from inside the handler via callOriginal
  - Per-thread reentry guard prevents infinite recursion
"""
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

    // ---------- 1) Baseline (real method body runs) ----------
    log.push("[1] baseline addInts(7,11) = " + unwrap(call(7, 11)));

    // ---------- 2) .implementation = fn (sync replace returns 999) ----------
    T.addInts.implementation = function(a, b) { return 999; };
    log.push("[2] .impl returns 999 -> addInts(7,11) = " + unwrap(call(7, 11)));

    // ---------- 3) callOriginal with modified args ----------
    T.addInts.implementation = function(a, b) {
        return T.addInts.callOriginal(a * 10, b * 10);
    };
    log.push("[3] callOriginal(a*10, b*10) -> addInts(7,11) = " + unwrap(call(7, 11)));

    // ---------- 4) Arg-aware handler ----------
    T.addInts.implementation = function(a, b) { return a + b + 1000; };
    log.push("[4] a+b+1000 -> addInts(5,7) = " + unwrap(call(5, 7)));

    // ---------- 5) Unhook ----------
    T.addInts.implementation = null;
    log.push("[5] after unhook addInts(7,11) = " + unwrap(call(7, 11)));

    // ---------- 6) Observer pattern: .attach (async, doesn't change return) ----------
    Java._observed = [];
    T.addInts.attach(function(a, b) { Java._observed.push("a=" + a + " b=" + b); });
    var r6 = unwrap(call(7, 11));
    Java.drain();   // pump async observer queue
    log.push("[6] .attach + addInts(7,11) = " + r6 +
             " | observed = " + JSON.stringify(Java._observed));

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
    # Find the reply line containing msg=[...]  (JSON array).
    log = None
    for L in r.stdout.splitlines():
        if "[agent.reply]" in L and "msg=" in L:
            after = L.split("msg=", 1)[1]
            try: log = json.loads(after); break
            except Exception: continue
    if log is None:
        print("(no reply)"); print(r.stdout[:500]); p.kill(); return

    print()
    print("=" * 72)
    print("HOOK DEMO  --  Callable.addInts(int, int) on JDK 17")
    print("=" * 72)
    for line in log: print(line)
    print("=" * 72)
    p.kill()


if __name__ == "__main__":
    main()
