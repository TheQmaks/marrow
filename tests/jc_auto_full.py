"""Auto-bootstrap + L args + instance receiver via _invokeJC PDB-less.

Verifies:
- 1st _invokeJC call auto-resolves JC::call (no explicit Java.resolveJavaCallsCall)
- L arg via _invokeJC works (Callable.strLen("hello") -> 5)
- Instance receiver via _invokeJC works (String.length on a String oop)
- Subsequent calls don't re-resolve (cache works)
"""

import os
import subprocess
import time
import json
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java

JS = """(function(){
    var out = {};

    // Snapshot resolver state BEFORE first _invokeJC.
    out.beforeCache = Java._jcCallCache;
    out.beforeTried = Java._jcResolveTried;

    // 1) Primitive call -- should trigger auto-bootstrap.
    var T = Java.use("Callable");
    var nev = T.neverCalled;
    var addrN = Java._parseHex(nev.address);
    out.primitive = Marrow._invokeJC(addrN.lo, addrN.hi, "I");

    // After first call, resolver should have run + cached.
    out.afterCache = Java._jcCallCache;
    out.afterTried = Java._jcResolveTried;

    // 2) L arg test: Callable.strLen("hello") -> 5.
    var sH = Java._jstring("hello");           // returns wide oop hex
    var sl = T.strLen;
    var addrSl = Java._parseHex(sl.address);
    out.L_arg = Marrow._invokeJC(addrSl.lo, addrSl.hi, "I", "L", [sH]);

    // 3) Instance receiver: String.length() on "hello".
    var Str = Java.use("java.lang.String");
    var lenH = Str.length.overload("()I");
    var addrL = Java._parseHex(lenH.address);
    // Pass receiver oop in 6th arg slot (recv_hex).
    // Sig: ()I -> no args, no arg_types, no arg_arr.
    out.instance = Marrow._invokeJC(addrL.lo, addrL.hi, "I", "", [], sH);

    // 4) Subsequent call should NOT trigger the resolver again
    //    (verified by checking the active flag remains false during call).
    out.activeAfter = Java._jcResolverActive;

    return JSON.stringify(out);
})()"""


def main():
    version = os.environ.get("JDK_VERSION", "17")
    if len(sys.argv) > 1 and sys.argv[1].lstrip("-").isdigit():
        version = sys.argv[1].lstrip("-")
    java = find_java(version)
    if not java:
        print(f"[SKIP] no JDK {version} installed"); return
    print(f"[INFO] Using JDK {version}: {java}")
    p = subprocess.Popen([java, "-Xmx256m", "-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        line = p.stdout.readline()
        if line.startswith("Target PID:"):
            pid = int(line.split(":", 1)[1].strip()); break
    subprocess.run([PROBE, "inject", str(pid), AGENT], capture_output=True, timeout=15)
    time.sleep(1.5)

    r = subprocess.run([PROBE, "agent", str(pid), "eval", JS],
                       capture_output=True, text=True, timeout=60)
    line = ""
    for L in r.stdout.splitlines():
        if "[agent.reply]" in L: line = L; break
    m = re.search(r'msg=({.*})', line, re.DOTALL)
    if not m:
        print(f"NO PARSE\nstdout: {r.stdout[:500]}")
        p.kill(); return
    d = json.loads(m.group(1))
    print("Result:")
    expectations = {
        "beforeCache": "null",
        "primitive": "0xcafebabe",
        "afterCache": "0x",
        "afterTried": True,
        "L_arg": "0x5",       # strLen("hello") = 5
        "instance": "0x5",    # "hello".length() = 5
        "activeAfter": False,
    }
    for k, v in d.items():
        s = str(v).lower() if isinstance(v, str) else v
        exp = expectations.get(k)
        marker = ""
        if exp is None:
            pass
        elif exp == "null":
            marker = " *OK*" if v is None else " *EXPECTED null*"
        elif isinstance(exp, bool):
            marker = " *OK*" if v == exp else f" *EXPECTED {exp}*"
        elif exp in str(s) or (exp == "0x" and isinstance(v, str) and v.startswith("0x")):
            marker = " *OK*"
        else:
            marker = f" *EXPECTED {exp}*"
        print(f"  {k}: {v}{marker}")
    p.kill()


if __name__ == "__main__":
    main()
