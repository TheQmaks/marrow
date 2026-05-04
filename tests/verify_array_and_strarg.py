"""Verify two more Frida-parity additions:

1. Array auto-proxy: methods returning [Lname; / [B / etc. yield a JS
   array enhanced with $oop, $length, $elementSig — supports both
   iteration ([i], length) and pass-through (other Java methods see $oop).
2. JS string → Java String implicit allocation in arg position. Calling
   `someJavaMethod("hello")` no longer requires manual Java._jstring.

Tests fire against java.lang.String (which has both array-returning
methods like getBytes() and string-arg methods like equals(Object))."""
import os
import subprocess
import sys
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java  # noqa: E402


JS = (
    "(function(){"
    "var out = {};"
    # --- Array auto-proxy ---
    # String.split(String) returns String[] — pass a String arg too, so
    # both the array auto-proxy and JS-string allocation get exercised.
    "var T = Java.use('Target');"
    "var oop = Marrow.readStaticRef(T.$klass, 'displayName');"
    "var s = Java.cast(oop, 'java/lang/String');"
    # --- Array auto-proxy: getBytes() returns byte[] ---
    "var bytes = null;"
    "try { bytes = s.getBytes(); }"
    "catch (e) { out.bytes_err = String(e); }"
    "out.bytes_isArray   = Array.isArray(bytes);"
    "out.bytes_length    = bytes ? bytes.length : null;"
    "out.bytes_first     = bytes && bytes.length > 0 ? bytes[0] : null;"
    "out.bytes_has_oop   = bytes && bytes.$oop ? true : false;"
    "out.bytes_elem_sig  = bytes && bytes.$elementSig ? bytes.$elementSig : null;"
    # --- Array auto-proxy: split(String) returns String[] ---
    "var parts = null;"
    "try { parts = s.split('#'); }"  # JS-string arg; should auto-allocate
    "catch (e) { out.split_err = String(e); }"
    "out.split_isArray  = Array.isArray(parts);"
    "out.split_length   = parts ? parts.length : null;"
    "out.split_first_t  = parts && parts.length > 0 ? typeof parts[0] : null;"
    # --- JS string → Java String implicit alloc on arg position ---
    # String.equals(Object) — pass a plain JS string; under the hood we
    # should auto-allocate a Java String and the call should succeed.
    "var eq = null;"
    "try { eq = s.equals('not the same'); }"
    "catch (e) { out.eq_err = String(e); }"
    "out.eq_t           = typeof eq;"
    "out.eq_value       = eq;"
    "return JSON.stringify(out);"
    "})()"
)


def parse_reply(out):
    for ln in out.splitlines():
        if "[agent.reply]" in ln and "msg=" in ln:
            return ln.split("msg=", 1)[1].strip()
    return None


def main():
    java = find_java("17")
    if not java:
        print("[SKIP] no JDK 17"); return 0
    p = subprocess.Popen([java, "-Xmx256m", "-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        line = p.stdout.readline()
        if line.startswith("Target PID:"):
            pid = int(line.split(":", 1)[1].strip()); break
    if not pid:
        print("[FAIL] no PID"); return 1
    print(f"Target PID = {pid}\n")

    subprocess.run([PROBE, "inject", str(pid), AGENT],
                   capture_output=True, timeout=15)
    time.sleep(1.5)

    r = subprocess.run([PROBE, "agent", str(pid), "eval", JS],
                       capture_output=True, text=True, timeout=20)
    raw = parse_reply(r.stdout)
    if not raw:
        print("[FAIL] no reply"); print(r.stdout[:600]); p.kill(); return 1
    try:
        outer = json.loads(raw)
        d = json.loads(outer) if isinstance(outer, str) else outer
    except Exception as e:
        print(f"[parse] {e}\n{raw}"); p.kill(); return 1

    print("Result:")
    print(json.dumps(d, indent=2))
    print()

    a1 = (d.get("bytes_isArray") is True
          and isinstance(d.get("bytes_length"), int) and d["bytes_length"] > 0
          and d.get("bytes_has_oop") is True
          and d.get("bytes_elem_sig") in ("B", "[B"))
    a2 = (d.get("split_isArray") is True
          and isinstance(d.get("split_length"), int) and d["split_length"] >= 1)
    s1 = (d.get("eq_t") == "boolean" and "eq_err" not in d)

    print(f"Array auto-proxy (byte[]):       {'PASS' if a1 else 'FAIL'}")
    print(f"Array auto-proxy (String[]):     {'PASS' if a2 else 'FAIL'}")
    print(f"JS-string -> Java-String arg:     {'PASS' if s1 else 'FAIL'}")
    p.kill()
    return 0 if (a1 and a2 and s1) else 1


if __name__ == "__main__":
    sys.exit(main())
