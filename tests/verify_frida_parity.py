"""Verify the three Frida-parity additions:

1. .overload("int", "int", ...) — variadic Frida-style type strings,
   in addition to the existing .overload("(II)V") JVM-sig form.
2. L-typed return auto-casts to a Java.cast proxy (was raw oop hex).
3. Java.cast(oop, Java.use(...)) — accept a Java.use'd handle as the
   second arg, alongside the existing string form.

Each is fired against Callable / java.lang.String which are already
covered by the smoke suite, so dependencies are well-understood."""
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
    # --- Gap 1: variadic Frida-style overload ---
    "var C = Java.use('Callable');"
    "var addInts_jvm   = C.addInts.overload('(II)I');"
    "var addInts_frida = C.addInts.overload('int', 'int');"
    "out.gap1_jvm_sig    = addInts_jvm.$sig;"
    "out.gap1_frida_sig  = addInts_frida.$sig;"
    "out.gap1_same       = (addInts_jvm.$sig === addInts_frida.$sig);"
    # --- Gap 2: L-return auto-cast ---
    # Use Integer.toString(int) which returns String. After the patch, the
    # invocation should yield a Java.cast proxy (object with $oop/$class),
    # not a raw oop hex string.
    "var I = Java.use('java.lang.Integer');"
    "var s = I.toString.overload('int').apply(null, [42]);"
    "out.gap2_t           = typeof s;"
    "out.gap2_is_proxy    = (s && typeof s === 'object' && s.$oop) ? true : false;"
    "out.gap2_class       = (s && s.$class) ? s.$class : null;"
    "out.gap2_decoded     = (s && s.$oop) ? Java.toString(s.$oop) : null;"
    # --- Gap 3: Java.cast accepting Java.use'd handle ---
    "var rawOop = s && s.$oop ? s.$oop : null;"
    "var StringHandle = Java.use('java.lang.String');"
    "var via_handle = null;"
    "try { via_handle = Java.cast(rawOop, StringHandle); } catch(e){ via_handle = 'ERR:' + e; }"
    "out.gap3_via_handle  = (via_handle && typeof via_handle === 'object' && via_handle.$oop) ? 'proxy_ok' : String(via_handle);"
    "out.gap3_class       = (via_handle && via_handle.$class) ? via_handle.$class : null;"
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

    subprocess.run([PROBE, "inject", str(pid), AGENT],
                   capture_output=True, timeout=15)
    time.sleep(1.5)

    r = subprocess.run([PROBE, "agent", str(pid), "eval", JS],
                       capture_output=True, text=True, timeout=20)
    raw = parse_reply(r.stdout)
    if not raw:
        print("[FAIL] no reply"); print(r.stdout); p.kill(); return 1

    try:
        outer = json.loads(raw)
        d = json.loads(outer) if isinstance(outer, str) else outer
    except Exception as e:
        print(f"[FAIL] parse: {e}"); print(raw); p.kill(); return 1

    print("Result:")
    print(json.dumps(d, indent=2))
    print()

    g1 = d.get("gap1_same") is True and d.get("gap1_frida_sig") == "(II)I"
    g2 = (d.get("gap2_t") == "object" and d.get("gap2_is_proxy") is True
          and d.get("gap2_class") in ("java/lang/String", "java.lang.String")
          and d.get("gap2_decoded") == "42")
    g3 = (d.get("gap3_via_handle") == "proxy_ok"
          and d.get("gap3_class") in ("java/lang/String", "java.lang.String"))

    print(f"Gap 1 (variadic .overload):    {'PASS' if g1 else 'FAIL'}")
    print(f"Gap 2 (L-return auto-cast):    {'PASS' if g2 else 'FAIL'}")
    print(f"Gap 3 (cast w/ use'd handle):  {'PASS' if g3 else 'FAIL'}")
    p.kill()
    return 0 if (g1 and g2 and g3) else 1


if __name__ == "__main__":
    sys.exit(main())
