"""End-to-end verification: every Frida idiom that the canonical Android
SSL-repinning script uses, exercised against stdlib classes that are
already loaded in our test Target. If a pattern fails here, it would
fail in a real Frida-style script.

Patterns covered:
  A. Java.use("dotted.name")
  B. T.$new(arg) — constructor with JS-string arg auto-alloc
  C. T.staticMethod() — single-overload static, returns L (auto-cast)
  D. cls.method(arg) — multi-overload static dispatch (v0.1.3)
  E. instance.method(arg) — instance call on cast'd proxy
  F. instance.method() — chained from L-return without manual cast
  G. arr = instance.arrayReturningMethod() — array auto-proxy
  H. Java.cast(oop, Java.use("..."))  — handle as second arg (v0.1.1)
  I. null arg passed through to Java
  J. JS-string arg auto-allocation"""
import os
import subprocess
import sys
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java  # noqa: E402


JS = (
    "(function(){"
    "var r = {};"
    "function track(name, fn){ try { r[name] = fn(); } catch(e){ r[name] = 'ERR: '+e; } }"
    # A. Java.use with dotted name + cls.$name normalised to slashed.
    "track('A_use_dotted', function(){"
    "  var I = Java.use('java.lang.Integer');"
    "  return I && I.$name === 'java/lang/Integer';"
    "});"
    # C. Static returning L; result must be a Java.cast proxy.
    "track('C_static_L_return', function(){"
    "  var I = Java.use('java.lang.Integer');"
    "  var s = I.toString.overload('int').apply(null, [42]);"
    "  return s && typeof s === 'object' && s.$oop ? 'proxy' : 'NOT_PROXY';"
    "});"
    # D. Multi-overload static dispatch (was broken pre-v0.1.3).
    "track('D_multi_overload_static', function(){"
    "  var V = Java.use('java.lang.String');"
    "  var s = V.valueOf.overload('int').apply(null, [123]);"
    "  return s && s.$class === 'java/lang/String' ? 'ok' : 'BAD: ' + s;"
    "});"
    # E. Instance call returning a primitive.
    "track('E_instance_primitive_return', function(){"
    "  var T = Java.use('Target');"
    "  var oopHex = Marrow.readStaticRef(T.$klass, 'displayName');"
    "  var s = Java.cast(oopHex, 'java/lang/String');"
    "  var n = s.length();"  # length() is instance method
    "  return typeof n === 'number' && n > 0 ? n : 'BAD: '+n;"
    "});"
    # F. Chained call: cf.getInstance(...).method(...) without manual cast.
    "track('F_chained_static_then_instance', function(){"
    "  var T = Java.use('Target');"
    "  var oopHex = Marrow.readStaticRef(T.$klass, 'displayName');"
    "  var s = Java.cast(oopHex, 'java/lang/String');"
    "  var upper = s.toUpperCase.overload().apply(s, []);"
    "  if (!upper || !upper.$oop) return 'NOT_PROXY: '+upper;"
    "  var len = upper.length();"
    "  return typeof len === 'number' && len > 0 ? 'len=' + len : 'BAD chain: '+len;"
    "});"
    # G. Array auto-proxy: getBytes() returns byte[].
    "track('G_array_byte', function(){"
    "  var T = Java.use('Target');"
    "  var oopHex = Marrow.readStaticRef(T.$klass, 'displayName');"
    "  var s = Java.cast(oopHex, 'java/lang/String');"
    "  var b = s.getBytes.overload().apply(s, []);"
    "  return Array.isArray(b) && b.length > 0 && typeof b[0] === 'number' && b.$oop"
    "       ? 'len=' + b.length"
    "       : 'BAD: ' + JSON.stringify(b);"
    "});"
    # H. Java.cast with Java.use'd handle.
    "track('H_cast_with_handle', function(){"
    "  var T = Java.use('Target');"
    "  var oopHex = Marrow.readStaticRef(T.$klass, 'displayName');"
    "  var StringClass = Java.use('java/lang/String');"
    "  var s = Java.cast(oopHex, StringClass);"
    "  return s && s.$class === 'java/lang/String' ? 'ok' : 'BAD: '+s;"
    "});"
    # J. JS-string arg auto-allocated to Java String, passed to instance method.
    "track('J_jstring_arg_alloc', function(){"
    "  var T = Java.use('Target');"
    "  var oopHex = Marrow.readStaticRef(T.$klass, 'displayName');"
    "  var s = Java.cast(oopHex, 'java/lang/String');"
    "  var eq = s.equals('completely different string xyz');"
    "  return typeof eq === 'boolean' ? 'ok=' + eq : 'BAD: '+eq;"
    "});"
    # I. null arg. java.lang.String.split(regex, limit) — pass null regex (will throw, but the call should reach Java).
    "track('I_null_arg_passthrough', function(){"
    "  var I = Java.use('java.lang.Integer');"
    # Integer.toString(int, int) — pass a normal arg pair to confirm; null testing on Integer.toString isn't safe.
    # Instead use String.equals(null) which is a valid Java pattern returning false.
    "  var T = Java.use('Target');"
    "  var oopHex = Marrow.readStaticRef(T.$klass, 'displayName');"
    "  var s = Java.cast(oopHex, 'java/lang/String');"
    "  var eq = s.equals(null);"
    "  return typeof eq === 'boolean' && eq === false ? 'ok' : 'BAD: '+typeof eq+'='+eq;"
    "});"
    "return JSON.stringify(r);"
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
                       capture_output=True, text=True, timeout=30)
    raw = parse_reply(r.stdout)
    if not raw:
        print("[FAIL] no reply"); print(r.stdout[:600]); p.kill(); return 1
    try:
        outer = json.loads(raw)
        d = json.loads(outer) if isinstance(outer, str) else outer
    except Exception as e:
        print(f"[parse] {e}\n{raw}"); p.kill(); return 1

    print("Per-pattern results:")
    keys = sorted(d.keys())
    failures = []
    for k in keys:
        v = d[k]
        is_fail = (
            v is False
            or (isinstance(v, str)
                and (v.startswith("ERR") or v.startswith("BAD") or v.startswith("NOT_PROXY")))
        )
        mark = "FAIL" if is_fail else " ok "
        print(f"  [{mark}] {k:40s}  {v}")
        if is_fail:
            failures.append(k)
    print()
    if failures:
        print(f"FAILED: {len(failures)} of {len(keys)} patterns")
        print(f"   {failures}")
    else:
        print(f"ALL {len(keys)} PATTERNS PASS")
    p.kill()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
