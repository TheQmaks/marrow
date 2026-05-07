"""Verify Marrow._defineClassNative works PDB-less on JDK 21+.

Strategy:
  1. Compile a tiny TestPayload.java to bytecode.
  2. Launch a target JVM (no agent yet).
  3. Inject + push a marrow script that:
     - Reads the bytecode bytes.
     - Calls Marrow._defineClassNative('TestPayload_v0_7', bytes, null).
     - Then Class.forName('TestPayload_v0_7') via JNI surface.
     - Reports both oops.
  4. PASS = both oops non-null AND second equals first (Class.forName
     finds the class we just defined).
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java  # noqa


PAYLOAD_SRC = """\
public class TestPayload_v0_7 {
    public static int magic() { return 0xCAFE; }
}
"""


SCRIPT = """
(function(){
    // Read bytecode bytes from a side-channel: stored in
    // globalThis._bytecode by an earlier _evalString. We pass the
    // bytecode array directly here.
    var bc = globalThis._bytecode;
    if (!bc || !bc.length) return 'no_bytecode';
    var oop = Marrow._defineClassNative('TestPayload_v0_7', bc, null);
    if (!oop || oop === 'null') return 'defineClass_failed';
    return 'defined:' + oop;
})()
"""

VERIFY_SCRIPT = (
    "(function(){"
    "try {"
    "  var k = Java.use('TestPayload_v0_7');"
    "  if (!k) return 'use_returned_null';"
    "  var v = k.magic();"
    "  return 'magic=' + v;"
    "} catch (e) {"
    "  return 'use_threw:' + e;"
    "}"
    "})()"
)


def parse_reply(out):
    for ln in out.splitlines():
        if "[agent.reply]" in ln and "msg=" in ln:
            return ln.split("msg=", 1)[1].strip()
    return None


def main():
    jdk = os.environ.get("MARROW_TEST_JDK", "21")
    java = find_java(jdk)
    if not java: print(f"[SKIP] no JDK {jdk}"); return 0

    # Compile payload class to a temp dir.
    import tempfile
    workdir = tempfile.mkdtemp(prefix="marrow_dc_")
    src = os.path.join(workdir, "TestPayload_v0_7.java")
    with open(src, "w", encoding="utf-8") as f:
        f.write(PAYLOAD_SRC)
    javac = java.replace("java.exe", "javac.exe")
    subprocess.run([javac, "-d", workdir, src], check=True)
    bc_path = os.path.join(workdir, "TestPayload_v0_7.class")
    with open(bc_path, "rb") as f:
        bytecode = f.read()
    print(f"[JDK {jdk}] payload bytecode: {len(bytecode)} bytes")

    # Launch a generic target.
    p = subprocess.Popen([java, "-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        ln = p.stdout.readline()
        if "PID:" in ln:
            pid = int(ln.split(":", 1)[1].strip()); break
    if not pid: p.kill(); print("[FAIL] no PID"); return 1

    subprocess.run([PROBE, "inject", str(pid), AGENT],
                   capture_output=True, timeout=15)
    time.sleep(1.5)

    # Push bytecode into JS globalThis._bytecode.
    bc_js = "globalThis._bytecode = [" + ",".join(str(b) for b in bytecode) + "];"
    push = f"(function(){{ {bc_js} return 'pushed:'+_bytecode.length; }})()"
    r = subprocess.run([PROBE, "agent", str(pid), "eval", push],
                       capture_output=True, text=True, timeout=30)
    rep = parse_reply(r.stdout)
    if not rep or not rep.startswith("pushed:"):
        p.kill(); print(f"[FAIL] push bytecode: {rep}"); return 1
    print(f"  pushed: {rep}")

    r = subprocess.run([PROBE, "agent", str(pid), "eval", SCRIPT],
                       capture_output=True, text=True, timeout=30)
    rep = parse_reply(r.stdout)
    if not rep or not rep.startswith("defined:"):
        p.kill(); print(f"[FAIL] defineClass: {rep}"); return 1
    print(f"  defineClass: {rep}")

    r = subprocess.run([PROBE, "agent", str(pid), "eval", VERIFY_SCRIPT],
                       capture_output=True, text=True, timeout=30)
    rep = parse_reply(r.stdout)
    p.kill()
    if not rep or not rep.startswith("magic=51966"):
        # 0xCAFE = 51966
        print(f"[FAIL] verify: {rep}"); return 1
    print(f"  verify: {rep}")
    print(f"[PASS] defineClass PDB-less injection on JDK {jdk}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
