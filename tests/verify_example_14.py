"""End-to-end smoke for examples/14_hotloop_survival.

Compiles App.java, launches it, injects marrow, applies attack.js,
waits for the App's 50K-iter loop to finish, drains stats, asserts
hits == 50000 (v0.5 JIT-survival promise).
"""
import os
import subprocess
import sys
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, find_java  # noqa


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EX_DIR    = os.path.join(REPO_ROOT, "examples", "14_hotloop_survival")


def parse_reply(out):
    for ln in out.splitlines():
        if "[agent.reply]" in ln and "msg=" in ln:
            return ln.split("msg=", 1)[1].strip()
    return None


def main():
    jdk = os.environ.get("MARROW_TEST_JDK", "17")
    java = find_java(jdk)
    if not java: print("[SKIP] no JDK"); return 0

    # Compile App.java
    javac = java.replace("java.exe", "javac.exe")
    if os.path.exists(javac):
        subprocess.run([javac, "App.java"], cwd=EX_DIR, check=True)
    elif not os.path.exists(os.path.join(EX_DIR, "App.class")):
        print("[FAIL] no javac and no precompiled App.class"); return 1

    # Launch
    p = subprocess.Popen([java, "-cp", EX_DIR, "App"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        ln = p.stdout.readline()
        if "PID:" in ln:
            pid = int(ln.split(":", 1)[1].strip()); break
    if not pid: p.kill(); print("[FAIL] no PID"); return 1

    # Inject + push attack.js
    subprocess.run([PROBE, "inject", str(pid), AGENT],
                   capture_output=True, timeout=15)
    time.sleep(1.5)
    with open(os.path.join(EX_DIR, "attack.js"), "r", encoding="utf-8") as f:
        attack = f.read()
    r = subprocess.run([PROBE, "agent", str(pid), "eval", attack],
                       capture_output=True, text=True, timeout=30)
    rep = parse_reply(r.stdout)
    if not rep: p.kill(); print(f"[FAIL] attack push: {r.stdout[:300]}"); return 1

    # Wait for App's 50K-iter loop to finish (~50ms loop + 2s sleep).
    time.sleep(3)

    # Drain stats
    drain = ("(function(){return JSON.stringify("
             "{hits:hits, misses:misses, lastSeen:lastSeen});})()")
    r = subprocess.run([PROBE, "agent", str(pid), "eval", drain],
                       capture_output=True, text=True, timeout=15)
    rep = parse_reply(r.stdout)
    p.kill()
    if not rep: print("[FAIL] drain: no reply"); return 1

    # Strip outer JSON.stringify quotes if any
    try:
        d = json.loads(rep)
        if isinstance(d, str): d = json.loads(d)
    except Exception as e:
        print(f"[FAIL] parse: {e}\n  raw: {rep}"); return 1

    print(f"[JDK {jdk}] {json.dumps(d)}")
    ok = d.get("hits") == 50000 and d.get("misses") == 0 and d.get("lastSeen") == 49999
    if ok:
        print(f"[PASS] example 14 hot-loop survival: 50000/50000 hits"); return 0
    else:
        print(f"[FAIL] expected hits=50000 misses=0 lastSeen=49999"); return 1


if __name__ == "__main__":
    sys.exit(main())
