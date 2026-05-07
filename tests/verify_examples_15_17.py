"""End-to-end smoke for examples 15-17 (cookbook trio).

Each example: compile App.java, launch JVM, inject marrow, push
attack.js, read App stdout, assert expected line.
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, find_java  # noqa


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse_reply(out):
    for ln in out.splitlines():
        if "[agent.reply]" in ln and "msg=" in ln:
            return ln.split("msg=", 1)[1].strip()
    return None


def run_example(jdk, ex_dir, expected_app_line, javac_first=True):
    java = find_java(jdk)
    if not java: return f"[SKIP] no JDK {jdk}"

    if javac_first:
        javac = java.replace("java.exe", "javac.exe")
        if os.path.exists(javac):
            subprocess.run([javac, "App.java"], cwd=ex_dir, check=True)

    p = subprocess.Popen([java, "-cp", ex_dir, "App"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        ln = p.stdout.readline()
        if "PID:" in ln:
            pid = int(ln.split(":", 1)[1].strip()); break
    if not pid: p.kill(); return "[FAIL] no PID"

    subprocess.run([PROBE, "inject", str(pid), AGENT],
                   capture_output=True, timeout=15)
    time.sleep(1.5)
    with open(os.path.join(ex_dir, "attack.js"), "r", encoding="utf-8") as f:
        attack = f.read()
    r = subprocess.run([PROBE, "agent", str(pid), "eval", attack],
                       capture_output=True, text=True, timeout=15)
    rep = parse_reply(r.stdout)
    if not rep: p.kill(); return f"[FAIL] no reply to attack: {r.stdout[:200]}"

    # Wait for App to finish + read remaining stdout.
    found = False
    t0 = time.time()
    while time.time() - t0 < 8:
        ln = p.stdout.readline()
        if not ln: break
        if expected_app_line in ln:
            found = True
            break
    p.kill()
    if not found:
        return f"[FAIL] expected '{expected_app_line}' not in stdout"
    return "[PASS]"


def main():
    jdk = os.environ.get("MARROW_TEST_JDK", "17")
    examples = [
        ("15_tls_trust_bypass",  "BYPASSED"),
        ("17_auth_intercept",    "login result: true"),
        # 16 is observer-only — App output unchanged. We assert that
        # marrow's _reqHits became 5 by reading globalThis directly.
    ]
    fails = 0
    for ex_name, expected in examples:
        ex_dir = os.path.join(REPO_ROOT, "examples", ex_name)
        result = run_example(jdk, ex_dir, expected)
        print(f"  {ex_name}: {result}")
        if "FAIL" in result: fails += 1

    # Example 16: passive observer — verify via marrow eval after run.
    ex16 = os.path.join(REPO_ROOT, "examples", "16_request_observer")
    java = find_java(jdk)
    if java:
        javac = java.replace("java.exe", "javac.exe")
        if os.path.exists(javac):
            subprocess.run([javac, "App.java"], cwd=ex16, check=True)
        p = subprocess.Popen([java, "-cp", ex16, "App"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            bufsize=1, errors="replace")
        pid = None
        t0 = time.time()
        while time.time() - t0 < 10:
            ln = p.stdout.readline()
            if "PID:" in ln:
                pid = int(ln.split(":", 1)[1].strip()); break
        if pid:
            subprocess.run([PROBE, "inject", str(pid), AGENT],
                           capture_output=True, timeout=15)
            time.sleep(1.5)
            with open(os.path.join(ex16, "attack.js"), "r", encoding="utf-8") as f:
                attack = f.read()
            r0 = subprocess.run([PROBE, "agent", str(pid), "eval", attack],
                                 capture_output=True, text=True, timeout=15)
            print(f"    install reply: {parse_reply(r0.stdout)!r}")
            # Wait for App's 5 calls + drain.
            time.sleep(4)
            r = subprocess.run([PROBE, "agent", str(pid), "eval",
                                "(function(){try{Java.drain();"
                                "return 'hits='+globalThis._reqHits;}"
                                "catch(e){return 'err:'+e;}})()"],
                               capture_output=True, text=True, timeout=15)
            rep = parse_reply(r.stdout)
            p.kill()
            ok = (rep == "hits=5")
            print(f"  16_request_observer: {'[PASS] ' + str(rep) if ok else '[FAIL] ' + str(rep)}")
            if not ok: fails += 1

    print()
    print(f"{'PASS' if fails == 0 else 'FAIL'} ({len(examples) + 1 - fails}/{len(examples) + 1})")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
