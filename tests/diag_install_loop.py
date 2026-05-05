"""Diagnostic: bisect install/uninstall loop hang on non-JDK-17.
Run with --iter N to test N iterations; default 5 to start small.
"""
import os, sys, subprocess, time, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java  # noqa


SETUP = (
    "(function(){"
    "globalThis._C = Java.use('Callable');"
    "globalThis._results = [];"
    "return 'setup_ok';"
    "})()"
)


def run_loop(n):
    return (
        "(function(){"
        f"var N = {n};"
        "var failed = 0;"
        "var step = 'start';"
        "try {"
        "for (var i = 0; i < N; ++i) {"
        "  step = 'install_'+i;"
        "  _C.addInts.implementation = function(a, b) { return 0xBEEF; };"
        "  step = 'call_hooked_'+i;"
        "  var v = _C.addInts(1, 2);"
        "  if (v !== 0xBEEF) { failed++; _results.push('hooked_'+i+'='+v); }"
        "  step = 'uninstall_'+i;"
        "  _C.addInts.implementation = null;"
        "  step = 'call_orig_'+i;"
        "  var v2 = _C.addInts(3, 4);"
        "  if (v2 !== 7) { failed++; _results.push('orig_'+i+'='+v2); }"
        "}"
        "} catch(e) { _results.push('throw at '+step+': '+e); }"
        "_results.push('finished at '+step);"
        "return JSON.stringify({fails: failed, log: _results});"
        "})()"
    )


def parse_reply(out):
    for ln in out.splitlines():
        if "[agent.reply]" in ln and "msg=" in ln:
            return ln.split("msg=", 1)[1].strip()
    return None


def main():
    jdk = os.environ.get("MARROW_TEST_JDK", "8")
    n = int(os.environ.get("MARROW_DIAG_ITER", "5"))
    java = find_java(jdk)
    if not java: print("no jdk"); return 1
    extra = ["-Xint"] if os.environ.get("MARROW_DIAG_XINT") else []
    p = subprocess.Popen([java] + extra + ["-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        ln = p.stdout.readline()
        if ln.startswith("Target PID:"): pid = int(ln.split(":", 1)[1].strip()); break
    if not pid: p.kill(); return 1
    subprocess.run([PROBE, "inject", str(pid), AGENT], capture_output=True, timeout=15)
    time.sleep(1.5)

    print(f"[JDK {jdk}] N={n}")
    for js, label in [(SETUP, "setup"), (run_loop(n), "loop")]:
        r = subprocess.run([PROBE, "agent", str(pid), "eval", js],
                           capture_output=True, text=True, timeout=180)
        rep = parse_reply(r.stdout)
        if rep is None:
            print(f"[FAIL] {label}: no reply")
            print(f"  stdout: {r.stdout[:400]}")
            print(f"  stderr: {r.stderr[:400]}")
            p.kill(); return 1
        if label == "loop":
            try: d = json.loads(rep)
            except: d = rep
            print(json.dumps(d, indent=2) if isinstance(d, dict) else d)
        else:
            print(f"  {label}: {rep}")
    p.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
