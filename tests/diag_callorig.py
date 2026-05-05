"""Diagnostic: count tramp fires vs handler hits to find why callOriginal
under hot loop loses 230/500 calls. Three numbers expected:

  fire_total       == 1000 (500 outer + 500 inner via callOriginal)
  skip_reentry     == 500  (inner calls skipped by reentry guard)
  hits             == 500  (handler ran on every outer call)

If hits<500 AND skip_reentry==500, then 230 outer calls bypassed tramp
entirely (JIT route?). If skip_reentry > 500, then reentry slot leaked
across outer iterations.
"""
import os, sys, subprocess, time, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java  # noqa


SETUP = (
    "(function(){"
    "globalThis._C = Java.use('Callable');"
    "Marrow._dbgReset();"
    "globalThis._stats = {};"
    "return 'setup_ok';"
    "})()"
)

RUN = (
    "(function(){"
    "var hits = 0;"
    "_C.addInts.implementation = function(a, b) {"
    "    hits++;"
    "    return _C.addInts.callOriginal(a, b) * 2;"
    "};"
    "var N = 5000;"
    "var sum = 0;"
    "for (var i = 0; i < N; ++i) sum += _C.addInts(3, 4);"
    "_C.addInts.implementation = null;"
    "_stats.iter        = N;"
    "_stats.hits        = hits;"
    "_stats.sum         = sum;"
    "_stats.fire_total  = Marrow._dbgFireTotal();"
    "_stats.skip_reent  = Marrow._dbgSkipReentry();"
    "return JSON.stringify(_stats);"
    "})()"
)


def parse_reply(out):
    for ln in out.splitlines():
        if "[agent.reply]" in ln and "msg=" in ln:
            return ln.split("msg=", 1)[1].strip()
    return None


def main():
    java = find_java(os.environ.get("MARROW_TEST_JDK", "17"))
    if not java: print("no jdk"); return 1
    extra = ["-Xint"] if os.environ.get("MARROW_DIAG_XINT") else []
    p = subprocess.Popen([java, "-Xmx256m"] + extra + ["-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        ln = p.stdout.readline()
        if ln.startswith("Target PID:"): pid = int(ln.split(":", 1)[1].strip()); break
    if not pid: p.kill(); print("no pid"); return 1

    subprocess.run([PROBE, "inject", str(pid), AGENT], capture_output=True, timeout=15)
    time.sleep(1.5)

    for js, label in [(SETUP, "setup"), (RUN, "run")]:
        r = subprocess.run([PROBE, "agent", str(pid), "eval", js],
                           capture_output=True, text=True, timeout=120)
        rep = parse_reply(r.stdout)
        if not rep: p.kill(); print(f"no reply for {label}: {r.stdout[:300]}"); return 1
        if label == "run":
            try:
                outer = json.loads(rep)
                d = json.loads(outer) if isinstance(outer, str) else outer
            except Exception as e:
                p.kill(); print(f"parse: {e}\n{rep}"); return 1
            print(json.dumps(d, indent=2))
        else:
            print(f"setup: {rep}")

    p.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
