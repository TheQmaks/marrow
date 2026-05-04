"""Microbenchmark: cost of the v0.1.1 L-return auto-cast vs raw oop hex.

Measures average time per static method invocation that returns an L type.
Compares:
  baseline_primitive: Callable.addInts(int,int)->int    no auto-cast involved
  with_auto_cast:    Integer.toString(int)->String      auto-cast fires every call

Same loop count and method-handle resolve cost, so the delta is the proxy
construction overhead (defineProperty per field + method binding)."""
import os
import subprocess
import sys
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java  # noqa: E402


JS = (
    "(function(){"
    "var N = 5000;"
    "var I = Java.use('java.lang.Integer');"
    "var C = Java.use('Callable');"
    # Warm: resolve + cache method handles, fields, etc.
    "C.addInts(1, 2);"
    "I.toString.overload('int').apply(null, [1]);"
    "var t0 = new Date().getTime();"
    "for (var i = 0; i < N; ++i) C.addInts(i, i);"
    "var t1 = new Date().getTime();"
    "for (var i = 0; i < N; ++i) I.toString.overload('int').apply(null, [i]);"
    "var t2 = new Date().getTime();"
    "return JSON.stringify({"
    "    N: N,"
    "    primitive_ms_total: t1 - t0,"
    "    primitive_us_per_call: ((t1 - t0) * 1000) / N,"
    "    autocast_ms_total: t2 - t1,"
    "    autocast_us_per_call: ((t2 - t1) * 1000) / N,"
    "    overhead_us: (((t2 - t1) - (t1 - t0)) * 1000) / N"
    "});"
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
                       capture_output=True, text=True, timeout=120)
    raw = parse_reply(r.stdout)
    if raw:
        try:
            outer = json.loads(raw)
            d = json.loads(outer) if isinstance(outer, str) else outer
            print("Benchmark:")
            print(json.dumps(d, indent=2))
            print()
            ratio = d["autocast_us_per_call"] / max(d["primitive_us_per_call"], 0.001)
            print(f"auto-cast / primitive ratio: {ratio:.2f}x")
            print(f"per-call cost of auto-cast wrapping: {d['overhead_us']:.1f} us")
            tput_au = 1_000_000 / d["autocast_us_per_call"]
            tput_pr = 1_000_000 / d["primitive_us_per_call"]
            print(f"throughput primitive : {tput_pr:>8.0f} calls/sec")
            print(f"throughput auto-cast : {tput_au:>8.0f} calls/sec")
        except Exception as e:
            print(f"[FAIL] parse: {e}\n{raw}")
    else:
        print("[FAIL] no reply"); print(r.stdout)
    p.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
