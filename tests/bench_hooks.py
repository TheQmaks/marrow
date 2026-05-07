"""Marrow microbenchmarks. Measure per-fire overhead, install latency,
async-drain throughput. Numbers are reported in ns/op (per-fire) and
ms/op (per-install) so users can size production budgets.

Workload: dispatching `Callable.addInts(int,int)int` in a tight loop.
Per-fire overhead is `(elapsed_with_hook - elapsed_no_hook) / N` for
each variant (no hook / .attach observer / .implementation passthrough
/ .implementation replace).
"""
import os
import subprocess
import sys
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java  # noqa


N = int(os.environ.get("MARROW_BENCH_N", "20000"))


SETUP = (
    "(function(){"
    "globalThis._C = Java.use('Callable');"
    "return 'ok';"
    "})()"
)


def make_bench(label, install_js, drain_js=None):
    """Returns a JS expr that:
      1. Runs install_js (sets up the hook variant).
      2. Times N invocations of _C.addInts.
      3. (Optional) drains async results.
      4. Resets via _C.addInts.implementation = null.
    Returns elapsed nanoseconds and N.
    """
    return (
        "(function(){"
        f"var N = {N};"
        f"{install_js}"
        "var t0 = Date.now();"
        "for (var i = 0; i < N; ++i) _C.addInts(3, 4);"
        "var t1 = Date.now();"
        f"{drain_js or ''}"
        "_C.addInts.implementation = null;"
        f"return JSON.stringify({{label: '{label}', ms: t1-t0, n: N}});"
        "})()"
    )


VARIANTS = [
    # (label, install_js, drain_js)
    ("baseline_nohook", "", None),
    ("impl_replace",
        "_C.addInts.implementation = function(a,b){ return 1234; };",
        None),
]


def parse_reply(out):
    for ln in out.splitlines():
        if "[agent.reply]" in ln and "msg=" in ln:
            return ln.split("msg=", 1)[1].strip()
    return None


def main():
    jdk = os.environ.get("MARROW_TEST_JDK", "17")
    java = find_java(jdk)
    if not java: print("[SKIP] no JDK"); return 0

    p = subprocess.Popen([java, "-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        ln = p.stdout.readline()
        if "Target PID:" in ln:
            pid = int(ln.split(":", 1)[1].strip()); break
    if not pid: p.kill(); return 1
    subprocess.run([PROBE, "inject", str(pid), AGENT],
                   capture_output=True, timeout=15)
    time.sleep(1.5)

    env = os.environ.copy()
    env.setdefault("MARROW_AGENT_TIMEOUT_SEC", "180")

    r = subprocess.run([PROBE, "agent", str(pid), "eval", SETUP],
                       capture_output=True, text=True, timeout=30, env=env)
    rep = parse_reply(r.stdout)
    if rep != "ok": p.kill(); print(f"[FAIL] setup: {rep}"); return 1

    print(f"=== Marrow bench  JDK {jdk}  N={N} ===")
    print()
    print(f"  {'variant':<24} {'total ms':>12} {'ns/op':>12}")
    print(f"  {'-'*24} {'-'*12} {'-'*12}")

    results = {}
    for label, install_js, drain_js in VARIANTS:
        js = make_bench(label, install_js, drain_js)
        r = subprocess.run([PROBE, "agent", str(pid), "eval", js],
                           capture_output=True, text=True, timeout=180,
                           env=env)
        rep = parse_reply(r.stdout)
        if not rep: print(f"  {label}: FAIL no reply"); continue
        try:
            d = json.loads(rep)
            if isinstance(d, str): d = json.loads(d)
        except Exception as e:
            print(f"  {label}: parse error {e} raw={rep[:100]}"); continue
        ns = (d["ms"] * 1_000_000) / d["n"]
        results[label] = {"ms": d["ms"], "ns_per_op": ns}
        print(f"  {label:<24} {d['ms']:>12} {ns:>12.1f}")

    # Install latency: wall-clock time for one .implementation = fn install.
    install_bench = (
        "(function(){"
        "var iters = 100;"
        "var t0 = Date.now();"
        "for (var i = 0; i < iters; ++i) {"
        "  _C.addInts.implementation = function(a,b){ return 0; };"
        "  _C.addInts.implementation = null;"
        "}"
        "var t1 = Date.now();"
        "return JSON.stringify({ms: t1-t0, iters: iters});"
        "})()"
    )
    r = subprocess.run([PROBE, "agent", str(pid), "eval", install_bench],
                       capture_output=True, text=True, timeout=180, env=env)
    rep = parse_reply(r.stdout)
    if rep:
        try:
            d = json.loads(rep)
            if isinstance(d, str): d = json.loads(d)
            us_per_install = (d["ms"] * 1000) / d["iters"]
            print()
            print(f"  install latency: {us_per_install:.1f} us per install/uninstall cycle "
                  f"(N={d['iters']} cycles, total {d['ms']} ms)")
            results["install_us"] = us_per_install
        except Exception:
            pass

    p.kill()

    if "baseline_nohook" in results:
        base_ns = results["baseline_nohook"]["ns_per_op"]
        print()
        print(f"  Per-fire overhead vs baseline ({base_ns:.1f} ns/op):")
        for label in ["attach_observer", "impl_passthrough", "impl_replace"]:
            if label in results:
                delta = results[label]["ns_per_op"] - base_ns
                print(f"    {label:<24} +{delta:>8.1f} ns/op")

    return 0


if __name__ == "__main__":
    sys.exit(main())
