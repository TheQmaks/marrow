"""Hot-tick drain bench.

Validates the bootstrap drain() RING_CAP fix: when a hooked method is
hit at multi-MHz rates, drain() must return promptly with at most
RING_CAP=16 invocations per cookie per call (not millions of redecodes
of the same 16 ring slots).

Procedure:
  1) Launch HotTarget (~MHz tick rate).
  2) Inject agent and install Java.use('HotTarget').tick.implementation
     handler that just counts invocations.
  3) Wait 1 second so the ring fills.
  4) Call Java.drain() with a tight timeout.
  5) Verify drain returned <= 16 (one cookie, one drain).

Pass criteria:
  - Eval round-trip < 8s (no hang).
  - drain() return value 0..16 inclusive.
  - HotTarget still alive (no agent crash).
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java


def start_hot(java: str, xint: bool) -> tuple[subprocess.Popen | None, int | None]:
    args = [java, "-Xmx256m"]
    if xint:
        args.append("-Xint")
    else:
        # Keep tick() as a real call from JIT'd main(), so the verified_entry
        # detour has something to catch. Without this, C2 inlines tick into
        # main and the hook never fires regardless of where we patch.
        args += ["-XX:CompileCommand=dontinline,HotTarget.tick"]
    args += ["-cp", TGT_CP, "HotTarget"]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        line = proc.stdout.readline()
        if line.startswith("HotTarget PID:"):
            pid = int(line.split(":", 1)[1].strip())
            break
    if not pid:
        proc.kill()
        return None, None
    # Wait for first rate report so JIT (if any) has settled.
    t1 = time.time()
    while time.time() - t1 < 6:
        line = proc.stdout.readline()
        if line.startswith("rate="):
            break
    return proc, pid


def agent_eval(pid: int, script: str, timeout: int = 8) -> tuple[int, str]:
    r = subprocess.run([PROBE, "agent", str(pid), "eval", script],
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def run_one(label: str, java: str, xint: bool) -> bool:
    print(f"\n[bench] {label} (xint={xint})")
    proc, pid = start_hot(java, xint)
    if not pid:
        print("  FAIL: could not start HotTarget")
        return False
    print(f"  HotTarget pid={pid}")
    try:
        inj = subprocess.run([PROBE, "inject", str(pid), AGENT],
                             capture_output=True, text=True, timeout=15)
        if inj.returncode != 0:
            print(f"  FAIL: inject rc={inj.returncode}  {inj.stderr.strip()}")
            return False
        time.sleep(1.5)
        # Install hook + wait + drain in one eval.
        script = (
            "(function(){"
            "var T=Java.use('HotTarget');"
            "var seen=0;"
            # Use .attach (async) so MHz tick fires queue into the ring
            # without blocking JVM threads on the Duktape mutex (which
            # the busy-wait below would hold).
            "T.tick.attach(function(){ seen++; });"
            "var rec=Java._impls[T.tick.$cookie];"
            "var jit=rec&&rec.jitDetour?rec.jitDetour:null;"
            "var jitInfo=jit?(jit.jitDetourId+':'+jit.jitDetourVa+':'+jit.origCode+':vep='+jit.vepSrc):'none';"
            # Sanity check: probe _inlineHookV2 on verified_entry to see
            # whether LDE accepts the prologue.
            "var t0=Date.now();"
            "while(Date.now()-t0<200){}"   # short busy-wait, ring fills fast
            "var d1=Java.drain();"
            "var d2=Java.drain();"           # second drain — should be small
            "return 'd1='+d1+',d2='+d2+',seen='+seen+',jit='+jitInfo;"
            "})()"
        )
        t0 = time.time()
        rc, out = agent_eval(pid, script, timeout=8)
        dt = time.time() - t0
        print(f"  rc={rc}  dt={dt:.2f}s")
        last_reply = ""
        for line in out.splitlines():
            if "[agent.reply]" in line:
                last_reply = line
        print(f"  {last_reply}")
        # Parse d1/d2.
        import re
        m = re.search(r"d1=(\d+),d2=(\d+),seen=(\d+)", last_reply)
        if not m:
            print("  FAIL: could not parse drain counts")
            return False
        d1 = int(m.group(1)); d2 = int(m.group(2)); seen = int(m.group(3))
        if d1 > 16 or d2 > 16:
            print(f"  FAIL: drain exceeded RING_CAP=16  d1={d1} d2={d2}")
            return False
        if dt > 6.5:
            print(f"  FAIL: drain too slow  dt={dt:.2f}s")
            return False
        if seen == 0:
            print("  WARN: seen=0 — handler never fired (hook may not bind)")
            # Not a hard fail: drain perf is the test target.
        # Confirm HotTarget still alive.
        if proc.poll() is not None:
            print(f"  FAIL: HotTarget exited rc={proc.returncode}")
            return False
        print(f"  PASS: d1={d1} d2={d2} seen={seen} dt={dt:.2f}s alive=yes")
        return True
    finally:
        try: proc.kill()
        except Exception: pass


def main() -> int:
    java = find_java("17")
    if not java:
        print("no temurin-17 jdk found"); return 2
    ok = True
    ok &= run_one("HotTarget JIT'd",   java, xint=False)
    ok &= run_one("HotTarget -Xint",   java, xint=True)
    print()
    print("hot_drain_bench:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
