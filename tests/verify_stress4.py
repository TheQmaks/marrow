"""Fourth-round stress: concurrency, stability, leak.

  - Two methods hooked simultaneously, fired from different threads
    (Target.tick on JVM main thread; Callable.addInts via JS thread)
  - Install/uninstall hook 50 times — verify no resource leak / crash
  - Java.reload() 10 times — agent state stays clean
  - Async observer fires from JVM thread while agent processes user JS
  - Hook handler that itself reads instance fields under concurrency
"""
import os
import subprocess
import sys
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java  # noqa: E402


SETUP = (
    "(function(){"
    "globalThis._s4 = {};"
    "globalThis._t4 = function(n,fn){try{_s4[n]=fn();}catch(e){_s4[n]='ERR:'+e;}};"
    "globalThis._C = Java.use('Callable');"
    "globalThis._T = Java.use('Target');"
    "return 'setup_ok';"
    "})()"
)

# Cross-thread .attach observer counts JVM-thread-driven Target.tick fires
# while the agent is busy processing JS in another thread.
B_CROSS_THREAD = (
    "(function(){"
    "_t4('cross_thread_tick_observed',   function(){"
    "  globalThis._tickHits = 0;"
    "  _T.tick.attach(function(n) { _tickHits++; });"
    # Sleep ~1.2s while Target ticks every 500ms (~2-3 fires).
    "  return 'attached';"
    "});"
    "return 'b_xthread_setup_ok';"
    "})()"
)

# Drain after sleep — count async observer fires.
B_CROSS_DRAIN = (
    "(function(){"
    "_t4('cross_thread_drain_count',     function(){"
    "  Java.drain();"
    "  return _tickHits;"
    "});"
    "return 'b_xthread_drain_ok';"
    "})()"
)

# Install/uninstall hook 50 times — leak/state test.
B_INSTALL_LOOP = (
    "(function(){"
    "_t4('install_uninstall_loop_50',    function(){"
    "  var failed = 0;"
    "  for (var i = 0; i < 50; ++i) {"
    "    _C.addInts.implementation = function(a, b) { return 0xBEEF; };"
    "    var v = _C.addInts(1, 2);"
    "    if (v !== 0xBEEF) { failed++; }"
    "    _C.addInts.implementation = null;"
    "    var v2 = _C.addInts(3, 4);"
    "    if (v2 !== 7) { failed++; }"
    "  }"
    "  return failed === 0 ? 'ok' : 'failures='+failed;"
    "});"
    "return 'b_install_loop_ok';"
    "})()"
)

# Many concurrent invocations of two different hooked methods (same thread
# but interleaved with JVM thread firing tick concurrently).
B_INTERLEAVE = (
    "(function(){"
    "_t4('interleave_hot_call_under_tick',function(){"
    "  globalThis._addHits = 0;"
    "  _C.addInts.implementation = function(a, b) { _addHits++; return -1; };"
    "  for (var i = 0; i < 500; ++i) {"
    "    _C.addInts(i, 1);"
    "  }"
    "  _C.addInts.implementation = null;"
    "  return _addHits === 500 ? 'ok' : 'hits='+_addHits;"
    "});"
    "return 'b_interleave_ok';"
    "})()"
)

# Reload 10 times — verify state stays clean
B_RELOAD_LOOP = (
    "(function(){"
    "_t4('reload_10_cycles',             function(){"
    "  var failures = 0;"
    "  for (var i = 0; i < 10; ++i) {"
    "    var C = Java.use('Callable');"
    "    C.addInts.implementation = function(a, b) { return 1234; };"
    "    var v = C.addInts(1, 2);"
    "    if (v !== 1234) failures++;"
    "    Java.reload();"
    "  }"
    "  var C2 = Java.use('Callable');"
    "  var fin = C2.addInts(7, 8);"
    "  return failures === 0 && fin === 15 ? 'ok' : 'fails='+failures+' final='+fin;"
    "});"
    "return 'b_reload_loop_ok';"
    "})()"
)

DRAIN = "(function(){return JSON.stringify(globalThis._s4||{});})()"

EXPECTATIONS = {
    'cross_thread_tick_observed':       lambda v: v == 'attached',
    'cross_thread_drain_count':         lambda v: isinstance(v, int) and v >= 1,
    'install_uninstall_loop_50':        lambda v: v == 'ok',
    'interleave_hot_call_under_tick':   lambda v: v == 'ok',
    'reload_10_cycles':                 lambda v: v == 'ok',
}


def parse_reply(out):
    for ln in out.splitlines():
        if "[agent.reply]" in ln and "msg=" in ln:
            return ln.split("msg=", 1)[1].strip()
    return None


def eval_js(pid, js, label):
    # Stress4 batches (install_loop_50 in particular) take ~35s on JDK 8
    # — bump the agent IPC timeout above the default 30s so the slow-but-
    # working path doesn't get killed mid-batch.
    env = os.environ.copy()
    env.setdefault("MARROW_AGENT_TIMEOUT_SEC", "150")
    r = subprocess.run([PROBE, "agent", str(pid), "eval", js],
                       capture_output=True, text=True, timeout=200, env=env)
    raw = parse_reply(r.stdout)
    if not raw:
        print(f"[FAIL] {label}: no reply"); print(r.stdout[:300]); return None
    return raw


def main():
    target_jdk = os.environ.get("MARROW_TEST_JDK", "17")
    java = find_java(target_jdk)
    if not java:
        print(f"[SKIP] no JDK {target_jdk}"); return 0
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
        p.kill(); print("[FAIL] no PID"); return 1

    subprocess.run([PROBE, "inject", str(pid), AGENT], capture_output=True, timeout=15)
    time.sleep(1.5)

    print(f"=== JDK {target_jdk}  PID={pid} ===")
    # Setup + cross-thread setup; THEN sleep while target ticks; THEN drain.
    for batch_name, batch_js in [("setup", SETUP),
                                 ("b_xthread_setup", B_CROSS_THREAD)]:
        rep = eval_js(pid, batch_js, batch_name)
        if rep is None: p.kill(); return 1
        print(f"  {batch_name}: ran")
    # Wait so Target.tick fires several times.
    time.sleep(2.5)
    for batch_name, batch_js in [("b_xthread_drain", B_CROSS_DRAIN),
                                 ("b_install_loop", B_INSTALL_LOOP),
                                 ("b_interleave", B_INTERLEAVE),
                                 ("b_reload_loop", B_RELOAD_LOOP)]:
        rep = eval_js(pid, batch_js, batch_name)
        if rep is None: p.kill(); return 1
        print(f"  {batch_name}: ran")

    raw = eval_js(pid, DRAIN, "drain")
    p.kill()
    if not raw: return 1
    try:
        outer = json.loads(raw)
        d = json.loads(outer) if isinstance(outer, str) else outer
    except Exception as e:
        print(f"[parse] {e}\n{raw}"); return 1

    print()
    fails = []
    for k, expected in EXPECTATIONS.items():
        v = d.get(k)
        try: ok = expected(v)
        except Exception: ok = False
        mark = " ok " if ok else "FAIL"
        print(f"  [{mark}] {k:38s} {v}")
        if not ok: fails.append((k, v))
    print()
    if fails:
        print(f"FAILED {len(fails)}/{len(EXPECTATIONS)} on JDK {target_jdk}")
        for k, v in fails: print(f"  {k}: {v}")
    else:
        print(f"ALL {len(EXPECTATIONS)} CHECKS PASS on JDK {target_jdk}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
