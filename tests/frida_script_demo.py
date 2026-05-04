"""Driver: launch Target, inject agent, eval the Frida-style script,
let it observe a few real ticks, then drain + report."""
import os
import subprocess
import time
import json
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java


def parse_reply(out):
    for L in out.splitlines():
        if "[agent.reply]" in L and "msg=" in L:
            return L.split("msg=", 1)[1]
    return None


def main():
    java = find_java("17")
    if not java: print("[SKIP] no JDK 17 installed"); return
    p = subprocess.Popen([java, "-Xmx256m", "-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        line = p.stdout.readline()
        if line.startswith("Target PID:"):
            pid = int(line.split(":", 1)[1].strip()); break
    print(f"Target launched pid={pid}, ticks every 500ms")

    subprocess.run([PROBE, "inject", str(pid), AGENT],
                   capture_output=True, timeout=15)
    time.sleep(1.5)

    # Load the script source.
    script_path = os.path.join(os.path.dirname(__file__), "frida_script_demo.js")
    with open(script_path, "r", encoding="utf-8") as f:
        script = f.read()

    # Eval the whole script (defines Java.perform call site + pollDrain fn).
    print()
    print("=" * 72)
    print("evaluating frida_script_demo.js")
    print("=" * 72)
    r = subprocess.run([PROBE, "agent", str(pid), "eval", script],
                       capture_output=True, text=True, timeout=15)
    # Print agent.log lines from script's console.log calls.
    for L in r.stdout.splitlines():
        if "[agent.log]" in L:
            msg = L.split("[agent.log]", 1)[1].strip()
            print("  " + msg)

    # Let the running Target tick a few times so observers fire.
    print()
    print("(letting Target run 3 seconds so .attach observers see live ticks...)")
    time.sleep(3)

    # Drain + collect results.
    drain = subprocess.run(
        [PROBE, "agent", str(pid), "eval", "pollDrain()"],
        capture_output=True, text=True, timeout=10)
    for L in drain.stdout.splitlines():
        if "[agent.log]" in L:
            msg = L.split("[agent.log]", 1)[1].strip()
            print("  " + msg)
    payload = parse_reply(drain.stdout)
    if payload:
        try: data = json.loads(json.loads(payload))  # JSON-stringified JSON
        except Exception: data = json.loads(payload)
        print()
        print("=" * 72)
        print("OBSERVED RESULTS")
        print("=" * 72)
        print(f"  tickCount observed by .attach    = {data['tickCount']}")
        print(f"  addInts(3,4) hijacked            = {data['addInts_3_4']}  (expect 0x3ef = 1007)")
        print(f"  alsoNever() hijacked             = {data['alsoNever']}    (expect 0x2a = 42)")
        print(f"  neverCalled() unhooked           = {data['neverCalled']} (expect 0xcafebabe)")

    p.kill()


if __name__ == "__main__":
    main()
