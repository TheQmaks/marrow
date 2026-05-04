"""Demo: install a native counting hook on Target.tick(I)V.

We allocate a tiny x64 trampoline in the target process, point
Method::_from_interpreted_entry at it, and let Target keep running
normally — every tick now increments our counter before falling through
to the real body. Unlike the bytecode-replacement demo, the method's
behaviour is unchanged: this is a *pre-invocation hook*, not a rewrite.
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(_HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from vm_meta import VMMeta
from walker import ClassWalker
from method_walker import find_method
from hooks import install_counting_hook

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")


def find_java(v: str) -> str | None:
    hits = glob.glob(
        os.path.join(REPO_ROOT, "..", "jdks", f"temurin-{v}-jdk",
                     "**", "bin", "java.exe"),
        recursive=True)
    return hits[0] if hits else None


def launch(java: str) -> tuple[subprocess.Popen, int]:
    proc = subprocess.Popen(
        [java, "-cp", TARGET_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1)
    deadline = time.time() + 10.0
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.startswith("Target PID:"):
            return proc, int(line.split(":", 1)[1].strip())
    proc.kill()
    raise TimeoutError("no PID")


def run_one(version: str) -> None:
    java = find_java(version)
    if not java:
        print(f"[JDK {version}] java.exe missing"); return
    proc, pid = launch(java)
    try:
        time.sleep(1.2)
        vm = VMMeta.from_pid(pid)

        target_klass = next(
            (k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
        if not target_klass:
            print("  Target class missing"); return
        tick = find_method(vm, target_klass, "tick", "(I)V")
        if tick is None:
            print("  tick(I)V missing"); return

        print(f"[JDK {version}] pid={pid}")
        hook = install_counting_hook(vm, tick)
        print(f"  hook installed: trampoline @ {hook.trampoline_addr:#x}, "
              f"counter @ {hook.counter_addr:#x}")
        print(f"  original _from_interpreted_entry = {hook.original_interpreted_entry:#x}")

        # Let Target run 3 seconds. At one tick per ~500 ms we should see
        # the counter approach 6.
        samples = []
        for _ in range(6):
            time.sleep(0.5)
            samples.append(hook.read_count())
        print(f"  counter samples: {samples}")
        delta = samples[-1] - samples[0]
        print(f"  increments over ~2.5s: {delta}  (expect ~5)")

        hook.uninstall()
        print("  hook uninstalled.")
        vm.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> int:
    if not os.path.isfile(os.path.join(TARGET_CP, "Target.class")):
        print("Target.class missing"); return 2
    for v in ["8", "11", "17", "21", "25"]:
        print(f"=== JDK {v} ===")
        try:
            run_one(v)
        except Exception as e:
            import traceback
            print(f"  FAILED: {e}")
            traceback.print_exc()
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
