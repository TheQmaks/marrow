"""Demo: clone Target's ConstantPool into our page, redirect _constants,
verify target keeps running.

If this succeeds, we've proven HotSpot doesn't require `_constants` to
live in real metaspace — meaning we can extend CPs with new entries
(methodref / Utf8 / NameAndType) for injecting `invokestatic` of any
existing method into patched bytecode.
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

from vm_meta import VMMeta, _ptr
from walker import ClassWalker
from metaspace import clone_constant_pool, restore_constant_pool

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
        tk = next((k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
        if not tk:
            print("  Target not loaded"); return

        print(f"[JDK {version}] pid={pid}  klass={tk:#x}")
        clone = clone_constant_pool(vm, tk)
        print(f"  original cp @ {clone.orig_cp:#x}")
        print(f"  cloned cp  @ {clone.new_cp:#x}  (size {clone.size} B, "
              f"page {clone.page_size} B)")

        # Let target run for ~5 ticks. If it survives and keeps producing
        # tick= lines, HotSpot followed our redirected _constants without
        # complaint. Any verifier that checks metaspace range would crash.
        deadline = time.time() + 12.0
        ticks = []
        while time.time() < deadline and len(ticks) < 2:
            line = proc.stdout.readline()
            if line.startswith("tick="):
                ticks.append(line.strip())
            if not line:
                time.sleep(0.05)
        print(f"  tick lines captured: {len(ticks)}")
        for t in ticks:
            print(f"    {t}")

        restore_constant_pool(vm, clone)
        print("  original cp restored and clone freed")
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()


def main() -> int:
    for v in ["8", "11", "17", "21", "25"]:
        print(f"=== JDK {v} ===")
        try:
            run_one(v)
        except Exception as e:
            print(f"  FAILED: {e}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
