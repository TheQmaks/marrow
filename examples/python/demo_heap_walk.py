"""Demo: find every instance of a given class in a running JVM.

We scan the full writable address space, so the demo works under any GC
(G1 default, ParallelGC on JDK 8, ZGC, Shenandoah) — no GC-specific
heap-region navigation.

Query: all instances of java/lang/Thread. Expected: ~one per live
JavaThread (bare minimum), plus any Thread subclasses.
"""
from __future__ import annotations

import glob
import os
import struct
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(_HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from vm_meta import VMMeta, _ptr
from walker import ClassWalker
from oop_reader import OopDecoder
from heap_walker import find_instances_by_klass

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


def run_one(version: str, target_class: str = "Target") -> None:
    java = find_java(version)
    if not java:
        print(f"[JDK {version}] java.exe missing"); return
    proc, pid = launch(java)
    try:
        time.sleep(1.2)
        vm = VMMeta.from_pid(pid)
        decoder = OopDecoder(vm)

        klass = next(
            (k.address for k in ClassWalker(vm) if k.name == target_class), 0)
        if not klass:
            print(f"[JDK {version}] {target_class} not loaded"); return

        print(f"[JDK {version}] pid={pid}  searching for instances of "
              f"{target_class!r} (Klass @ {klass:#x})")
        t0 = time.time()
        hits = find_instances_by_klass(vm, decoder, klass, limit=50)
        elapsed = time.time() - t0
        print(f"  found {len(hits)} in {elapsed:.2f}s")
        for oop in hits[:10]:
            print(f"    oop @ {oop:#x}")
        vm.close()
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()


def main() -> int:
    if not os.path.isfile(os.path.join(TARGET_CP, "Target.class")):
        print("Target.class missing"); return 2
    for v in ["8", "21", "25"]:
        print(f"=== JDK {v} — Target ===")
        try:
            run_one(v, "Target")
        except Exception as e:
            print(f"  FAILED: {e}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
