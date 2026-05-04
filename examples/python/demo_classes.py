"""Demo: enumerate every loaded Klass in a target JVM with its name.

Launches Target.java under each installed JDK and prints counts + samples
produced by ClassWalker. Proves Symbol decoder + both class-enumeration
strategies (CLDG and SystemDictionary) work end-to-end.
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys
import time
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(_HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from vm_meta import VMMeta
from walker import ClassWalker

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")


def find_java(v: str) -> str | None:
    hits = glob.glob(
        os.path.join(REPO_ROOT, "..", "jdks", f"temurin-{v}-jdk",
                     "**", "bin", "java.exe"),
        recursive=True)
    return hits[0] if hits else None


def launch_and_get_pid(java: str, wait_ms: int = 2500) -> tuple[subprocess.Popen, int]:
    proc = subprocess.Popen(
        [java, "-cp", TARGET_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1)
    deadline = time.time() + 10.0
    pid = None
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.startswith("Target PID:"):
            pid = int(line.split(":", 1)[1].strip())
            break
        if not line:
            time.sleep(0.05)
    if pid is None:
        proc.kill()
        raise TimeoutError("no PID")
    time.sleep(wait_ms / 1000)  # let the JVM finish loading bootstrap classes
    return proc, pid


def dump_classes(version: str) -> None:
    java = find_java(version)
    if not java:
        print(f"[JDK {version}] java.exe missing"); return
    proc, pid = launch_and_get_pid(java)
    try:
        t0 = time.time()
        vm = VMMeta.from_pid(pid)
        walker = ClassWalker(vm)
        classes = walker.list()
        elapsed = time.time() - t0

        kinds = Counter(k.kind for k in classes)
        print(f"[JDK {version}] pid={pid} strategy={walker.strategy!r} "
              f"classes={len(classes)} in {elapsed:.2f}s  kinds={dict(kinds)}")

        names = sorted({k.name for k in classes if k.kind == "instance"})
        target_hits = [n for n in names if n == "Target"]
        java_lang = [n for n in names if n.startswith("java/lang/")][:8]
        print(f"    Target class visible: {bool(target_hits)}")
        print(f"    sample java/lang/* ({len(java_lang)}):")
        for n in java_lang:
            print(f"      {n}")

        # Print a handful of array klasses too — proves Symbol works for
        # the mangled '[Ljava/lang/Object;' style names.
        arrays = sorted({k.name for k in classes
                         if k.kind in ("obj_array", "type_array")})[:4]
        if arrays:
            print("    sample arrays:")
            for n in arrays:
                print(f"      {n}")

        vm.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> int:
    if not os.path.isfile(os.path.join(TARGET_CP, "Target.class")):
        print("Target.class missing — run target/build-and-run.sh first.")
        return 2
    for v in ["8", "11", "17", "21", "25"]:
        print(f"=== JDK {v} ===")
        try:
            dump_classes(v)
        except Exception as e:
            print(f"    FAILED: {e}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
