"""Demo: read threads + class names from a Target running under ZGC.

Covers the decoder-integration path: under ZGC, reference fields (including
OopHandle slots) hold "coloured" pointers whose raw value isn't a usable
heap address. We detect ZGC via ZGlobalsForVMStructs, uncolour each loaded
reference, and then follow through to the thread's Class/name just like on
any other GC.
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
from walker import ClassWalker, ThreadWalker, read_symbol
from oop_reader import OopDecoder
from zgc import ZGCDecoder

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")


def find_java(v: str) -> str:
    return glob.glob(
        os.path.join(REPO_ROOT, "..", "jdks", f"temurin-{v}-jdk",
                     "**", "bin", "java.exe"),
        recursive=True)[0]


# (title, version, extra_args)
CONFIGS = [
    ("JDK 17 classic ZGC",
     "17", ["-XX:+UseZGC", "-XX:+UnlockExperimentalVMOptions", "-Xmx64m"]),
    ("JDK 21 generational ZGC",
     "21", ["-XX:+UseZGC", "-XX:+ZGenerational",
            "-XX:+UnlockExperimentalVMOptions", "-Xmx64m"]),
    ("JDK 25 ZGC (generational default)",
     "25", ["-XX:+UseZGC", "-Xmx64m"]),
]


def launch(java: str, extra: list[str]) -> tuple[subprocess.Popen, int]:
    proc = subprocess.Popen(
        [java] + extra + ["-cp", TARGET_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, errors="replace")
    deadline = time.time() + 10.0
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.startswith("Target PID:"):
            return proc, int(line.split(":", 1)[1].strip())
    proc.kill()
    raise TimeoutError("no PID")


def run_one(title: str, version: str, extra: list[str]) -> None:
    java = find_java(version)
    proc, pid = launch(java, extra)
    try:
        time.sleep(1.2)
        vm = VMMeta.from_pid(pid)
        zgc = ZGCDecoder.detect(vm)
        decoder = OopDecoder(vm)
        print(f"=== {title} ===")
        print(f"  pid={pid}  {zgc!r}")
        print(f"  OopDecoder {decoder!r}")
        if not zgc.is_active:
            print("  (ZGC not active or legacy-mode masks empty — skipping)")
            return

        # Thread walker still works (it reads only VM metadata, no oops).
        walker = ThreadWalker(vm)
        threads = walker.list()
        print(f"  {len(threads)} threads via {walker.strategy}")

        # For each thread: pull _threadObj as raw 8-byte pointer, then
        # uncolour via ZGC, then read Klass::_name. OopHandle-on-ZGC is
        # a direct oop slot (no compressed oops under ZGC).
        jt = vm.type("JavaThread")
        thr_f = jt.field("_threadObj")
        assert thr_f.type_string == "OopHandle"  # every ZGC-capable JDK 17+

        for t in threads[:6]:
            handle = t.thread_obj  # value of OopHandle._obj (slot pointer)
            raw = _ptr(vm.reader, handle) if handle else 0
            uncolored = zgc.decode(raw)
            name_str = "?"
            if uncolored:
                # Klass pointer in oop header — ZGC still uses compressed
                # class pointers by default, so this is a 4-byte narrow klass.
                klass_slot = uncolored + 8
                try:
                    klass = decoder.klass_of(uncolored)
                    if klass:
                        name_sym = _ptr(vm.reader, klass +
                                        vm.type("Klass").field("_name").offset)
                        name_str = read_symbol(vm, vm.reader, name_sym) or "?"
                except Exception as e:
                    name_str = f"<klass read failed: {e}>"
            print(f"    tid={t.os_tid:>6d}  {t.state_name:<22}  "
                  f"raw={raw:#018x}  uncolored={uncolored:#x}  class={name_str}")
        vm.close()
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()


def main() -> int:
    if not os.path.isfile(os.path.join(TARGET_CP, "Target.class")):
        print("Target.class missing."); return 2
    for title, version, extra in CONFIGS:
        try:
            run_one(title, version, extra)
        except Exception as e:
            import traceback
            print(f"=== {title} FAILED ===")
            traceback.print_exc()
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
