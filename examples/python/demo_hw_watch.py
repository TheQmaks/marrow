"""Demo: hardware-assisted field watcher via VEH + VirtualProtect.

Counts every hardware-enforced write to `Target.counter` from Target's
own main loop. Compared with the polling watcher (M6.a), this catches
*every* write — no sampling-interval misses, and it's driven by the CPU
rather than by our poll cadence.

Pipeline:
  1. Create a named shared-memory control block.
  2. Launch Target, attach via VMMeta, resolve &counter inside mirror.
  3. Inject watcher.dll via CreateRemoteThread(LoadLibraryA).
  4. Write &counter into the control block, then VirtualProtectEx the
     page to PAGE_READONLY.
  5. Target's `counter++` in main() -> AV -> VEH -> count, unprotect,
     set TF, continue. After the write single-steps -> VEH re-protects.
  6. Poll the counter from Python. Expected: one hit per tick
     (~500 ms), matching `counter++` frequency.
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

from vm_meta import VMMeta, _i32, _ptr
from walker import ClassWalker
from field_reader import find_field
from injector import (
    SharedControlBlock, inject_dll, protect_remote_page,
    PAGE_READWRITE, PAGE_READONLY,
)

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")
WATCHER_DLL = os.path.join(
    REPO_ROOT, "watcher", "build", "Release", "marrow_watcher.dll")


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


def mirror_of(vm: VMMeta, klass_ptr: int) -> int:
    r = vm.reader
    mf = vm.type("Klass").field("_java_mirror")
    raw = _ptr(r, klass_ptr + mf.offset)
    return _ptr(r, raw) if mf.type_string == "OopHandle" else raw


def run_one(version: str) -> None:
    java = find_java(version)
    if not java:
        print(f"[JDK {version}] java.exe missing"); return
    proc, pid = launch(java)
    ctl = SharedControlBlock()
    try:
        time.sleep(1.2)
        vm = VMMeta.from_pid(pid)
        tk = next((k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
        if not tk:
            print("  Target not loaded"); return
        mirror = mirror_of(vm, tk)
        counter_f = find_field(vm, tk, "counter")
        counter_addr = mirror + counter_f.offset
        print(f"[JDK {version}] pid={pid}  counter @ {counter_addr:#x}")

        # 1. inject DLL
        exit_code = inject_dll(pid, WATCHER_DLL)
        print(f"  injected watcher.dll (LoadLibrary returned hmodule={exit_code:#x})")
        deadline = time.time() + 3.0
        while time.time() < deadline and not ctl.is_installed():
            time.sleep(0.05)
        if not ctl.is_installed():
            print("  DLL did not signal installed — aborting"); return

        # 2. program the watcher and arm the page
        ctl.set_watched(counter_addr)
        before_count = _i32(vm.reader, counter_addr)
        old_prot = protect_remote_page(pid, counter_addr, readonly=True)
        print(f"  page {counter_addr & ~0xFFF:#x} now PAGE_READONLY "
              f"(was prot={old_prot:#x}, counter started at {before_count})")

        # 3. watch for ~2.5s: Target increments counter once per tick.
        samples = []
        for _ in range(5):
            time.sleep(0.5)
            samples.append(ctl.get_count())
        print(f"  VEH hit counter samples: {samples}")
        delta = samples[-1] - samples[0]
        print(f"  increments seen over ~2.5s: {delta}  (expect ~4-5)")
        print(f"  last fault at addr={ctl.get_last_fault_addr():#x} "
              f"rip={ctl.get_last_fault_rip():#x}")

        # 4. disarm so target can run normally if we outlive the sample window.
        protect_remote_page(pid, counter_addr, readonly=False)
        ctl.set_watched(0)
        vm.close()
    finally:
        ctl.close()
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()


def main() -> int:
    if not os.path.isfile(WATCHER_DLL):
        print(f"Watcher DLL missing at {WATCHER_DLL}. Build first.")
        return 2
    if not os.path.isfile(os.path.join(TARGET_CP, "Target.class")):
        print("Target.class missing"); return 2
    for v in ["21"]:  # one JDK is enough for a hardware-behaviour demo
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
