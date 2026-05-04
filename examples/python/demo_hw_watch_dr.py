"""Demo: byte-level hardware watchpoint via CPU DR0-DR3.

The page-protect demo (demo_hw_watch.py) reacted to ANY write on the 4
KiB page — `counter` shares the page with `lastMessage`, so each tick
fired the VEH twice. Here we install a DR0 write-only watchpoint on
exactly the 4 bytes of `Target.counter`. Other writes on the page don't
fire at CPU level; only `counter++` reaches our VEH.

The watcher DLL's VEH distinguishes the two paths by inspecting DR6's
low bits (which watchpoint tripped) and bumps `hw_write_count`.
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
from field_reader import find_field
from injector import (
    SharedControlBlock, inject_dll,
    set_hw_watchpoint, clear_hw_watchpoint,
)

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")
WATCHER_DLL = os.path.join(
    REPO_ROOT, "watcher", "build", "Release", "marrow_watcher.dll")


# ControlBlock layout mirrors watcher.cpp after our extension:
#   0   watched_addr      (u64)
#   8   write_count       (u64)  — page-protect hits
#  16   last_fault_rip    (u64)
#  24   last_fault_addr   (u64)
#  32   installed         (i32)
#  36   _pad              (i32)
#  40   hw_write_count    (u64)  — DR-register hits
#  48   last_hw_rip       (u64)
_HW_COUNT_OFFSET = 40
_HW_RIP_OFFSET = 48


def _hw_count(ctl: SharedControlBlock) -> int:
    raw = bytes(ctl._mm[:])
    return struct.unpack_from("<Q", raw, _HW_COUNT_OFFSET)[0]


def _hw_rip(ctl: SharedControlBlock) -> int:
    raw = bytes(ctl._mm[:])
    return struct.unpack_from("<Q", raw, _HW_RIP_OFFSET)[0]


def find_java(v: str) -> str:
    return glob.glob(
        os.path.join(REPO_ROOT, "..", "jdks", f"temurin-{v}-jdk",
                     "**", "bin", "java.exe"),
        recursive=True)[0]


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


def run_one(version: str = "21") -> None:
    java = find_java(version)
    proc, pid = launch(java)
    ctl = SharedControlBlock()
    armed = 0
    try:
        time.sleep(1.2)
        vm = VMMeta.from_pid(pid)
        tk = next((k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
        mirror = mirror_of(vm, tk)
        counter_addr = mirror + find_field(vm, tk, "counter").offset
        print(f"[JDK {version}] pid={pid}  counter @ {counter_addr:#x}  "
              f"(page {counter_addr & ~0xFFF:#x})")

        exit_code = inject_dll(pid, WATCHER_DLL)
        deadline = time.time() + 3.0
        while time.time() < deadline and not ctl.is_installed():
            time.sleep(0.05)
        if not ctl.is_installed():
            print("  DLL failed to install VEH"); return
        print(f"  watcher.dll loaded (hmodule={exit_code:#x})")

        armed = set_hw_watchpoint(pid, counter_addr, length=4,
                                  slot=0, write_only=True)
        print(f"  DR0 armed on {armed} threads: 4-byte write-only watch")

        hw = []
        for _ in range(6):
            time.sleep(0.5)
            hw.append(_hw_count(ctl))
        print(f"  hw DR0 hit samples: {hw}")
        delta = hw[-1] - hw[0]
        print(f"  hits over ~3s: {delta}  (expect ~5-6; one per counter++)")
        print(f"  last hw rip: {_hw_rip(ctl):#x}")
    finally:
        if armed:
            cleared = clear_hw_watchpoint(pid, slot=0)
            print(f"  DR0 cleared on {cleared} threads")
        ctl.close()
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()


def main() -> int:
    if not os.path.isfile(WATCHER_DLL):
        print("watcher DLL missing"); return 2
    run_one("21")
    return 0


if __name__ == "__main__":
    sys.exit(main())
