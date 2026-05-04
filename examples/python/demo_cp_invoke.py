"""End-to-end: extend CP with a new Methodref that duplicates an existing
Thread.sleep entry, patch Target.tick() bytecode to invokestatic it,
verify target calls it (tick slows down visibly).

Demonstrates the full arbitrary-invoke chain:
    1. Scan existing CP for java/lang/Thread.sleep(J)V Methodref.
    2. Extend CP by 1 slot; duplicate that Methodref at the new index.
    3. Rewrite tick()'s bytecode to `lconst_1; i2l(dup)` ... ok, sleep
       takes a long; we push a long constant, invokestatic sleep, return.
    4. Observe tick() now sleeps instead of doing its normal work —
       lastMessage stops updating as tick() never reaches those writes.
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
from method_walker import find_method, rewrite_method_body
from metaspace import (
    extend_cp, restore_constant_pool,
    set_cp_tag, set_cp_slot_methodref,
    JVM_CONSTANT_Methodref,
)
from cp_scanner import find_methodref

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")


def find_java(v):
    hits = glob.glob(
        os.path.join(REPO_ROOT, "..", "jdks", f"temurin-{v}-jdk",
                     "**", "bin", "java.exe"),
        recursive=True)
    return hits[0] if hits else None


def launch(java):
    proc = subprocess.Popen(
        [java, "-cp", TARGET_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1)
    deadline = time.time() + 10.0
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.startswith("Target PID:"):
            return proc, int(line.split(":", 1)[1].strip())
    proc.kill(); raise TimeoutError("no PID")


def run_one(version: str = "21") -> None:
    java = find_java(version)
    if not java:
        print(f"[JDK {version}] java.exe missing"); return
    proc, pid = launch(java)
    try:
        time.sleep(1.2)
        vm = VMMeta.from_pid(pid)
        tk = next((k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
        if not tk:
            print("Target not loaded"); return
        cp_ptr = _ptr(vm.reader,
                      tk + vm.type("InstanceKlass").field("_constants").offset)
        # Match on method+signature only — resolved Class slots vary in
        # layout and don't always decode cleanly via our scanner. Given
        # Target calls Thread.sleep(500) from main(), any Methodref with
        # name=sleep, sig=(J)V is going to be Thread.sleep.
        sleep_ref = find_methodref(vm, cp_ptr, "", "sleep", "(J)V")
        if not sleep_ref:
            print("  Target.CP has no Thread.sleep(J)V Methodref"); return
        print(f"[JDK {version}] pid={pid}")
        print(f"  Methodref Thread.sleep(J)V @ CP index {sleep_ref.index}")

        # HotSpot on x86 byte-swaps invokeX u2 operands at class-load
        # time for native-endian reads at runtime. JVM class-file format
        # is big-endian, but post-class-load bytecode holds u2 operands
        # in native (little-endian) order. We're writing fresh bytecode
        # at runtime — it must match native layout, so write u2 as LE.
        from cpcache import cache_index_for_cp
        cache_idx = cache_index_for_cp(vm, cp_ptr, sleep_ref.index,
                                        bytecode=0xB8)
        if cache_idx is None:
            print("  no existing CPCache entry for sleep"); return
        print(f"  Using existing CPCache entry {cache_idx} (sleep's)")

        tick = find_method(vm, tk, "tick", "(I)V")
        assert tick is not None
        bc = bytes([0x0A,                                  # lconst_1
                    0xB8, cache_idx & 0xFF, (cache_idx >> 8) & 0xFF,
                    0xB1])                                 # return
        print(f"  patching tick() bytecode: {bc.hex()}  "
              f"(invokestatic LE[{cache_idx}])")
        rewrite_method_body(vm, tick, bc)

        # Observe: if tick now sleeps 1ms, its body (which updates
        # lastMessage/tag/ticks) no longer runs -> lastMessage stays put.
        # Capture two tick= log lines (target prints every 20 counter++s).
        deadline = time.time() + 25.0
        ticks = []
        all_lines = []
        while time.time() < deadline and len(ticks) < 2:
            line = proc.stdout.readline()
            if not line:
                # proc may have died
                if proc.poll() is not None:
                    print(f"  target died, exit={proc.returncode}")
                    break
                time.sleep(0.05); continue
            all_lines.append(line.rstrip())
            if line.startswith("tick="):
                ticks.append(line.strip())
        print(f"  target tick lines: {len(ticks)} (of {len(all_lines)} total lines)")
        for ln in all_lines[-8:]:
            print(f"    stdout: {ln[:120]}")
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()


def main():
    for v in ["8", "11", "17", "21", "25"]:
        print(f"=== JDK {v} ===")
        try: run_one(v)
        except Exception as e:
            print(f"  FAILED: {e}")
            import traceback; traceback.print_exc()
        print()


if __name__ == "__main__":
    main()
