"""Demo: write a static int field in a running JVM from outside.

Launches Target.java, lets it run for a few ticks, then attaches via
VMMeta.from_pid() with write access, finds the Target class and its
`counter` static field, and pokes a large value. Target prints a tick log
every 20 counts, so we can confirm the change by watching stdout.

Scope: M4.a — primitive scalar write. No card marks (not needed for a
scalar field), no safepoint coordination (a 4-byte aligned write to a
normal heap page is atomic on x86-64).
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

from vm_meta import VMMeta, _i32, _ptr, _write_i32
from walker import ClassWalker
from field_reader import find_field

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")

NEW_COUNTER = 999_980  # round-ish so the next 'tick=' print hits 1000000


def find_java(v: str) -> str | None:
    hits = glob.glob(
        os.path.join(REPO_ROOT, "..", "jdks", f"temurin-{v}-jdk",
                     "**", "bin", "java.exe"),
        recursive=True)
    return hits[0] if hits else None


def launch_target(java: str) -> tuple[subprocess.Popen, int]:
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


def read_until(proc: subprocess.Popen, predicate, timeout_s: float) -> str | None:
    """Read stdout until predicate(line) is truthy or timeout expires."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05); continue
        if predicate(line):
            return line
    return None


def mirror_address_for_klass(vm: VMMeta, klass_ptr: int) -> int:
    """Resolve the java.lang.Class mirror oop for this Klass, following
    OopHandle indirection on JDK 11+."""
    r = vm.reader
    mirror_f = vm.type("Klass").field("_java_mirror")
    raw = _ptr(r, klass_ptr + mirror_f.offset)
    if mirror_f.type_string == "OopHandle":
        if not raw:
            return 0
        return _ptr(r, raw)
    return raw


def poke_counter(version: str) -> None:
    java = find_java(version)
    if not java:
        print(f"[JDK {version}] java.exe missing"); return
    proc, pid = launch_target(java)
    try:
        # Let Target warm up and emit at least one tick line.
        first_tick = read_until(
            proc, lambda ln: ln.startswith("tick="), timeout_s=15.0)
        if first_tick:
            print(f"  before: {first_tick.strip()}")

        vm = VMMeta.from_pid(pid)

        # Find Target class. Klass enumeration is fast (~0.1s).
        target_klass = 0
        for k in ClassWalker(vm):
            if k.name == "Target":
                target_klass = k.address
                break
        if not target_klass:
            print("  [fail] Target class not loaded")
            return

        counter_field = find_field(vm, target_klass, "counter")
        if counter_field is None or not counter_field.is_static:
            print("  [fail] static field 'counter' missing on Target")
            return

        mirror = mirror_address_for_klass(vm, target_klass)
        if not mirror:
            print("  [fail] Target._java_mirror is null")
            return

        addr = mirror + counter_field.offset
        cur = _i32(vm.reader, addr)
        print(f"  Target.counter @ mirror {mirror:#x} + {counter_field.offset}"
              f"  = {cur}  -> writing {NEW_COUNTER}")

        _write_i32(vm.reader, addr, NEW_COUNTER)

        verify = _i32(vm.reader, addr)
        print(f"  readback: {verify}")

        # Target prints every 20 ticks; after counter=999_980 the next log
        # line should be 'tick=1000000' (give or take a few ticks).
        next_tick = read_until(
            proc, lambda ln: ln.startswith("tick="), timeout_s=20.0)
        print(f"  after:  {next_tick.strip() if next_tick else '<no output>'}")

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
            poke_counter(v)
        except Exception as e:
            import traceback
            print(f"  FAILED: {e}")
            traceback.print_exc()
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
