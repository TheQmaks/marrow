"""Demo: overwrite a reference field under generational ZGC.

ZGC uses colour bits in the low bits of 64-bit pointers. Reading is a
right-shift. Writing requires re-colouring: shift the target heap
address up and OR in the current `ZPointerStoreGoodMask`. Without that,
the JVM sees a "load-bad" pointer on the next read and aborts.

Target runs under `-XX:+UseZGC -XX:+ZGenerational`. We take the current
value of `Target.lastMessage` as our donor oop, uncolour it, re-colour
it for store, then install it into `Target.displayName`. We skip card
marks because ZGC doesn't use a card table.
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

from vm_meta import VMMeta, _ptr, _write_u64
from walker import ClassWalker
from field_reader import find_field
from oop_reader import OopDecoder
from string_reader import StringReader
from zgc import ZGCDecoder

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")


def find_java(v: str) -> str:
    return glob.glob(
        os.path.join(REPO_ROOT, "..", "jdks", f"temurin-{v}-jdk",
                     "**", "bin", "java.exe"),
        recursive=True)[0]


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


def mirror_of(vm: VMMeta, klass_ptr: int) -> int:
    r = vm.reader
    mf = vm.type("Klass").field("_java_mirror")
    raw = _ptr(r, klass_ptr + mf.offset)
    return _ptr(r, raw) if mf.type_string == "OopHandle" else raw


CONFIGS = [
    ("JDK 17 classic ZGC", "17",
     ["-XX:+UseZGC", "-XX:+UnlockExperimentalVMOptions", "-Xmx64m"]),
    ("JDK 21 generational ZGC", "21",
     ["-XX:+UseZGC", "-XX:+ZGenerational",
      "-XX:+UnlockExperimentalVMOptions", "-Xmx64m"]),
    ("JDK 25 ZGC (generational default)", "25",
     ["-XX:+UseZGC", "-Xmx64m"]),
]


def run_one(title: str, version: str, extra: list[str]) -> None:
    java = find_java(version)
    proc, pid = launch(java, extra)
    try:
        time.sleep(1.3)
        vm = VMMeta.from_pid(pid)
        zgc = ZGCDecoder.detect(vm)
        decoder = OopDecoder(vm)
        str_reader = StringReader(vm, decoder, zgc=zgc)

        print(f"=== {title} ===")
        print(f"  pid={pid}  {zgc}")
        if not zgc.is_active:
            print("  skipped (ZGC not active)"); return

        tk = next((k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
        if not tk:
            print("  Target not loaded"); return
        mirror_raw = mirror_of(vm, tk)
        # Under ZGC the mirror oop lands coloured; uncolour before using it
        # as a base address for field reads.
        mirror = zgc.decode(mirror_raw)
        print(f"  mirror raw={mirror_raw:#x}  uncoloured={mirror:#x}")
        last_f = find_field(vm, tk, "lastMessage")
        disp_f = find_field(vm, tk, "displayName")

        # Donor: read raw wide pointer from lastMessage.
        raw_last = struct.unpack_from(
            "<Q", vm.reader.read(mirror + last_f.offset, 8))[0]
        donor_heap = zgc.decode(raw_last)
        donor_text = str_reader.read(donor_heap)
        print(f"  donor raw        = {raw_last:#018x}")
        print(f"  donor uncoloured = {donor_heap:#x}")
        print(f"  donor text       = {donor_text!r}")

        colored = zgc.encode_for_store(donor_heap)
        print(f"  encoded-for-store= {colored:#018x}")

        disp_addr = mirror + disp_f.offset
        before_raw = struct.unpack_from(
            "<Q", vm.reader.read(disp_addr, 8))[0]
        before_text = str_reader.read(zgc.decode(before_raw))
        print(f"  before displayName raw = {before_raw:#018x}  text={before_text!r}")

        _write_u64(vm.reader, disp_addr, colored)

        after_raw = struct.unpack_from(
            "<Q", vm.reader.read(disp_addr, 8))[0]
        after_text = str_reader.read(zgc.decode(after_raw))
        print(f"  after  displayName raw = {after_raw:#018x}  text={after_text!r}")
        print(f"  value installed: {after_raw == colored}")
        print(f"  text matches:    {after_text == donor_text}")

        # Check target didn't die by waiting for one tick print.
        deadline = time.time() + 12.0
        tick_line = None
        while time.time() < deadline:
            line = proc.stdout.readline()
            if line.startswith("tick="):
                tick_line = line.strip(); break
            if not line:
                time.sleep(0.05)
        if tick_line:
            print(f"  target says: {tick_line}")
        else:
            print("  target produced no tick in 12s — may have died")
        vm.close()
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()


def main() -> int:
    if not os.path.isfile(os.path.join(TARGET_CP, "Target.class")):
        print("Target.class missing"); return 2
    for title, version, extra in CONFIGS:
        try:
            run_one(title, version, extra)
        except Exception as e:
            print(f"=== {title} FAILED ===  {e}")
            import traceback; traceback.print_exc()
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
