"""Demo: execute our own code inside the target JVM — by rewriting a
method's bytecode and invalidating its JIT form so the new body runs.

We pick Target.tick(I)V, which the target calls every 500 ms. Before the
patch: each tick increments `ticks`, XORs `tag`, and rewrites
`lastMessage`. After we replace the body with a single `return` opcode
and invalidate the compiled method, the same Java-level invocation runs
our new bytecode — which does nothing — so `lastMessage` freezes.

Observed via polling from our side AND Target's own printout.
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
from oop_reader import OopDecoder
from string_reader import StringReader
from method_walker import methods_of, find_method, rewrite_method_body, make_nop_return

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


def mirror_of(vm: VMMeta, klass_ptr: int) -> int:
    r = vm.reader
    mf = vm.type("Klass").field("_java_mirror")
    raw = _ptr(r, klass_ptr + mf.offset)
    return _ptr(r, raw) if mf.type_string == "OopHandle" else raw


def read_last_message(vm: VMMeta, decoder: OopDecoder,
                      str_reader: StringReader, addr: int) -> str:
    if decoder.oops_are_compressed:
        narrow = struct.unpack_from("<I", vm.reader.read(addr, 4))[0]
        oop = decoder.decode_oop(narrow)
    else:
        oop = _ptr(vm.reader, addr)
    return str_reader.read(oop) if oop else ""


def run_one(version: str) -> None:
    java = find_java(version)
    if not java:
        print(f"[JDK {version}] java.exe missing"); return
    proc, pid = launch(java)
    try:
        time.sleep(1.5)
        vm = VMMeta.from_pid(pid)
        decoder = OopDecoder(vm)
        str_reader = StringReader(vm, decoder)

        target_klass = next(
            (k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
        if not target_klass:
            print("  Target class not loaded"); return
        mirror = mirror_of(vm, target_klass)
        last_f = find_field(vm, target_klass, "lastMessage")
        last_addr = mirror + last_f.offset

        tick = find_method(vm, target_klass, "tick", "(I)V")
        if tick is None:
            print("  Target.tick(I)V not found"); return

        print(f"[JDK {version}] pid={pid}")
        print(f"  Method Target.tick(I)V @ {tick.address:#x}")
        print(f"  ConstMethod @ {tick.const_method:#x}  code_size={tick.code_size}  "
              f"code @ {tick.code_base:#x}")

        # --- phase A: observe the method running normally ---
        samples_before = []
        for _ in range(5):
            samples_before.append(read_last_message(vm, decoder, str_reader, last_addr))
            time.sleep(0.55)
        print(f"  before patch: {samples_before}")
        unique_before = len(set(samples_before))

        # --- patch: replace body with `return` ---
        new_body = make_nop_return(tick)
        rewrite_method_body(vm, tick, new_body)
        print(f"  patched body: {new_body.hex()} + {tick.code_size - 1} nops")

        # Give the interpreter a moment to pick up the change on next dispatch.
        time.sleep(0.1)

        # --- phase B: observe post-patch ---
        samples_after = []
        for _ in range(5):
            samples_after.append(read_last_message(vm, decoder, str_reader, last_addr))
            time.sleep(0.55)
        print(f"  after  patch: {samples_after}")
        unique_after = len(set(samples_after))

        froze = unique_after == 1 and unique_before >= 3
        print(f"  unique before={unique_before}, after={unique_after}  "
              f"-> tick() effectively neutralised: {froze}")
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
            run_one(v)
        except Exception as e:
            import traceback
            print(f"  FAILED: {e}")
            traceback.print_exc()
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
