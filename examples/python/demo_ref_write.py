"""Demo: replace a live Java reference field from outside the JVM.

Overwrites Target.displayName (static String, never mutated by Target
itself) with another live String oop — the current value of
Target.lastMessage, captured as a donor. Correct GC interaction requires
marking the card table entry covering the mutated slot so the next young
GC keeps the donor reachable via our write.

Scope M4.b:
  * narrow-oop encoding
  * cross-process WriteProcessMemory for a 4-byte reference slot
  * card-table byte_map_base resolution (JDK 8 vs JDK 11+ paths)
  * explicit dirty mark

Card marks are a no-op for non-card-table BarrierSets (ZGC, Shenandoah);
we don't target those here. All five of our test JVMs use the default GC
(ParallelGC on 8, G1 on 11..25), all of which have a card table.
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

from vm_meta import VMMeta, _ptr, _write_u32, _write_u64
from walker import ClassWalker
from field_reader import find_field
from oop_reader import OopDecoder
from string_reader import StringReader
from barriers import get_card_byte_map_base, mark_card_dirty

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")


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


def mirror_of(vm: VMMeta, klass_ptr: int) -> int:
    r = vm.reader
    mirror_f = vm.type("Klass").field("_java_mirror")
    raw = _ptr(r, klass_ptr + mirror_f.offset)
    if mirror_f.type_string == "OopHandle":
        return _ptr(r, raw) if raw else 0
    return raw


def read_ref_slot(vm: VMMeta, decoder: OopDecoder, addr: int) -> int:
    """Read a Java reference slot as a wide oop, handling narrow layout."""
    if decoder.oops_are_compressed:
        narrow = struct.unpack_from("<I", vm.reader.read(addr, 4))[0]
        return decoder.decode_oop(narrow)
    return _ptr(vm.reader, addr)


def write_ref_slot(vm: VMMeta, decoder: OopDecoder,
                   addr: int, wide_oop: int) -> None:
    """Write a wide oop into a Java reference slot, encoding as narrow
    when compressed oops are active. Caller must card-mark separately."""
    if decoder.oops_are_compressed:
        _write_u32(vm.reader, addr, decoder.encode_oop(wide_oop))
    else:
        _write_u64(vm.reader, addr, wide_oop)


def run_one(version: str) -> None:
    java = find_java(version)
    if not java:
        print(f"[JDK {version}] java.exe missing"); return
    proc, pid = launch_target(java)
    try:
        # Wait for Target to execute at least one tick so lastMessage has
        # left its 'init' static initializer and points at a live "tick #N".
        time.sleep(1.2)

        vm = VMMeta.from_pid(pid)
        decoder = OopDecoder(vm)
        str_reader = StringReader(vm, decoder)

        target_klass = next(
            (k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
        if not target_klass:
            print("  Target class not loaded"); return
        mirror = mirror_of(vm, target_klass)
        last_f = find_field(vm, target_klass, "lastMessage")
        disp_f = find_field(vm, target_klass, "displayName")
        assert last_f and disp_f

        last_addr = mirror + last_f.offset
        disp_addr = mirror + disp_f.offset

        # Snapshot donor from Target.lastMessage right now. This String is
        # a live heap object (referenced from the mutating field). Without
        # a card mark after we install the reference elsewhere, the donor
        # would become unreachable from the viewpoint of young GC and get
        # collected despite our pointer — exactly the barrier we're testing.
        donor = read_ref_slot(vm, decoder, last_addr)
        donor_text = str_reader.read(donor) if donor else ""

        before = read_ref_slot(vm, decoder, disp_addr)
        before_text = str_reader.read(before) if before else ""

        print(f"[JDK {version}] pid={pid} mirror={mirror:#x}")
        print(f"           decoder={decoder}")
        print(f"           donor:  {donor_text!r}  @ {donor:#x}")
        print(f"           before: displayName = {before_text!r}")

        # --- the write ---
        write_ref_slot(vm, decoder, disp_addr, donor)
        byte_map_base = get_card_byte_map_base(vm)
        if byte_map_base:
            mark_card_dirty(vm, byte_map_base, disp_addr)
            print(f"           card:   byte_map_base={byte_map_base:#x}  "
                  f"marked @ {(byte_map_base + (disp_addr >> 9)):#x}")
        else:
            print("           card:   no card-table BarrierSet — skipped")

        after = read_ref_slot(vm, decoder, disp_addr)
        after_text = str_reader.read(after) if after else ""
        print(f"           after:  displayName = {after_text!r}")
        print(f"           match:  {after == donor and after_text == donor_text}")
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
