"""Demo: construct a brand-new Java String outside the target VM.

Flow:
  1. Launch Target (static `displayName = "initial"`).
  2. Attach cross-process; suspend all target threads.
  3. Allocate byte[18] via TLAB hijack; fill with b"hello from outside".
  4. Allocate a fresh java.lang.String via TLAB hijack; wire its `value`
     field to our byte[] and its `coder` byte to 0 (Latin1).
  5. Store the new String into Target.displayName, card-mark the mirror.
  6. Wait for Target's next printout; expect `displayName=hello from outside`.

Everything stays within the no-JNI/JVMTI constraint: we only write raw
bytes into regions the target already owns.
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
from tlab import TLABAllocator

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")
PAYLOAD = b"hello from outside"


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


def find_klass(vm: VMMeta, name: str) -> int:
    for k in ClassWalker(vm):
        if k.name == name:
            return k.address
    return 0


# JDK 8's SystemDictionary doesn't register primitive array klasses — they
# are reached instead through Universe::_xxxArrayKlassObj statics, which are
# exported on 8 but dropped from vmStructs in 11+.
_PRIMITIVE_ARRAY_UNIVERSE_FIELD = {
    "[B": "_byteArrayKlassObj",
    "[C": "_charArrayKlassObj",
    "[S": "_shortArrayKlassObj",
    "[I": "_intArrayKlassObj",
    "[J": "_longArrayKlassObj",
    "[F": "_singleArrayKlassObj",
    "[D": "_doubleArrayKlassObj",
    "[Z": "_boolArrayKlassObj",
}


def find_primitive_array_klass(vm: VMMeta, array_name: str) -> int:
    k = find_klass(vm, array_name)
    if k:
        return k
    field = _PRIMITIVE_ARRAY_UNIVERSE_FIELD.get(array_name)
    if not field:
        return 0
    u = vm.type("Universe")
    if not u.has_field(field):
        return 0
    return _ptr(vm.reader, u.static_field(field).address)


def write_ref_slot(vm: VMMeta, decoder: OopDecoder,
                   addr: int, wide_oop: int) -> None:
    if decoder.oops_are_compressed:
        _write_u32(vm.reader, addr, decoder.encode_oop(wide_oop))
    else:
        _write_u64(vm.reader, addr, wide_oop)


def read_ref_slot(vm: VMMeta, decoder: OopDecoder, addr: int) -> int:
    if decoder.oops_are_compressed:
        narrow = struct.unpack_from("<I", vm.reader.read(addr, 4))[0]
        return decoder.decode_oop(narrow)
    return _ptr(vm.reader, addr)


def run_one(version: str) -> None:
    java = find_java(version)
    if not java:
        print(f"[JDK {version}] java.exe missing"); return
    proc, pid = launch(java)
    try:
        time.sleep(1.2)  # let the target warm up + print first tick
        vm = VMMeta.from_pid(pid)
        decoder = OopDecoder(vm)
        str_reader = StringReader(vm, decoder)
        alloc = TLABAllocator(vm, decoder)

        string_klass = find_klass(vm, "java/lang/String")
        target_klass = find_klass(vm, "Target")
        value_f = find_field(vm, string_klass, "value")
        coder_f = find_field(vm, string_klass, "coder")

        # JDK 8 String.value is char[]; JDK 9+ Compact Strings store byte[].
        is_compact = coder_f is not None
        array_name = "[B" if is_compact else "[C"
        array_klass = find_primitive_array_klass(vm, array_name)
        if not (array_klass and string_klass and target_klass):
            print(f"  missing klass: {array_name}={array_klass:#x} "
                  f"String={string_klass:#x} Target={target_klass:#x}")
            return

        if is_compact:
            buf = PAYLOAD
            element_count = len(PAYLOAD)
        else:
            buf = PAYLOAD.decode("ascii").encode("utf-16-le")
            element_count = len(PAYLOAD)

        # --- step 1: array with payload ---
        arr = alloc.allocate_type_array(array_klass, element_count)
        vm.reader.write(arr + alloc.array_data_offset(), buf)
        print(f"[JDK {version}] pid={pid}")
        print(f"  {array_name} @ {arr:#x} length={element_count} payload={PAYLOAD!r}")

        # --- step 2: String with wired-up value + coder ---
        new_str = alloc.allocate_instance(string_klass)
        write_ref_slot(vm, decoder, new_str + value_f.offset, arr)
        if is_compact:
            vm.reader.write(new_str + coder_f.offset, b"\x00")  # Latin1

        # Card-mark the String itself — its `value` field now points into a
        # freshly allocated (likely eden) array; without the mark the next
        # young GC might miss this cross-generation reference.
        byte_map_base = get_card_byte_map_base(vm)
        if byte_map_base:
            mark_card_dirty(vm, byte_map_base, new_str + value_f.offset)

        coder_info = "coder=0 (Latin1)" if is_compact else "char[] (JDK 8)"
        print(f"  String @ {new_str:#x}  value={array_name}[{arr:#x}]  {coder_info}")

        # --- step 3: target Target.displayName ---
        mirror = mirror_of(vm, target_klass)
        disp_f = find_field(vm, target_klass, "displayName")
        disp_addr = mirror + disp_f.offset
        write_ref_slot(vm, decoder, disp_addr, new_str)
        if byte_map_base:
            mark_card_dirty(vm, byte_map_base, disp_addr)

        # --- step 4: readback proves it from our side ---
        back_oop = read_ref_slot(vm, decoder, disp_addr)
        back_text = str_reader.read(back_oop) if back_oop else ""
        print(f"  readback: displayName = {back_text!r}")
        match = back_text == PAYLOAD.decode("latin-1")
        print(f"  match: {match}")
        vm.close()

        # --- step 5: Target's next tick print ---
        deadline = time.time() + 12.0
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.05); continue
            if line.startswith("tick="):
                print(f"  target says: {line.strip()}")
                break
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
