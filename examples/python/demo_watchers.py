"""Demo: live-watch two static fields of Target.java across all 5 JDKs.

Target increments `counter` every ~500 ms and rewrites `lastMessage` to
"tick #N" each iteration. We attach read-only via VMMeta.from_pid() and
poll the two fields from our process, printing every value change.

This exercises every read primitive we've built so far:
  - VMMeta cross-process parsing
  - Klass lookup via ClassWalker
  - Static field offset via FieldInfo / FieldInfoStream
  - Klass._java_mirror deref (direct oop on 8, OopHandle on 11+)
  - Narrow oop decoding for the lastMessage reference field
  - java.lang.String decoding (coder-aware)
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
from watchers import FieldWatch, PollingWatcher

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")
WATCH_SECONDS = 4.0


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


def run_one(version: str) -> None:
    java = find_java(version)
    if not java:
        print(f"[JDK {version}] java.exe missing"); return
    proc, pid = launch_target(java)
    try:
        # Wait for Target to have done at least one tick so both fields
        # have materialized beyond their static initializers.
        time.sleep(1.0)

        vm = VMMeta.from_pid(pid)
        decoder = OopDecoder(vm)
        str_reader = StringReader(vm, decoder)

        target_klass = next(
            (k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
        if not target_klass:
            print("  Target class not loaded"); return
        mirror = mirror_of(vm, target_klass)
        counter_f = find_field(vm, target_klass, "counter")
        message_f = find_field(vm, target_klass, "lastMessage")
        assert counter_f and message_f, "Target static fields missing"

        counter_addr = mirror + counter_f.offset
        message_addr = mirror + message_f.offset

        def read_counter() -> int:
            return _i32(vm.reader, counter_addr)

        def read_message() -> str:
            # Reference field is a narrow oop on a compressed heap.
            if decoder.oops_are_compressed:
                narrow = struct.unpack_from(
                    "<I", vm.reader.read(message_addr, 4))[0]
                str_oop = decoder.decode_oop(narrow)
            else:
                str_oop = _ptr(vm.reader, message_addr)
            return str_reader.read(str_oop) if str_oop else ""

        events: list[str] = []

        def on_counter(old: int, new: int) -> None:
            events.append(f"    counter  {old} -> {new}")

        def on_message(old: str, new: str) -> None:
            events.append(f"    message  {old!r} -> {new!r}")

        print(f"[JDK {version}] pid={pid}  watching for {WATCH_SECONDS}s")
        print(f"           counter@{counter_addr:#x}  "
              f"message@{message_addr:#x}")

        watcher = PollingWatcher()
        watcher.watch(FieldWatch("Target.counter",
                                 read_counter, on_counter,
                                 interval_ms=50))
        watcher.watch(FieldWatch("Target.lastMessage",
                                 read_message, on_message,
                                 interval_ms=50))
        watcher.run_for(WATCH_SECONDS)

        # Stdout on Windows defaults to cp1251; an astral-code-point in a
        # decoded String would crash print(). Flatten to ASCII-safe repr.
        def _safe(s: object) -> str:
            return repr(s).encode("ascii", "backslashreplace").decode("ascii")
        for e in events:
            try:
                print(e)
            except UnicodeEncodeError:
                print(_safe(e))
        print(f"           captured {len(events)} events")
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
