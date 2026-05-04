"""Demo: list every thread in a live target JVM, for each of our 5 JDKs.

Launches Target.java under each installed JDK, attaches via VMMeta.from_pid(),
and prints the thread snapshot produced by ThreadWalker. Proves end-to-end
that (a) PE export resolution, (b) RPM, (c) vmStructs parsing, and
(d) version-adaptive thread walking all work together.
"""
from __future__ import annotations

import glob
import os
import struct
import subprocess
import sys
import time
from typing import Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(_HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from vm_meta import VMMeta, _ptr
from walker import ThreadWalker, read_symbol
from oop_reader import OopDecoder
from field_reader import find_field
from string_reader import StringReader

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")


def find_java(v: str) -> str | None:
    hits = glob.glob(
        os.path.join(REPO_ROOT, "..", "jdks", f"temurin-{v}-jdk",
                     "**", "bin", "java.exe"),
        recursive=True)
    return hits[0] if hits else None


def launch_and_get_pid(java: str, wait_ms: int = 1500) -> tuple[subprocess.Popen, int]:
    proc = subprocess.Popen(
        [java, "-cp", TARGET_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    deadline = time.time() + 10.0
    pid = None
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05); continue
        if line.startswith("Target PID:"):
            pid = int(line.split(":", 1)[1].strip())
            break
    if pid is None:
        proc.kill()
        raise TimeoutError("Target did not announce PID")
    # Give the JVM a moment so post-startup threads (compiler, GC, service)
    # have attached — otherwise we see only main + VM Thread.
    time.sleep(wait_ms / 1000)
    return proc, pid


def dump_threads(version: str) -> None:
    java = find_java(version)
    if not java:
        print(f"[JDK {version}] java.exe missing"); return

    proc, pid = launch_and_get_pid(java)
    try:
        vm = VMMeta.from_pid(pid)
        walker = ThreadWalker(vm)
        decoder = OopDecoder(vm)
        threads = walker.list()
        print(f"[JDK {version}] pid={pid} strategy={walker.strategy!r} "
              f"{decoder!r}")
        print(f"           found {len(threads)} threads")

        # _threadObj is a direct oop in JDK 8/11, OopHandle in JDK 17+.
        thrObj_f = vm.type("JavaThread").field("_threadObj")
        is_handle = thrObj_f.type_string == "OopHandle"

        # Prime OopDecoder's compressed-klass probe on a known-good oop, then
        # build a StringReader over the same VM. Thread.name field offset is
        # looked up once per JDK via the live field-info decoder.
        str_reader = StringReader(vm, decoder)
        thread_klass_name_offset: int | None = None

        for t in threads:
            thread_oop = (decoder.deref_oop_handle(t.thread_obj)
                          if is_handle else t.thread_obj)
            klass_ptr = decoder.klass_of(thread_oop) if thread_oop else 0
            class_name = "?"
            name_text = "?"
            if klass_ptr:
                name_sym = _ptr(vm.reader, klass_ptr
                                + vm.type("Klass").field("_name").offset)
                class_name = read_symbol(vm, vm.reader, name_sym)
                # Lazy: resolve 'name' field offset on the first Thread-like
                # class we see. Java's Thread and its subclasses share the
                # field at the same offset because it's declared on Thread.
                if thread_klass_name_offset is None:
                    f = find_field(vm, klass_ptr, "name")
                    if f is None:
                        # Try the concrete java/lang/Thread klass directly.
                        from walker import ClassWalker
                        for k in ClassWalker(vm):
                            if k.name == "java/lang/Thread":
                                f = find_field(vm, k.address, "name")
                                break
                    if f is not None:
                        thread_klass_name_offset = f.offset

            if thread_oop and thread_klass_name_offset is not None:
                # String reference field — narrow oop in a compressed heap.
                name_slot = thread_oop + thread_klass_name_offset
                if decoder.oops_are_compressed:
                    narrow = struct.unpack_from("<I",
                        vm.reader.read(name_slot, 4))[0]
                    str_oop = decoder.decode_oop(narrow)
                else:
                    str_oop = _ptr(vm.reader, name_slot)
                if str_oop:
                    name_text = str_reader.read(str_oop) or "<empty>"

            vt = f"  vthread={t.vthread:#x}" if t.vthread else ""
            tid_str = f"tid={t.os_tid:>6d}" if t.os_tid else "tid=     ?"
            print(f"    [{tid_str}] {t.state_name:<22}  "
                  f"{class_name:<40}  name={name_text!r}{vt}")
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
            dump_threads(v)
        except Exception as e:
            print(f"    FAILED: {e}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
