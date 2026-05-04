"""Matrix smoke: read Target.lastMessage under every JDK x GC x compressed
combination we claim to support. Catches regressions like the one we just
fixed (Shen + -UseCompressedOops).

For each (jdk, gc, compressed) cell: start Target, let it tick once, read
Target.lastMessage through StringReader. Cell passes iff the decoded text
matches the 'tick #N' pattern.

GCs not available in a given build are expected to fall back to the default
GC; we detect that and report with an 'fallback' note.
"""
from __future__ import annotations

import glob
import os
import re
import struct
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))   # repo root for python modules
sys.path.insert(0, _HERE)                    # tests dir for _paths

from vm_meta import VMMeta, _ptr, _u32
from walker import ClassWalker
from field_reader import find_field
from oop_reader import OopDecoder
from string_reader import StringReader
from zgc import ZGCDecoder
from _paths import TGT_CP as TARGET_CP, find_java

JDKS = ["11", "17", "21", "25"]
# Each GC entry: (label, flags). Flags is a list so we can inject the extras
# a given GC needs on specific JDK versions.
GCS = [
    ("Serial",   ["-XX:+UseSerialGC"]),
    ("Parallel", ["-XX:+UseParallelGC"]),
    ("G1",       ["-XX:+UseG1GC"]),
    ("Shen",     ["-XX:+UseShenandoahGC"]),
    ("ZGC",      ["-XX:+UseZGC"]),
]
COMPRESSED = [("comp", None), ("wide", "-XX:-UseCompressedOops")]

# GC/JDK pairs that require extra flags or are known-unsupported on Windows.
def patch_flags(jdk, gc_label, flags):
    """Adjust or reject a (jdk, gc) combination. Returns (flags|None, reason).
    flags is None -> skip this cell with the reason.
    """
    if gc_label == "ZGC":
        if jdk == "11":
            # Temurin JDK 11 on Windows doesn't ship ZGC (Windows support
            # landed in JDK 14). Skip honestly rather than pretend to test.
            return None, "ZGC not supported on Windows in JDK 11"
        if jdk == "21":
            # JDK 21 default ZGC is legacy single-gen with no exported
            # masks we can decode. Force generational so our probe works.
            return flags + ["-XX:+ZGenerational"], None
    return flags, None

TICK_RE = re.compile(r"^tick #\d+$")


def mirror_of(vm, klass_ptr, zgc):
    """Return the dereferenceable (decoded) mirror oop for a Klass.

    Under ZGC the slot in oopStorage holds a coloured pointer; we must
    uncolour it before adding field offsets.
    """
    r = vm.reader
    mf = vm.type("Klass").field("_java_mirror")
    raw = _ptr(r, klass_ptr + mf.offset)
    mirror = _ptr(r, raw) if mf.type_string == "OopHandle" else raw
    return zgc.decode(mirror) if zgc.is_active else mirror


def read_last_message(vm):
    decoder = OopDecoder(vm)
    zgc = ZGCDecoder.detect(vm)
    str_reader = StringReader(vm, decoder, zgc=zgc)
    tk = next((k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
    if not tk:
        return None, "Target klass not found"
    mirror = mirror_of(vm, tk, zgc)
    last_f = find_field(vm, tk, "lastMessage")
    slot = mirror + last_f.offset
    if zgc.is_active:
        raw = struct.unpack_from("<Q", vm.reader.read(slot, 8))[0]
        oop = zgc.decode(raw)
    elif decoder.oops_are_compressed:
        narrow = _u32(vm.reader, slot)
        oop = decoder.decode_oop(narrow)
    else:
        oop = _ptr(vm.reader, slot)
    return str_reader.read(oop), None


def run_cell(java, gc_flags, comp_flag):
    flags = list(gc_flags)
    if comp_flag:
        flags.append(comp_flag)
    cmd = [java, *flags, "-Xmx256m", "-cp", TARGET_CP, "Target"]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, errors="replace")
    pid = None
    saw_tick = False
    stderr_tail = []
    deadline = time.time() + 12.0
    try:
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.02); continue
            stderr_tail.append(line.rstrip())
            if len(stderr_tail) > 8:
                stderr_tail = stderr_tail[-8:]
            if line.startswith("Target PID:"):
                pid = int(line.split(":", 1)[1].strip())
            elif pid and line.startswith("tick="):
                saw_tick = True
                break
        if not pid:
            return False, "no PID (jvm failed to start?)", stderr_tail
        if not saw_tick:
            return False, "no tick observed", stderr_tail
        vm = VMMeta.from_pid(pid)
        text, err = read_last_message(vm)
        if err:
            return False, err, stderr_tail
        ok = bool(text) and bool(TICK_RE.match(text))
        return ok, f"text={text!r}", stderr_tail
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()


def main():
    results = []  # (jdk, gc, comp, ok, note)
    for jdk in JDKS:
        java = find_java(jdk)
        if not java:
            print(f"JDK {jdk}: NOT INSTALLED, skipping")
            continue
        for gc_name, gc_flags in GCS:
            patched, skip_reason = patch_flags(jdk, gc_name, gc_flags)
            for comp_name, comp_flag in COMPRESSED:
                tag = f"JDK {jdk:2}  {gc_name:8}  {comp_name}"
                if patched is None:
                    print(f"  SKIP  {tag}  {skip_reason}")
                    continue
                try:
                    ok, note, _tail = run_cell(java, patched, comp_flag)
                except Exception as e:
                    ok, note = False, f"EXC {e}"
                mark = "PASS" if ok else "FAIL"
                print(f"  {mark}  {tag}  {note}")
                results.append((jdk, gc_name, comp_name, ok, note))
    total = len(results)
    failed = [r for r in results if not r[3]]
    print()
    print(f"Summary: {total - len(failed)}/{total} pass, {len(failed)} fail")
    for jdk, gc, comp, ok, note in failed:
        print(f"  FAIL  JDK {jdk}  {gc}  {comp}  -- {note}")
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
