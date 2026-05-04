"""Demo: extend Target's ConstantPool with extra slots, verify target
survives the extended CP.

Just grows the CP by 4 slots left blank. If HotSpot tolerates a longer
CP whose tail entries are 0-tagged (invalid), we're good to fill in
actual Utf8 / NameAndType / Methodref entries in a follow-up.
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(_HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from vm_meta import VMMeta, _i32, _ptr
from walker import ClassWalker
from metaspace import extend_cp, restore_constant_pool

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


def run_one(version):
    java = find_java(version)
    if not java: return
    proc, pid = launch(java)
    try:
        time.sleep(1.2)
        vm = VMMeta.from_pid(pid)
        tk = next((k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
        if not tk: return

        ext = extend_cp(vm, tk, extra_slots=4)
        print(f"[JDK {version}] pid={pid}")
        print(f"  orig cp @ {ext.clone.orig_cp:#x}  len={ext.orig_length}")
        print(f"  new  cp @ {ext.clone.new_cp:#x}  len={ext.new_length}")
        print(f"  new tags @ {ext.new_tags_array:#x}")
        print(f"  free slots: [{ext.free_slot_start}..{ext.new_length - 1}]")

        # Let target run. If HotSpot accepts the extended CP, tick lines continue.
        deadline = time.time() + 12.0
        ticks = []
        while time.time() < deadline and len(ticks) < 2:
            line = proc.stdout.readline()
            if line.startswith("tick="):
                ticks.append(line.strip())
            if not line:
                time.sleep(0.05)
        print(f"  ticks captured: {len(ticks)}")
        for t in ticks:
            print(f"    {t}")

        restore_constant_pool(vm, ext.clone)
        vm.reader.free(ext.new_tags_array)
        print("  original CP + tags restored")
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()


def main():
    for v in ["8", "11", "17", "21", "25"]:
        print(f"=== JDK {v} ===")
        try:
            run_one(v)
        except Exception as e:
            print(f"  FAILED: {e}")
            import traceback; traceback.print_exc()
        print()


if __name__ == "__main__":
    main()
