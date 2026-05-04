"""True full arbitrary invoke: extend CPCache with a NEW cache entry
(not reusing Target's existing one), patch bytecode to call via the
new cache index. HotSpot resolves the unresolved entry on first call.

This verifies we can invoke methods that Target NEVER ORIGINALLY CALLED,
as long as we know their CP Methodref index.
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

from vm_meta import VMMeta, _ptr
from walker import ClassWalker
from method_walker import find_method, rewrite_method_body
from cp_scanner import find_methodref
from cpcache import (clone_and_extend_cpcache_legacy,
                     clone_and_extend_cpcache_modern)

TARGET_CP = os.path.join(REPO_ROOT, "tests", "target", "build")


def find_java(v):
    hits = glob.glob(
        os.path.join(REPO_ROOT, "..", "jdks", f"temurin-{v}-jdk",
                     "**", "bin", "java.exe"), recursive=True)
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


def run_one(version: str) -> None:
    java = find_java(version)
    if not java: return
    proc, pid = launch(java)
    try:
        time.sleep(1.2)
        vm = VMMeta.from_pid(pid)
        tk = next((k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
        if not tk:
            print("Target not loaded"); return
        cp_ptr = _ptr(vm.reader,
                      tk + vm.type("InstanceKlass").field("_constants").offset)

        sleep_ref = find_methodref(vm, cp_ptr, "", "sleep", "(J)V")
        if not sleep_ref:
            print("  no sleep Methodref"); return

        # Pick legacy vs modern extension path based on layout.
        if vm.has_type("ConstantPoolCacheEntry"):
            old_cc, new_cc, new_cache_idxs = clone_and_extend_cpcache_legacy(
                vm, cp_ptr, extra_entries=1,
                new_cp_indices=[(sleep_ref.index, 0xB8)])
            path = "legacy inline"
        else:
            old_cc, new_cc, new_cache_idxs = clone_and_extend_cpcache_modern(
                vm, cp_ptr, extra_entries=1,
                new_cp_indices=[sleep_ref.index])
            path = "modern Array<ResolvedMethodEntry>"
        new_cidx = new_cache_idxs[0]
        print(f"[JDK {version}] pid={pid}  path={path}")
        print(f"  old @ {old_cc:#x}  new @ {new_cc:#x}")
        print(f"  new cache entry at index {new_cidx}, cloned from donor")

        # Patch tick to invoke via the new (unresolved) cache entry.
        tick = find_method(vm, tk, "tick", "(I)V")
        assert tick is not None
        bc = bytes([0x0A,
                    0xB8, new_cidx & 0xFF, (new_cidx >> 8) & 0xFF,
                    0xB1])
        print(f"  patching tick bytecode: {bc.hex()}  "
              f"(invokestatic LE[new_cache={new_cidx}])")
        rewrite_method_body(vm, tick, bc)

        deadline = time.time() + 15.0
        ticks = []
        while time.time() < deadline and len(ticks) < 2:
            line = proc.stdout.readline()
            if line.startswith("tick="):
                ticks.append(line.strip())
            if not line:
                if proc.poll() is not None:
                    print(f"  target died exit={proc.returncode}")
                    break
                time.sleep(0.05)
        print(f"  tick lines: {len(ticks)}")
        for t in ticks:
            print(f"    {t}")
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
