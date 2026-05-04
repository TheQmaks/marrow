"""Demo: invoke using a cache entry whose _flags were synthesised from
the method descriptor rather than copied from a matching-signature donor.

We use a donor with a different signature but same bytecode (invokestatic),
then override _flags to describe our actual target method. If HotSpot
dispatches correctly, synth is verified.

Simplest non-trivial variant: call Thread.sleep(J)V using a cache entry
whose DONOR was Long.parseLong(Ljava/lang/String;)J — different arg type,
different return. Synth'd _flags describe (J)V though, so dispatch pops
2 slots (long) and expects void return — matching sleep's real needs.
`_f1` is replaced with sleep's actual Method* (read from Target's own
existing sleep cache entry so we don't need to walk InstanceKlass._methods).
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
                     iterate_cpcache_entries_legacy, find_cpcache)

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


def run_one(v):
    java = find_java(v)
    if not java: return
    proc, pid = launch(java)
    try:
        time.sleep(1.2)
        vm = VMMeta.from_pid(pid)
        tk = next((k.address for k in ClassWalker(vm) if k.name == "Target"), 0)
        cp_ptr = _ptr(vm.reader,
                      tk + vm.type("InstanceKlass").field("_constants").offset)

        # Methodref we want to invoke (Thread.sleep(J)V).
        sleep_ref = find_methodref(vm, cp_ptr, "", "sleep", "(J)V")
        assert sleep_ref
        # Read sleep's actual Method* from the existing resolved entry
        # so override_f1 has the right pointer.
        sleep_f1 = 0
        for e in iterate_cpcache_entries_legacy(vm, find_cpcache(vm, cp_ptr)):
            if e.cp_index == sleep_ref.index and e.b1 == 0xB8:
                sleep_f1 = e.f1; break
        assert sleep_f1

        # Ask for an entry whose CP index is sleep's, bytecode invokestatic,
        # signature "(J)V" — synthesizer fills _flags accordingly. Donor
        # is auto-chosen by the extend function.
        old_cc, new_cc, idxs = clone_and_extend_cpcache_legacy(
            vm, cp_ptr, extra_entries=1,
            new_cp_indices=[(sleep_ref.index, 0xB8)],
            sigs=["(J)V"],
            is_static=[True],
            override_f1=[sleep_f1],
        )
        print(f"[JDK {v}] pid={pid}")
        print(f"  extended cpcache: old @ {old_cc:#x}  new @ {new_cc:#x}")
        print(f"  new entry idx={idxs[0]}, sig='(J)V', _f1=sleep Method*")

        tick = find_method(vm, tk, "tick", "(I)V")
        assert tick is not None
        ci = idxs[0]
        bc = bytes([0x0A, 0xB8, ci & 0xFF, (ci >> 8) & 0xFF, 0xB1])
        rewrite_method_body(vm, tick, bc)
        print(f"  patched tick bytecode: {bc.hex()}")

        deadline = time.time() + 15.0
        ticks = []
        while time.time() < deadline and len(ticks) < 2:
            line = proc.stdout.readline()
            if line.startswith("tick="):
                ticks.append(line.strip())
            if not line:
                if proc.poll() is not None:
                    print(f"  target died exit={proc.returncode}"); break
                time.sleep(0.05)
        print(f"  ticks: {len(ticks)}")
        for t in ticks:
            print(f"    {t}")
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()


def main():
    # Legacy inline CPCache: JDK 8/11/17/21. JDK 25 uses modern layout.
    for v in ["11", "17", "21"]:
        print(f"=== JDK {v} ===")
        try: run_one(v)
        except Exception as e:
            print(f"  FAILED: {e}")
            import traceback; traceback.print_exc()
        print()


if __name__ == "__main__":
    main()
