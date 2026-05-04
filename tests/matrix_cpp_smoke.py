"""C++ CLI matrix smoke. Exercises every command the C++ port exposes
across JDK × GC × compressed combinations, so any regression in a shared
path (oop decode, klass resolve, writes, barriers) surfaces early.

Each cell starts a Target, waits for one tick, runs the C++ command,
and grades pass/fail by stdout content.
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE as EXE, TGT_CP as TARGET_CP, find_java

# (label, flags). Wide-oops variants included where interesting.
CELLS = [
    ("JDK11 G1 comp",    "11", ["-XX:+UseG1GC"]),
    ("JDK11 Par wide",   "11", ["-XX:+UseParallelGC", "-XX:-UseCompressedOops"]),
    ("JDK11 Shen comp",  "11", ["-XX:+UseShenandoahGC"]),
    ("JDK17 G1 comp",    "17", ["-XX:+UseG1GC"]),
    ("JDK17 G1 wide",    "17", ["-XX:+UseG1GC", "-XX:-UseCompressedOops"]),
    ("JDK17 Shen comp",  "17", ["-XX:+UseShenandoahGC"]),
    ("JDK17 ZGC",        "17", ["-XX:+UseZGC"]),
    ("JDK21 Serial",     "21", ["-XX:+UseSerialGC"]),
    ("JDK21 Shen wide",  "21", ["-XX:+UseShenandoahGC", "-XX:-UseCompressedOops"]),
    ("JDK21 ZGC gen",    "21", ["-XX:+UseZGC", "-XX:+ZGenerational"]),
    ("JDK25 G1 comp",    "25", ["-XX:+UseG1GC"]),
    ("JDK25 G1 wide",    "25", ["-XX:+UseG1GC", "-XX:-UseCompressedOops"]),
    ("JDK25 ZGC gen",    "25", ["-XX:+UseZGC"]),
    ("JDK25 Shen comp",  "25", ["-XX:+UseShenandoahGC"]),
]


def start_target(java, flags):
    proc = subprocess.Popen(
        [java, *flags, "-Xmx256m", "-cp", TARGET_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        line = proc.stdout.readline()
        if line.startswith("Target PID:"):
            pid = int(line.split(":", 1)[1].strip()); break
    if not pid: proc.kill(); return None, None
    # Wait for first tick so Target mutates lastMessage.
    t1 = time.time()
    while time.time() - t1 < 12:
        line = proc.stdout.readline()
        if line.startswith("tick="): break
    return proc, pid


def run_cli(pid, *args, timeout=20):
    r = subprocess.run([EXE, *args, *([str(pid)] if False else [])],
                       capture_output=True, text=True, timeout=timeout)
    # Simpler: command-first then pid. Re-do the call cleanly.
    return r


def cli(pid, *rest, timeout=20):
    r = subprocess.run([EXE, rest[0], str(pid), *rest[1:]],
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def grade(pid, label):
    checks = []

    rc, out, err = cli(pid, "threads")
    checks.append(("threads", rc == 0 and "JavaThread@" in out))

    rc, out, err = cli(pid, "classes")
    checks.append(("classes", rc == 0 and "java/lang/" in out))

    rc, out, err = cli(pid, "read-string", "Target", "lastMessage")
    checks.append(("read-string", rc == 0 and "tick #" in out))

    rc, out, err = cli(pid, "methods", "Target")
    checks.append(("methods", rc == 0 and "tick(I)V" in out))

    rc, out, err = cli(pid, "write-ref", "Target", "displayName", "lastMessage")
    rc2, out2, _ = cli(pid, "read-string", "Target", "displayName")
    checks.append(("write-ref", rc == 0 and "tick #" in out2))

    rc, out, err = cli(pid, "instances", "Target")
    checks.append(("instances", rc == 0 and "instances found" in out))

    rc, out, err = cli(pid, "alloc-ba", "32")
    checks.append(("alloc-ba", rc == 0 and "byte[32]" in out))

    rc, out, err = cli(pid, "clone-class", "Target", "TargetClone_" + label.replace(" ", "_"))
    checks.append(("clone-class", rc == 0 and "sees" in out and "YES" in out))

    # hook takes 2s — keep this as the last because target may slow under suspension.
    rc, out, err = cli(pid, "hook", "Target", "tick", timeout=30)
    checks.append(("hook", rc == 0 and "count after 2s" in out))

    return checks


def main():
    total_cells = 0
    failed_cells = 0
    for label, jdk, flags in CELLS:
        java = find_java(jdk)
        if not java:
            print(f"[SKIP] {label}: JDK {jdk} not installed"); continue
        total_cells += 1
        proc, pid = start_target(java, flags)
        if not pid:
            print(f"[FAIL] {label}: Target failed to start")
            failed_cells += 1; continue
        try:
            checks = grade(pid, label)
            failed = [c for c, ok in checks if not ok]
            mark = "PASS" if not failed else "FAIL"
            print(f"[{mark}] {label}: "
                  + ", ".join(f"{c}={'ok' if ok else 'FAIL'}" for c, ok in checks))
            if failed: failed_cells += 1
        finally:
            proc.terminate()
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill()
    print()
    print(f"Summary: {total_cells - failed_cells}/{total_cells} PASS")
    sys.exit(0 if failed_cells == 0 else 1)


if __name__ == "__main__":
    main()
