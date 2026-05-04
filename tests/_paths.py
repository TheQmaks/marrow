"""Path resolution shared by all test scripts.

REPO_ROOT is derived from __file__ -- this module lives at
<REPO_ROOT>/tests/_paths.py, so REPO_ROOT = parent of `tests`.

JDKs are user-installed and not in the repo. Tests look for them in:
    1. $MARROW_JDKS (env var override)
    2. <REPO_ROOT>/../jdks (repo's parent dir, the dev layout)
    3. $JAVA_HOME/.. (sibling JDK installs near JAVA_HOME)
"""
from __future__ import annotations

import glob
import os
import sys

# tests/_paths.py -> REPO_ROOT = jvm-probe/
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)

# Built artifacts (assumes `cmake --build build --config Release` already ran).
PROBE  = os.path.join(REPO_ROOT, "cpp", "build", "Release", "marrow.exe")
AGENT  = os.path.join(REPO_ROOT, "cpp", "build", "Release", "marrow_agent.dll")

# Compiled Target/Callable/HotTarget classes.
TGT_CP = os.path.join(REPO_ROOT, "tests", "target", "build")


def _candidate_jdk_dirs() -> list[str]:
    out: list[str] = []
    env = os.environ.get("MARROW_JDKS")
    if env: out.append(env)
    out.append(os.path.normpath(os.path.join(REPO_ROOT, "..", "jdks")))
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        out.append(os.path.normpath(os.path.join(java_home, "..")))
    return out


def find_java(version: str = "17") -> str | None:
    """Locate java.exe for `version` (e.g. "17", "8") under a JDKs dir.

    Looks for `temurin-{version}-jdk/**/bin/java.exe` first; falls back to
    any `*{version}*/bin/java.exe` for non-Temurin layouts.
    """
    for base in _candidate_jdk_dirs():
        if not os.path.isdir(base):
            continue
        # Preferred: Temurin layout
        hits = glob.glob(
            os.path.join(base, f"temurin-{version}-jdk", "**", "bin", "java.exe"),
            recursive=True)
        if hits: return hits[0]
        # Fallback: any layout containing the version number
        hits = glob.glob(
            os.path.join(base, f"*{version}*", "**", "bin", "java.exe"),
            recursive=True)
        if hits: return hits[0]
    return None


def assert_built() -> None:
    """Bail out with a clear message if PROBE / AGENT aren't built yet."""
    if not os.path.exists(PROBE) or not os.path.exists(AGENT):
        print(f"[FAIL] missing build artifacts at {os.path.dirname(PROBE)}",
              file=sys.stderr)
        print("       run: cmake --build cpp/build --config Release",
              file=sys.stderr)
        sys.exit(2)


def assert_target_built() -> None:
    """Bail out if tests/target/build/Target.class is missing."""
    if not os.path.exists(os.path.join(TGT_CP, "Target.class")):
        print(f"[FAIL] missing test classes at {TGT_CP}", file=sys.stderr)
        print("       run: bash tests/target/build-and-run.sh",
              file=sys.stderr)
        sys.exit(2)
