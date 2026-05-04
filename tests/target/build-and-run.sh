#!/usr/bin/env bash
# Compile Target.java + Callable.java + HotTarget.java with JDK 8 (lowest
# common denominator) and run Target under each JDK. By default just
# compiles + runs under JDK 21 for quick iteration; pass 'all' to smoke
# every JDK.
#
# JDK lookup: $MARROW_JDKS (env var) or <repo>/../jdks/temurin-{N}-jdk/.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)        # tests/target/
REPO=$(cd "$HERE/../.." && pwd)            # repo root
OUT="$HERE/build"
mkdir -p "$OUT"

JDK_BASE="${MARROW_JDKS:-$(cd "$REPO/.." && pwd)/jdks}"

JDK8=$(find "$JDK_BASE/temurin-8-jdk" -name javac.exe 2>/dev/null | head -1)
[ -z "$JDK8" ] && { echo "no javac for JDK 8 in $JDK_BASE"; exit 1; }
JDK8=$(dirname "$JDK8")

echo "Compiling with $JDK8/javac (target 1.8)"
"$JDK8/javac" -d "$OUT" -source 1.8 -target 1.8 \
    "$HERE/Target.java" "$HERE/Callable.java" "$HERE/HotTarget.java" || exit 1
echo "OK: $OUT/*.class"

jdks="${1:-21}"
[ "$jdks" = "all" ] && jdks="8 11 17 21 25"

for v in $jdks; do
  java=$(find "$JDK_BASE/temurin-${v}-jdk" -name java.exe -path "*/bin/*" 2>/dev/null | head -1)
  [ -z "$java" ] && { echo "[JDK $v] no java.exe"; continue; }
  echo
  echo "=== JDK $v: $java ==="
  timeout 3 "$java" -cp "$(cygpath -w "$OUT")" Target || true
done
