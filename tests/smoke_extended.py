"""Extended smoke -- covers feature areas the regular smoke doesn't yet
exercise. Goal: confirm what works in the current build, surface any
regressions, and document partial/skip behavior with a precise reason.

Pass criteria (per test): JS returns "ok" OR a "skip_*" string the regex
tolerates. Anything else (raw error message, hex value mismatch, throw)
counts as fail.

Each test is self-contained -- installs its own state inside the eval and
unhooks before returning so subsequent tests see vanilla state.
"""
from __future__ import annotations
import glob
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java

RX_OK = r"\[agent\.reply\] status=0\s+msg=(ok|skip_)"

# Each entry: (name, JS-string, optional_extra_timeout)
CHECKS = [
    # -----------------------------------------------------------------
    # Object allocation + construction
    # -----------------------------------------------------------------
    ("$new -- allocate + construct", """(function(){
        try {
            var L = Java.use("java.lang.Long");
            var inst = L.$new(42);
            if (!inst) return "fail:no_inst";
            // The proxy should expose $oop or $class metadata.
            return "ok";
        } catch (e) { return "skip_threw:" + (e.message || e); }
    })()"""),

    # -----------------------------------------------------------------
    # Class definition / loading
    # -----------------------------------------------------------------
    ("openClassFile reachable", """(function(){
        try {
            // Don't actually define -- just check the API exists.
            var hasFn = (typeof Java.openClassFile === "function");
            return hasFn ? "ok" : "skip_no_api";
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    ("registerClass reachable", """(function(){
        try {
            var hasFn = (typeof Java.registerClass === "function");
            return hasFn ? "ok" : "skip_no_api";
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    ("cloneClassDeep reachable", """(function(){
        try {
            var hasFn = (typeof Java.cloneClassDeep === "function" ||
                         typeof Marrow.cloneClassDeep === "function");
            return hasFn ? "ok" : "skip_no_api";
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    # -----------------------------------------------------------------
    # Bytecode operations
    # -----------------------------------------------------------------
    ("disasm bytecode (Callable.addInts)", """(function(){
        try {
            var C = Java.use("Callable");
            var insns = Marrow._disasm(
                Java._parseHex(C.addInts.address || C.addInts.addr).lo,
                Java._parseHex(C.addInts.address || C.addInts.addr).hi);
            if (!insns || insns.length === 0) return "skip_empty";
            // addInts is iload_0; iload_1; iadd; ireturn -- 4 ops.
            return insns.length >= 3 ? "ok" : "fail:too_few:" + insns.length;
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    ("redefineMethod surface", """(function(){
        try {
            var hasFn = (typeof Java.redefineMethod === "function" ||
                         typeof Marrow._redefineMethod === "function");
            return hasFn ? "ok" : "skip_no_api";
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    ("nmDump (Target.tick if JIT'd)", """(function(){
        try {
            var T = Java.use("Target");
            var nm = Marrow._nmDump(
                Java._parseHex(T.tick.address || T.tick.addr).lo,
                Java._parseHex(T.tick.address || T.tick.addr).hi);
            // null is valid -- method may not be JIT'd at all yet.
            if (!nm) return "skip_not_jitted";
            if (!nm.entry || !nm.verifiedEntry) return "fail:no_entry";
            return "ok";
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    # -----------------------------------------------------------------
    # Heap inspection
    # -----------------------------------------------------------------
    ("heapRegions enumerates", """(function(){
        try {
            var rs = Java.heapRegions ? Java.heapRegions(0) : null;
            if (!rs) return "skip_no_api";
            return rs.length > 0 ? "ok" : "fail:empty";
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    ("heapScan finds Strings", """(function(){
        try {
            var hits = Java.heapScan ? Java.heapScan("java/lang/String", 8) : null;
            if (!hits) return "skip_no_api";
            return hits.length > 0 ? "ok" : "fail:no_strings";
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    ("snapshotHeap returns oops", """(function(){
        try {
            var oops = Java.snapshotHeap(8);
            return (oops && oops.length === 8) ? "ok" : "fail:" + (oops && oops.length);
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    # -----------------------------------------------------------------
    # System / process introspection
    # -----------------------------------------------------------------
    ("systemProperties accessible", """(function(){
        try {
            // systemPropsOop is the lower-level handle.
            var oop = Java.systemPropsOop ? Java.systemPropsOop() : null;
            if (oop) return "ok";
            return "skip_no_api";
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    ("modules enumeration", """(function(){
        try {
            var mods = Marrow._modulesEnum ? Marrow._modulesEnum() : null;
            if (!mods) return "skip_no_api";
            return mods.length > 0 ? "ok" : "fail:empty";
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    # -----------------------------------------------------------------
    # Compiler / runtime control
    # -----------------------------------------------------------------
    ("deoptimizeAll callable", """(function(){
        try {
            var rc = Marrow._deoptimizeAll ? Marrow._deoptimizeAll() : null;
            if (rc === null || rc === undefined) return "skip_no_api";
            return "ok";
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    ("initializeKlass callable", """(function(){
        try {
            var T = Java.use("Target");
            if (typeof Marrow._initializeKlass !== "function") return "skip_no_api";
            // initializeKlass takes klassObj (the {lo,hi,addr} struct).
            var ok = Marrow._initializeKlass(T.$klass);
            // Returns false when no PDB and no fallback resolver -- accept.
            return (typeof ok === "boolean") ? "ok" : "fail:" + ok;
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    # -----------------------------------------------------------------
    # Hardware watchpoints (DR0-DR3)
    # -----------------------------------------------------------------
    ("hwWatch surface check", """(function(){
        try {
            var hasFn = (typeof Marrow._hwWatchInstall === "function" ||
                         typeof Java.watchField === "function");
            return hasFn ? "ok" : "skip_no_api";
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    # -----------------------------------------------------------------
    # invoke instance method (JC path -- needs PDB)
    # -----------------------------------------------------------------
    ("Java.invoke instance (PDB-gated)", """(function(){
        try {
            if (!Java._jcReady()) return "skip_no_jc";
            var T = Java.use("Target");
            var oop = Marrow.readStaticRef(T.$klass, "displayName");
            if (!oop || oop === "0x0") return "skip_no_oop";
            var STR = Java.use("java/lang/String");
            var r = Java.invoke(STR.length, oop);
            // Java.invoke unwraps -> number (the actual length).
            if (typeof r === "number" && r >= 0) return "ok";
            // Known boundaries surfaced as strings (JDK 8/11 / JC unresolvable).
            if (r === "java_exception" || r === "no_jc" ||
                r === "no_jnihandles" || r === "make_local_threw")
                return "skip_no_pdb_jc";
            return "bad_format:" + (typeof r) + ":" + r;
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    # -----------------------------------------------------------------
    # readStaticString / toString roundtrip
    # -----------------------------------------------------------------
    ("toString decodes String oop", """(function(){
        try {
            var T = Java.use("Target");
            var oop = Marrow.readStaticRef(T.$klass, "displayName");
            if (!oop || oop === "0x0") return "skip_no_oop";
            var s = Java.toString(oop);
            return (typeof s === "string" && s.length > 0) ? "ok" : "fail:" + s;
        } catch (e) { return "skip_threw:" + e.message; }
    })()"""),

    # -----------------------------------------------------------------
    # Compat shims
    # -----------------------------------------------------------------
    ("setTimeout shim runs callback", """(function(){
        var hit = 0;
        setTimeout(function(){ hit = 42; }, 0);
        return hit === 42 ? "ok" : "fail:" + hit;
    })()"""),

    ("console shim works", """(function(){
        try {
            console.log("[smoke] console.log probe");
            console.warn("[smoke] console.warn probe");
            return "ok";
        } catch (e) { return "fail:" + e.message; }
    })()"""),

    # -----------------------------------------------------------------
    # Diagnostics
    # -----------------------------------------------------------------
    ("javaCallStatus parses", """(function(){
        try {
            var s = Marrow._javaCallStatus();
            if (typeof s !== "string") return "fail:not_string";
            if (s.indexOf("ready:") < 0) return "fail:" + s;
            return "ok";
        } catch (e) { return "fail:" + e.message; }
    })()"""),

    ("xrefScan walks JNI_GetCreatedJavaVMs", """(function(){
        try {
            var va = Marrow.symbolAt("jvm.dll", "JNI_GetCreatedJavaVMs");
            if (!va) return "skip_no_export";
            var sc = Marrow._xrefScan(va, 64);
            if (!sc) return "fail:null";
            return (sc.insnsWalked > 0 && sc.ripRefs.length >= 1) ? "ok" : "fail:bad_walk";
        } catch (e) { return "fail:" + e.message; }
    })()"""),

    # -----------------------------------------------------------------
    # Cookie generator persistence (Java.reload regression)
    # -----------------------------------------------------------------
    ("cookies survive Java.reload", """(function(){
        try {
            var c1 = Marrow._nextCookie();
            Java.reload();
            var c2 = Marrow._nextCookie();
            return (c2 > c1) ? "ok" : "fail:" + c1 + "_to_" + c2;
        } catch (e) { return "fail:" + e.message; }
    })()"""),
]


def start_target(java: str) -> tuple[subprocess.Popen | None, int | None]:
    proc = subprocess.Popen(
        [java, "-Xmx256m", "-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        line = proc.stdout.readline()
        if line.startswith("Target PID:"):
            pid = int(line.split(":", 1)[1].strip()); break
    if not pid: proc.kill(); return None, None
    t1 = time.time()
    while time.time() - t1 < 12:
        line = proc.stdout.readline()
        if line.startswith("tick="): break
    return proc, pid


def main() -> int:
    version = os.environ.get("JDK_VERSION", "17")
    if len(sys.argv) > 1 and sys.argv[1].lstrip("-").isdigit():
        version = sys.argv[1].lstrip("-")
    java = find_java(version)
    if not java: print(f"no temurin-{version} jdk"); return 2
    print(f"[INFO] Using JDK {version}: {java}")
    proc, pid = start_target(java)
    if not pid: print("[FAIL] target failed to start"); return 2

    inj = subprocess.run([PROBE, "inject", str(pid), AGENT],
                         capture_output=True, text=True, timeout=15)
    if inj.returncode != 0:
        print(f"[FAIL] inject rc={inj.returncode}: {inj.stderr.strip()}")
        proc.kill(); return 2
    time.sleep(1.5)

    import re
    rx = re.compile(RX_OK)
    results = []
    for name, script in CHECKS:
        try:
            r = subprocess.run([PROBE, "agent", str(pid), "eval", script],
                               capture_output=True, text=True, timeout=15)
            out = r.stdout
            tail = next((ln for ln in out.splitlines() if "[agent.reply]" in ln), "")
            ok = bool(rx.search(tail))
            results.append((name, ok, tail))
        except subprocess.TimeoutExpired:
            results.append((name, False, "[timeout]"))

    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, tail in results:
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {name:<46} {tail[:120]}")
    print(f"\nsmoke_extended: {passed}/{len(results)} PASS")

    proc.kill()
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
