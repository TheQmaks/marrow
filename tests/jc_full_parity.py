"""Full parity test for _invokeJC after PDB-less JC::call identification.

Uses dynamic verification (try each structural match, pick one that returns
correct value). Then runs full primitive + L args + receiver tests.

Goal: prove _invokeJC works on JRE without PDB once JC::call is identified.
"""

import os
import subprocess
import time
import json
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java

SLOTS = {
    "CallStaticObjectMethodA": 116,
    "CallStaticBooleanMethodA": 119,
    "CallStaticIntMethodA":    131,
    "CallStaticLongMethodA":   134,
    "CallStaticVoidMethodA":   143,
}

# Stage 1: identify candidates structurally.
JS_FIND_CANDS = """(function(){
    var slots = SLOTS_JSON;
    var entries = {};
    for (var k in slots) entries[k] = Marrow._jniVtableSlot(slots[k]);
    function gather(va, maxd) {
        var v = {};
        var q = [{va:va, d:0}];
        while (q.length) {
            var n = q.shift();
            if (v[n.va] !== undefined) continue;
            if (n.d > maxd) continue;
            v[n.va] = n.d;
            if (n.d === maxd) continue;
            var sc = Marrow._xrefScan(n.va, 256);
            for (var i = 0; i < sc.calls.length; i++)
                if (v[sc.calls[i]] === undefined)
                    q.push({va:sc.calls[i], d:n.d+1});
        }
        return v;
    }
    var maps = {};
    for (var k in entries)
        if (typeof entries[k] === "string" && entries[k].indexOf("0x") === 0)
            maps[k] = gather(entries[k], 4);
    var keys = Object.keys(maps);
    var first = maps[keys[0]];
    var d1 = {}, d2 = [], d3 = {};
    for (var va in first) {
        var depths = [first[va]];
        var ok = true;
        for (var i = 1; i < keys.length; i++) {
            if (maps[keys[i]][va] === undefined) { ok = false; break; }
            depths.push(maps[keys[i]][va]);
        }
        if (!ok) continue;
        var aE1=true,aE2=true,aE3=true;
        for (var j = 0; j < depths.length; j++) {
            if (depths[j] !== 1) aE1 = false;
            if (depths[j] !== 2) aE2 = false;
            if (depths[j] !== 3) aE3 = false;
        }
        if (aE1) d1[va] = true;
        if (aE2) d2.push(va);
        if (aE3) d3[va] = true;
    }
    var matches = [];
    for (var i = 0; i < d2.length; i++) {
        var va = d2[i];
        var sc = Marrow._xrefScan(va, 64);
        if (sc.calls.length !== 1) continue;
        if (sc.stopReason !== "ret") continue;
        if (sc.insnsWalked > 20) continue;
        if (!d3[sc.calls[0]]) continue;
        matches.push(va);
    }
    return JSON.stringify({matches:matches});
})()""".replace("SLOTS_JSON", json.dumps(SLOTS))

# Stage 2: try each candidate with _invokeJC for Callable.neverCalled.
# Returns True if value=0xcafebabe.
JS_VERIFY_ONE = """(function(){
    var T = Java.use("Callable");
    var h = T.neverCalled;
    var addr = Java._parseHex(h.address);
    var prev = Marrow._setJavaCallsCall("CAND_VA");
    var r;
    try { r = Marrow._invokeJC(addr.lo, addr.hi, "I"); }
    catch (e) { r = "throw:" + (e.message||e); }
    Marrow._setJavaCallsCall(prev);
    return JSON.stringify({result:r});
})()"""

# Stage 3: full parity tests once JC is set.
JS_PARITY = """(function(){
    Marrow._setJavaCallsCall("WINNER_VA");
    var T = Java.use("Callable");
    var out = {};
    function rec(label, fn) {
        try { out[label] = "" + fn(); }
        catch (e) { out[label] = "threw:" + (e.message||e); }
    }
    rec("neverCalled_int",  function(){
        var h = T.neverCalled; var a = Java._parseHex(h.address);
        return Marrow._invokeJC(a.lo, a.hi, "I");
    });
    rec("addInts",  function(){
        var h = T.addInts; var a = Java._parseHex(h.address);
        return Marrow._invokeJC(a.lo, a.hi, "I", "II", [7, 11]);
    });
    rec("voidNever", function(){
        var h = T.voidNever; var a = Java._parseHex(h.address);
        return Marrow._invokeJC(a.lo, a.hi, "V");
    });
    rec("alsoNever_long", function(){
        var h = T.alsoNever; var a = Java._parseHex(h.address);
        return Marrow._invokeJC(a.lo, a.hi, "J");
    });
    rec("mulLong",  function(){
        var h = T.mulLong; var a = Java._parseHex(h.address);
        return Marrow._invokeJC(a.lo, a.hi, "J", "JJ", ["100","200"]);
    });
    rec("addDoubles", function(){
        var h = T.addDoubles; var a = Java._parseHex(h.address);
        // Encode 1.5 and 2.5 as IEEE754 hex strings.
        var b1 = new ArrayBuffer(8); var v1 = new DataView(b1);
        v1.setFloat64(0, 1.5, true);
        var hi1 = v1.getUint32(4, true), lo1 = v1.getUint32(0, true);
        var hex1 = "0x" + ((hi1>>>0).toString(16)) +
                   ((lo1>>>0).toString(16).padStart(8,'0'));
        var b2 = new ArrayBuffer(8); var v2 = new DataView(b2);
        v2.setFloat64(0, 2.5, true);
        var hi2 = v2.getUint32(4, true), lo2 = v2.getUint32(0, true);
        var hex2 = "0x" + ((hi2>>>0).toString(16)) +
                   ((lo2>>>0).toString(16).padStart(8,'0'));
        return Marrow._invokeJC(a.lo, a.hi, "D", "DD", [hex1, hex2]);
    });
    return JSON.stringify(out);
})()"""


def start():
    java = find_java("17")
    if not java: raise RuntimeError("no JDK 17 installed")
    p = subprocess.Popen([java, "-Xmx256m", "-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        line = p.stdout.readline()
        if line.startswith("Target PID:"):
            pid = int(line.split(":", 1)[1].strip()); break
    subprocess.run([PROBE, "inject", str(pid), AGENT],
                   capture_output=True, timeout=15)
    time.sleep(1.5)
    return p, pid


def run_eval(pid, js, timeout=15):
    try:
        r = subprocess.run([PROBE, "agent", str(pid), "eval", js],
                           capture_output=True, text=True, timeout=timeout)
        for L in r.stdout.splitlines():
            if "[agent.reply]" in L: return L
        return r.stdout
    except subprocess.TimeoutExpired:
        return "TIMEOUT"


def parse_msg(line):
    m = re.search(r'msg=({.*})', line, re.DOTALL)
    return json.loads(m.group(1)) if m else None


def main():
    # Step 1: find candidates (one short JVM session).
    p, pid = start()
    out = run_eval(pid, JS_FIND_CANDS)
    d = parse_msg(out) or {}
    cands = d.get("matches", [])
    p.kill(); time.sleep(0.3)
    print(f"Structural candidates for JC::call: {cands}")

    # Step 2: dynamically verify each (independent JVMs since some crash).
    winner = None
    for va in cands:
        p, pid = start()
        out = run_eval(pid, JS_VERIFY_ONE.replace("CAND_VA", va), timeout=10)
        if out == "TIMEOUT":
            print(f"  {va}: HANG"); p.kill(); time.sleep(0.3); continue
        info = parse_msg(out) or {}
        result = info.get("result", "?")
        if "0xcafebabe" in result.lower():
            winner = va
            print(f"  {va}: {result} *WINNER*")
            p.kill(); break
        else:
            print(f"  {va}: {result}")
            p.kill()
        time.sleep(0.3)

    if not winner:
        print("FAIL: no candidate verified as JC::call")
        return

    print(f"\n=== JavaCalls::call = {winner} ===")

    # Step 3: full parity tests in a fresh JVM.
    p, pid = start()
    out = run_eval(pid, JS_PARITY.replace("WINNER_VA", winner), timeout=20)
    info = parse_msg(out) or {"raw": out[:300]}
    print("\n== Parity tests ==")
    expected = {
        "neverCalled_int": "0xcafebabe",
        "addInts":         "0x12",  # 7+11=18
        "voidNever":       "type:14",  # T_VOID
        "alsoNever_long":  "0xdeadbeefcafebabe",
        "mulLong":         "0x4e20",  # 100*200=20000
    }
    for k, v in info.items():
        s = str(v).lower()
        marker = ""
        exp = expected.get(k)
        if exp:
            if exp in s: marker = " *OK*"
            else: marker = f" *MISMATCH (expected {exp})*"
        print(f"  {k}: {v}{marker}")
    p.kill()


if __name__ == "__main__":
    main()
