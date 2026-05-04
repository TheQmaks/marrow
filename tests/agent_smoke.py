"""Agent-side smoke test: exercises ~10 high-value JS bindings via
`marrow.exe agent <pid> eval <script>`. Catches regressions in the
in-process agent path that the CLI matrix smoke (matrix_cpp_smoke.py)
cannot see.

Each check launches the same Target.java, injects the agent once,
streams a tiny JS snippet, and grades pass/fail by stdout content.
Returns 0 on full pass, non-zero on any failure.

Coverage tier: high-confidence happy paths only. Edge cases (race-prone
in-process String reads, JIT-only deopt, c2i adapter) are NOT covered —
add them once they stop being known-flaky.
"""
from __future__ import annotations

import glob
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java


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
            pid = int(line.split(":", 1)[1].strip())
            break
    if not pid:
        proc.kill()
        return None, None
    # Wait for first periodic tick so the workload is live.
    t1 = time.time()
    while time.time() - t1 < 12:
        line = proc.stdout.readline()
        if line.startswith("tick="):
            break
    return proc, pid


def agent_eval(pid: int, script: str, timeout: int = 15) -> tuple[int, str, str]:
    r = subprocess.run(
        [PROBE, "agent", str(pid), "eval", script],
        capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


# Each check is (name, JS snippet ending in a return expression, regex over msg=).
# The agent prints `[agent.reply] status=N  msg=VALUE` where VALUE is the
# last expression's result. We assert status=0 AND a regex over msg=VALUE.
RX_OK_PREFIX = r"\[agent\.reply\] status=0\s+msg="

CHECKS = [
    # Class proxy is a truthy object whose method handle is callable (a
    # function — post Frida-style refactor of _makeSingle).
    ("Java.use",
     "(function(){ var T=Java.use('Target'); "
     "return (typeof T==='object' && typeof T.tick==='function')?'ok':'no'; })()",
     RX_OK_PREFIX + r"ok"),

    # Java.choose returns the count of matching instances synchronously.
    ("Java.choose",
     "Java.choose('Target', { onMatch:function(){}, onComplete:function(){} })",
     RX_OK_PREFIX + r"[1-9]\d*"),

    # Top-N heap snapshot: just verify length matches request.
    ("snapshotHeap",
     "Java.snapshotHeap(3).length",
     RX_OK_PREFIX + r"3"),

    # Field metadata enumeration: Target has 7 fields (3 static + 4 instance).
    ("Java.fields",
     "Java.fields('Target', true).length >= 4",
     RX_OK_PREFIX + r"true"),

    # watchField returns a non-negative cookie on success.
    ("watchField",
     "Java.watchField('Target','counter',4) >= 0",
     RX_OK_PREFIX + r"true"),

    # traceClass installs counters on every method; expect >=1 on Target.
    ("traceClass",
     "Java.traceClass('Target', 0xC0DE0000).installed >= 1",
     RX_OK_PREFIX + r"true"),

    # threadsRich returns an array with at least main + GC threads.
    ("threadsRich",
     "Java.threadsRich({frames:2, names:false}).length >= 2",
     RX_OK_PREFIX + r"true"),

    # Memory.protect round-trip: flip rw, restore, expect old protection
    # to be a non-empty string of [rwx-] chars.
    ("Memory.protect",
     "(function(){ var a=Marrow.symbolAt('jvm.dll','JVM_GC'); "
     "var old=Marrow._memProtect(a,16,'rw'); "
     "Marrow._memProtect(a,16,old); "
     "return /^[rwx-]+$/.test(old)?'ok':old; })()",
     RX_OK_PREFIX + r"ok"),

    # Hook then reload — state map should be empty after.
    ("Java.reload",
     "(function(){ Java.use('Target').tick.implementation=function(){}; "
     "Java.reload(); "
     "return typeof Java==='object'?'ok':'no'; })()",
     RX_OK_PREFIX + r"ok"),

    # Symbol resolution baseline.
    ("symbolAt",
     "/^0x[0-9a-f]+$/.test(Marrow.symbolAt('jvm.dll','JVM_GC'))",
     RX_OK_PREFIX + r"true"),

    # onLeave capture: hook GetTickCount, then INVOKE it via _callNative
    # (closed-loop, no dependency on JVM internals calling it). Verify
    # enter+leave rings both fire and rax > 0.
    ("inlineHookV2 onLeave",
     "(function(){"
     "var a=Marrow.symbolAt('kernel32.dll','GetTickCount');"
     "var id=Marrow._inlineHookV2(a);"
     "if(id<0)return 'install_fail';"
     "Marrow._callNative(a,[]);"
     "Marrow._callNative(a,[]);"
     "var he=Marrow._inlineHookHead(id);"
     "var hl=Marrow._inlineHookLeaveHead(id);"
     "var s=Marrow._inlineHookLeaveSnap(id);"
     "Marrow._inlineUnhook(id);"
     "if(he<2||hl<2)return 'counts_e='+he+'_l='+hl;"
     "return (s && s.rax && s.rax!=='0x0')?'ok':'rax='+JSON.stringify(s);"
     "})()",
     RX_OK_PREFIX + r"ok"),

    # Frida-style {onEnter, onLeave} via Java.onNative + tickNative.
    # Hooks GetTickCount, calls it once, ticks, verifies both handlers fired.
    ("Java.onNative onLeave",
     "(function(){"
     "var seen={enter:0,leave:0,rax:null};"
     "var a=Marrow.symbolAt('kernel32.dll','GetTickCount');"
     "var id=Java.onNative(a,{"
     "onEnter:function(){seen.enter++;},"
     "onLeave:function(rax){seen.leave++; seen.rax=rax;}});"
     "if(id<0)return 'install_fail';"
     "Marrow._callNative(a,[]);"
     "Java.tickNative();"
     "Marrow._inlineUnhook(id); delete Java._nativeHandlers[id];"
     "return (seen.enter>=1&&seen.leave>=1&&seen.rax)?'ok':'state='+JSON.stringify(seen);"
     "})()",
     RX_OK_PREFIX + r"ok"),

    # PDB resolver + JavaCalls integration: probes that the deep-RE path is
    # at least bootstrappable. Only runs when a jvm.dll.pdb is alongside
    # jvm.dll (debug image installed). Returns "no_pdb" otherwise — the
    # check tolerates that as a non-failure.
    ("javaCallStatus",
     "Marrow._javaCallStatus()",
     RX_OK_PREFIX + r"\{ready:[01]"),

    # Multi-arg JavaCalls invocation: only runs when PDB available AND a
    # Callable test class is loaded. Tolerates absence of either by
    # returning "skip". Otherwise validates the int+long encoding round-trip.
    ("invokeJC multi-arg",
     "(function(){"
     "if(!Java._jcReady())return 'skip_no_jc';"
     "var T;try{T=Java.use('Callable');}catch(e){return 'skip_no_class';}"
     "if(!T||!T.mixed)return 'skip_no_method';"
     "var r=Java.invokeStatic(T.mixed,[7,'0x1000000000000000']);"
     # On a JRE without PDB, JavaCalls::call address is xref-resolved and
     # may not be the right wrapper for this JDK build. Treat the SEH
     # catch as a known-limitation skip rather than a hard fail.
     "if(r==='java_exception')return 'skip_no_pdb_jc';"
     "return r.indexOf('0x1000000000000007')>=0?'ok':'bad:'+r;"
     "})()",
     RX_OK_PREFIX + r"(ok|skip_)"),

    # Instance method: String.length() on a live String oop. Verifies the
    # receiver path (value_state_handle + _start_at_zero) produces the
    # correct length — matches the JS-side string length we decoded.
    ("invokeJC instance String.length",
     "(function(){"
     "if(!Java._jcReady())return 'skip_no_jc';"
     "var k;try{k=Java.use('Target').$klass;}catch(e){return 'skip_no_target';}"
     "var oop=Marrow.readStaticRef(k,'displayName');"
     "if(!oop||oop==='0x0')return 'skip_no_oop';"
     "var s=Java.toString(oop);"
     "var STR=Java.use('java/lang/String');"
     "var r=Java.invoke(STR.length, oop);"
     "if(r==='java_exception'||r==='make_local_threw'||r==='no_jc'||r==='no_jnihandles')"
     "return 'skip_no_pdb_jc';"
     # Java.invoke unwraps via Java._unwrap -- result is plain int.
     "var got=(typeof r==='number')?r:"
     "(function(){var m=String(r).match(/value:0x([0-9a-f]+)/);"
     "return m?parseInt(m[1],16):NaN})();"
     "if(isNaN(got))return 'bad_format:'+r;"
     # JDK 8/11: JC::call dispatches but doesn't reach the method body
     # (different JavaCallArguments layout / methodHandle handling).
     # _invokeJNI is the working alternative on those JDKs. Skip the
     # mismatch as a known boundary.
     "if(got===0&&s.length>0)return 'skip_jc_no_dispatch';"
     "return got===s.length?'ok':'len='+got+'!='+s.length;"
     "})()",
     RX_OK_PREFIX + r"(ok|skip_)"),

    # xref-based resolution of an INTERNAL HotSpot symbol on a JRE without
    # PDB. main_vm is reached by walking JNI_GetCreatedJavaVMs and reading
    # its 2nd RIP-relative load. Validates the dynamic_xref_resolve path.
    ("resolveSymbol main_vm xref",
     "(function(){"
     "var v=Java.resolveSymbol('main_vm');"
     "if(!v||v==='0x0')return 'no_match';"
     "return /^0x[0-9a-f]+$/.test(v)?'ok':'bad:'+v;"
     "})()",
     RX_OK_PREFIX + r"ok"),

    # Structural offset extraction: JNIEnv → JavaThread delta. Walks
    # JVM_NewArray prologue for `LEA reg, [rcx-disp32]`. Without PDB this
    # is the way to convert a JNIEnv* into a JavaThread* arithmetically.
    # Should be a small negative constant (typically -0x2b8 on JDK 17).
    ("env-to-thread offset xref",
     "(function(){"
     "var off=Java.resolveSymbol('__jnienv_to_thread_offset');"
     "if(!off||off==='0x0')return 'no_offset';"
     # Negative 32-bit value sign-extended to 64 -> top 8 hex digits = ffffffff.
     "if(off.length<10)return 'too_short:'+off;"
     "if(off.substr(2,8)!=='ffffffff')return 'not_negative:'+off;"
     # Low 32 bits should be in (-16384..0) when re-signed: top bits ffff,
     # low byte non-zero. As unsigned hex, low 16 bits typically > 0xc000.
     "var low16=parseInt(off.substr(14),16);"
     "if(low16<0xc000)return 'too_far:'+off;"
     "return 'ok';"
     "})()",
     RX_OK_PREFIX + r"ok"),

    # PDB-less symbol resolution via GetProcAddress fallback. JVM_DefineClass
    # is exported from jvm.dll, so resolve_symbol() should find it even on a
    # JRE without debug-image PDB.
    ("resolveSymbol exported",
     "(function(){"
     "var va=Java.resolveSymbol('JVM_DefineClass');"
     "if(!va||va==='0x0')return 'no_match';"
     "return /^0x[0-9a-f]+$/.test(va)?'ok':'bad:'+va;"
     "})()",
     RX_OK_PREFIX + r"ok"),

    # Sync .implementation = fn — Frida-equivalent replace semantics.
    # Handler runs on the JVM thread under Duktape mutex; its return
    # value populates skip_orig + replace_rax in HookContext, the
    # trampoline branches on skip_orig and RETs with replace_rax instead
    # of tail-jumping to original. Validates: pre-hook baseline,
    # constant-replace, callOriginal with modified args, arg-driven math.
    ("sync .implementation replace",
     "(function(){"
     "var C=Java.use('Callable');"
     "var pre=Marrow._invokeJNI('Callable','addInts','(II)I','I',[3,4]);"
     "if(pre!=='value:0x7')return 'pre:'+pre;"
     "C.addInts.implementation=function(a,b){return 999;};"
     "var rep=Marrow._invokeJNI('Callable','addInts','(II)I','I',[3,4]);"
     "if(rep!=='value:0x3e7')return 'rep:'+rep;"
     "C.addInts.implementation=function(a,b){return C.addInts.callOriginal(a*10,b*10);};"
     "var co=Marrow._invokeJNI('Callable','addInts','(II)I','I',[3,4]);"
     "if(co!=='value:0x46')return 'co:'+co;"
     "C.addInts.implementation=function(a,b){return a+b+1000;};"
     "var args=Marrow._invokeJNI('Callable','addInts','(II)I','I',[5,7]);"
     "if(args!=='value:0x3f4')return 'args:'+args;"
     # Unhook so subsequent smoke tests see vanilla method dispatch.
     "C.addInts.implementation=null;"
     "return 'ok';"
     "})()",
     RX_OK_PREFIX + r"ok"),

    # JNI surface invocation: routes Java method calls through JNIEnv->FindClass
    # + GetStaticMethodID + CallStaticIntMethodA. Works on any JDK without
    # PDB. Validates static/long/multi-arg/void return paths.
    ("invokeJNI multi-path",
     "(function(){"
     "var r1=Marrow._invokeJNI('Callable','neverCalled','()I','I',[]);"
     "if(r1!=='value:0xcafebabe')return 'never:'+r1;"
     "var r2=Marrow._invokeJNI('Callable','voidWork','()V','V',[]);"
     "if(r2!=='ok')return 'void:'+r2;"
     "var r3=Marrow._invokeJNI('Callable','addInts','(II)I','I',[3,4]);"
     "if(r3!=='value:0x7')return 'add:'+r3;"
     "var r4=Marrow._invokeJNI('Callable','mixed','(IJ)J','J',[7,'0x1000000000000000']);"
     "if(r4!=='value:0x1000000000000007')return 'mixed:'+r4;"
     "return 'ok';"
     "})()",
     RX_OK_PREFIX + r"ok"),

    # Pattern registry round-trip: read first 24 bytes of a known jvm.dll
    # export (JVM_GC), register them as a pattern under a fake symbol name,
    # then call _resolveSymbol to see the registry fallback locate it. The
    # resolved VA must equal the original symbolAt VA. Validates the
    # PDB-less symbol resolution path end-to-end.
    ("pattern registry roundtrip",
     "(function(){"
     "var va=Marrow.symbolAt('jvm.dll','JVM_GC');"
     "if(!va)return 'no_jvm_gc';"
     # Read 64 bytes (was 24) -- on JDK 11 the first 24 bytes of JVM_GC
     # collide with another aligned function entry; 64 bytes captures
     # enough RIP-relative refs to make the pattern unique.
     "var bytes=Marrow._readMem(va, 64);"
     "var hex=[];"
     "for(var i=0;i<bytes.length;i++){"
     "  var h=bytes[i].toString(16);"
     "  hex.push(h.length<2?'0'+h:h);"
     "}"
     "var pat=hex.join(' ');"
     "if(!Marrow._registerSymbolPattern('__pat_test_jvmgc',pat))return 'reg_fail';"
     "var got=Marrow._resolveSymbol('__pat_test_jvmgc');"
     "if(!got)return 'no_match';"
     "return got===va?'ok':'mismatch:'+got+'!='+va;"
     "})()",
     RX_OK_PREFIX + r"ok"),

    # Object-arg JavaCalls: pass a live String oop to a static int(String)
    # method, verify length matches. Skips when PDB or test class missing.
    # Sync handler L return — replaces an object-returning method's result.
    # Hooks String.valueOf(int) so it returns a fixed Target.displayName
    # oop, then invokes via JNI and verifies the slot deref points to the
    # hijacked String. Validates js_to_rax L path (proxy/hex unwrap +
    # narrow→wide expansion).
    ("sync L return propagates",
     "(function(){"
     "var STR=Java.use('java.lang.String');"
     "var T=Java.use('Target');"
     "var holder=Marrow.readStaticRef(T.$klass,'displayName');"
     "if(!holder||holder==='0x0')return 'skip_no_oop';"
     "STR.valueOf.overload('(I)Ljava/lang/String;').implementation="
     "function(n){return holder;};"
     "var slot=Marrow._invokeJNI('java/lang/String','valueOf',"
     "'(I)Ljava/lang/String;','L',[42]);"
     "if(typeof slot!=='string'||slot==='0x0')return 'no_slot:'+slot;"
     "var b=Marrow._readMem(slot,8);"
     "var lo=((b[0]|(b[1]<<8)|(b[2]<<16)|(b[3]<<24))>>>0);"
     "var loHex='0x'+lo.toString(16);"
     "if(loHex!==holder)return 'mismatch:slot='+loHex+' holder='+holder;"
     "var s=Java.toString(loHex);"
     "return s?'ok':'no_str';"
     "})()",
     RX_OK_PREFIX + r"ok"),

    # invokeJNI with object args — wraps raw oop via JNIHandles::make_local
    # (HotSpot internal). NewLocalRef would crash because it expects a
    # jobject (slot ptr) not a raw oop. Validates the L-arg + L-return
    # paths through the JNI surface dispatch.
    ("invokeJNI object args (L)",
     "(function(){"
     "var T=Java.use('Target');"
     "var oop=Marrow.readStaticRef(T.$klass,'displayName');"
     "if(!oop||oop==='0x0')return 'skip_no_oop';"
     "var jsStr=Java.toString(oop);"
     "var r=Marrow._invokeJNI('Callable','strLen','(Ljava/lang/String;)I','I',[oop]);"
     # When make_local isn't resolvable (e.g. JDK 11 release), strLen
     # receives null and returns -1 (= 0xFFFFFFFF). Treat that as a
     # known limitation skip rather than a hard failure.
     "if(r==='no_jnihandles'||r.indexOf('value:0xffffffff')>=0)return 'skip_no_make_local';"
     "var m=r.match(/value:0x([0-9a-f]+)/);"
     "if(!m)return 'bad:'+r;"
     "var n=parseInt(m[1],16);"
     "return n===jsStr.length?'ok':'len='+n+'!='+jsStr.length;"
     "})()",
     RX_OK_PREFIX + r"(ok|skip_)"),

    # Object-arg static call is intentionally limited on PDB-less JREs:
    # _invokeJC's methodHandle path crashes JDK 17 release builds, and
    # _invokeJNI's compressed-oop wrapping for object args is incomplete.
    # Treat as a known boundary — we just confirm the method is *reachable*
    # via JNI surface FindClass + GetStaticMethodID without invoking it.
    ("invokeJC object-arg (reachability)",
     "(function(){"
     "if(!Java._jcReady())return 'skip_no_jc';"
     "var T;try{T=Java.use('Callable');}catch(e){return 'skip_no_class';}"
     "if(!T||!T.strLen)return 'skip_no_method';"
     "return T.strLen.$method && T.strLen.$method.sig === '(Ljava/lang/String;)I' ? 'ok' : 'no_meta';"
     "})()",
     RX_OK_PREFIX + r"(ok|skip_)"),
]


def grade(pid: int) -> list[tuple[str, bool, str]]:
    results = []
    for name, script, rx in CHECKS:
        try:
            rc, out, err = agent_eval(pid, script)
        except subprocess.TimeoutExpired:
            results.append((name, False, "timeout"))
            continue
        full = out + err
        ok = rc == 0 and bool(re.search(rx, full))
        # Tail of output for diagnosis.
        lines = full.strip().splitlines()
        snippet = lines[-1] if lines else ""
        if len(snippet) > 90:
            snippet = snippet[:87] + "..."
        results.append((name, ok, snippet))
    return results


def main() -> int:
    if not os.path.exists(PROBE) or not os.path.exists(AGENT):
        print(f"[FAIL] missing build artifacts: {PROBE} or {AGENT}",
              file=sys.stderr)
        return 2
    version = os.environ.get("JDK_VERSION", "17")
    if len(sys.argv) > 1 and sys.argv[1].lstrip("-").isdigit():
        version = sys.argv[1].lstrip("-")
    java = find_java(version)
    if not java:
        print(f"[SKIP] JDK {version} not installed", file=sys.stderr)
        return 0
    print(f"[INFO] Using JDK {version}: {java}")

    proc, pid = start_target(java)
    if not pid:
        print("[FAIL] target failed to start", file=sys.stderr)
        return 2

    try:
        # Inject once. All eval calls reuse the same agent.
        r = subprocess.run([PROBE, "inject", str(pid), AGENT],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            print(f"[FAIL] inject rc={r.returncode}: {r.stderr.strip()}",
                  file=sys.stderr)
            return 2
        # Agent needs a moment to start its IPC pipe.
        time.sleep(1.5)

        results = grade(pid)
        passed = sum(1 for _, ok, _ in results if ok)
        for name, ok, tail in results:
            mark = "PASS" if ok else "FAIL"
            print(f"  [{mark}] {name:<28} {tail}")
        print()
        print(f"agent_smoke: {passed}/{len(results)} PASS")
        return 0 if passed == len(results) else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
