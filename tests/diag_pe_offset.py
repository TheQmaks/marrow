"""Diagnostic: trigger a Java exception via _invokeJC, see if the
direct-offset path detects it (vs falling through to JNI).

Test target: invoke Integer.parseInt('not a number') which throws
NumberFormatException. _invokeJC catches via SEH or pending-exception
detection; on success, returns "java_exception".

We can't directly observe which path detected the exception in JC,
but we CAN verify that _invokeJC correctly surfaces the error on
every JDK. If our new pending_exception_via_offset works, that's
the pure-memory path; if it doesn't, the JNI ExceptionCheck fallback
fires. Either way, we expect "java_exception" string.
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java  # noqa


JS = (
    "(function(){"
    "try {"
    "  var I = Java.use('java/lang/Integer');"
    "  var addr = Java._parseHex(I.parseInt.overload('(Ljava/lang/String;)I').address);"
    "  var oop = Java._jstring('not_a_number');"
    "  var r = Marrow._invokeJC(addr.lo, addr.hi, 'I', 'L', [oop]);"
    "  return 'jc=' + r;"
    "} catch (e) { return 'err:' + e; }"
    "})()"
)


def parse_reply(out):
    for ln in out.splitlines():
        if "[agent.reply]" in ln and "msg=" in ln:
            return ln.split("msg=", 1)[1].strip()
    return None


def main():
    jdk = os.environ.get("MARROW_TEST_JDK", "17")
    java = find_java(jdk)
    if not java: print(f"[SKIP] no JDK {jdk}"); return 0
    p = subprocess.Popen([java, "-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        ln = p.stdout.readline()
        if "PID:" in ln: pid = int(ln.split(":", 1)[1].strip()); break
    if not pid: p.kill(); return 1
    subprocess.run([PROBE, "inject", str(pid), AGENT],
                   capture_output=True, timeout=15)
    time.sleep(1.5)
    r = subprocess.run([PROBE, "agent", str(pid), "eval", JS],
                       capture_output=True, text=True, timeout=15)
    rep = parse_reply(r.stdout)
    p.kill()
    print(f"[JDK {jdk}] {rep}")
    if rep and "java_exception" in rep:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
