"""Live verification: .implementation handler receives Java.cast proxy
for L-typed args (no manual Java.cast required by the user).

Hooks Callable.strLen(String) and triggers it via _invokeJNI; inspects the
captured arg's shape inside the handler."""
import os
import subprocess
import sys
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java  # noqa: E402


JS = (
    "(function(){"
    "var T=Java.use('Target');"
    "var C=Java.use('Callable');"
    "var info={hooked:false,fired:0,argType:null,hasOop:null,argClass:null,oopValue:null,strViaCast:null};"
    "C.strLen.implementation=function(s){"
    "  info.fired++;"
    "  info.argType=typeof s;"
    "  info.hasOop=(s && s.$oop) ? true : false;"
    "  info.argClass=(s && s.$class) ? s.$class : null;"
    "  info.oopValue=(s && s.$oop) ? s.$oop : null;"
    "  try { info.strViaCast = (s && s.$oop) ? Java.toString(s.$oop) : 'no-oop'; }"
    "  catch (e) { info.strViaCast = 'err:' + e; }"
    "  return 999;"
    "};"
    "info.hooked=true;"
    "var oop=Marrow.readStaticRef(T.$klass,'displayName');"
    "info.passedOop=oop;"
    "var rv=Marrow._invokeJNI('Callable','strLen','(Ljava/lang/String;)I','I',[oop]);"
    "info.invokeResult=String(rv);"
    "return JSON.stringify(info);"
    "})()"
)


def parse_reply(out: str):
    for ln in out.splitlines():
        if "[agent.reply]" in ln and "msg=" in ln:
            return ln.split("msg=", 1)[1].strip()
    return None


def main():
    java = find_java("17")
    if not java:
        print("[SKIP] no JDK 17"); return 0
    p = subprocess.Popen([java, "-Xmx256m", "-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        line = p.stdout.readline()
        if line.startswith("Target PID:"):
            pid = int(line.split(":", 1)[1].strip()); break
    if not pid:
        print("[FAIL] could not start Target"); return 1
    print(f"Target PID = {pid}\n")

    subprocess.run([PROBE, "inject", str(pid), AGENT],
                   capture_output=True, timeout=15)
    time.sleep(1.5)

    r = subprocess.run([PROBE, "agent", str(pid), "eval", JS],
                       capture_output=True, text=True, timeout=20)
    raw = parse_reply(r.stdout)
    print(f"raw reply: {raw}\n")
    if raw:
        try:
            outer = json.loads(raw)
            data = json.loads(outer) if isinstance(outer, str) else outer
            print("Decoded handler observation:")
            print(json.dumps(data, indent=2))
            print()
            # Verdict
            ok = (
                data.get("fired", 0) >= 1
                and data.get("argType") == "object"
                and data.get("hasOop") is True
                and data.get("argClass") in ("java/lang/String", "java.lang.String")
            )
            print("VERDICT:", "AUTO-CAST WORKS" if ok else "AUTO-CAST BROKEN")
        except Exception as e:
            print(f"[parse error] {e}")
    p.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
