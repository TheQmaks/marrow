"""Dump all Method fields exposed via vmStructs for the running JDK."""
import os, sys, subprocess, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java  # noqa


JS = (
    "(function(){"
    "var t = Marrow._dumpType('Method');"
    "if (!t) return 'no Method type';"
    "return t.fields.map(function(f){"
    "  return f.name + ' (' + f.type_string + ')';"
    "}).join(', ');"
    "})()"
)


def parse_reply(out):
    for ln in out.splitlines():
        if "[agent.reply]" in ln and "msg=" in ln:
            return ln.split("msg=", 1)[1].strip()
    return None


def main():
    java = find_java(os.environ.get("MARROW_TEST_JDK", "21"))
    if not java: return 1
    p = subprocess.Popen([java, "-cp", TGT_CP, "Target"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, errors="replace")
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        ln = p.stdout.readline()
        if ln.startswith("Target PID:"): pid = int(ln.split(":", 1)[1].strip()); break
    if not pid: p.kill(); return 1
    subprocess.run([PROBE, "inject", str(pid), AGENT], capture_output=True, timeout=15)
    time.sleep(1.5)
    r = subprocess.run([PROBE, "agent", str(pid), "eval", JS],
                       capture_output=True, text=True, timeout=15)
    rep = parse_reply(r.stdout)
    p.kill()
    print(rep)


if __name__ == "__main__":
    main()
