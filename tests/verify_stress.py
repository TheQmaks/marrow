"""Comprehensive stress test: every primitive/object/array variation
through the Frida-style API. Each batch runs as a separate eval to stay
under the marrow.exe argv budget; results accumulate in
globalThis._stress."""
import os
import subprocess
import sys
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _paths import PROBE, AGENT, TGT_CP, find_java  # noqa: E402


SETUP = (
    "(function(){"
    "globalThis._stress = {};"
    "globalThis._track = function(n,fn){try{_stress[n]=fn();}catch(e){_stress[n]='ERR:'+e;}};"
    "globalThis._C = Java.use('Callable');"
    "globalThis._T = Java.use('Target');"
    "globalThis._I = Java.use('java.lang.Integer');"
    "globalThis._L = Java.use('java.lang.Long');"
    "globalThis._displayOop = Marrow.readStaticRef(_T.$klass, 'displayName');"
    "globalThis._s = Java.cast(_displayOop, 'java/lang/String');"
    "return 'setup_ok';"
    "})()"
)

BATCH1 = (
    "(function(){"
    "_track('prim_int_arg_int_return',     function(){return _C.addInts(40,2);});"
    "_track('prim_int_4args_int_return',   function(){return _C.sumFour(1,2,3,4);});"
    "_track('prim_long_arg_long_return',   function(){"
    "  var r=_C.mulLong('0x100000000','0x2');"
    "  return typeof r==='string' && r.indexOf('0x')===0 ? 'long_hex' : 'BAD:'+r;"
    "});"
    "_track('prim_void_return',            function(){"
    "  var r=_C.voidWork();"
    "  return typeof r==='undefined'?'undefined':'BAD:'+r;"
    "});"
    "_track('prim_int_no_args',            function(){return _C.neverCalled();});"
    "_track('prim_long_no_args',           function(){"
    "  var r=_C.alsoNever();"
    "  return typeof r==='string' && r.indexOf('0x')===0?'long_hex':'BAD:'+r;"
    "});"
    "_track('prim_int_static_chain',       function(){"
    "  return _I.parseInt.overload('java.lang.String').apply(null,['12345']);"
    "});"
    "_track('str_length',                  function(){return _s.length();});"
    "_track('str_isEmpty',                 function(){return _s.isEmpty();});"
    "_track('str_charAt',                  function(){return _s.charAt(0);});"
    "_track('str_equals_self',             function(){return _s.equals(_s);});"
    "_track('str_equals_null',             function(){return _s.equals(null);});"
    "_track('str_equals_empty_jsstr',      function(){return _s.equals('');});"
    "_track('str_equals_unicode',          function(){return _s.equals('\\u043F\\u0440\\u0438\\u0432\\u0435\\u0442');});"
    "_track('str_equals_hex_looking',      function(){return _s.equals('0xCAFE');});"
    "return 'batch1_ok';"
    "})()"
)

BATCH2 = (
    "(function(){"
    "_track('arr_byte_via_getBytes',       function(){"
    "  var b=_s.getBytes.overload().apply(_s,[]);"
    "  return Array.isArray(b)&&b.length>0&&typeof b[0]==='number'?'len='+b.length:'BAD:'+JSON.stringify(b);"
    "});"
    "_track('arr_char_via_toCharArray',    function(){"
    "  var c=_s.toCharArray();"
    "  return Array.isArray(c)&&c.length>0?'len='+c.length:'BAD:'+JSON.stringify(c);"
    "});"
    "_track('arr_object_via_split',        function(){"
    "  var parts=_s.split.overload('java.lang.String').apply(_s,['#']);"
    "  if(!Array.isArray(parts))return 'NOT_ARRAY';"
    "  if(parts.length<1)return 'EMPTY';"
    "  return parts[0]&&parts[0].$class==='java/lang/String'?'cast_ok len='+parts.length:'NO_CAST';"
    "});"
    "_track('arr_object_pass_through',     function(){"
    "  var b=_s.getBytes.overload().apply(_s,[]);"
    "  return b&&b.$oop?'oop_ok':'NO_OOP';"
    "});"
    "_track('arr_empty_split',             function(){"
    "  var p=_s.split.overload('java.lang.String').apply(_s,['ZZZNEVER']);"
    "  return Array.isArray(p)&&p.length===1?'ok len=1':'BAD:'+JSON.stringify(p);"
    "});"
    "_track('boxed_int_valueOf',           function(){"
    "  var box=_I.valueOf.overload('int').apply(null,[42]);"
    "  return box&&box.$class==='java/lang/Integer'?'proxy_ok':'BAD:'+box;"
    "});"
    "_track('boxed_int_intValue',          function(){"
    "  var box=_I.valueOf.overload('int').apply(null,[42]);"
    "  return box.intValue();"
    "});"
    "_track('boxed_long_valueOf',          function(){"
    "  var box=_L.valueOf.overload('long').apply(null,['0x7FFFFFFFFFFFFFFF']);"
    "  return box&&box.$class==='java/lang/Long'?'proxy_ok':'BAD:'+box;"
    "});"
    "return 'batch2_ok';"
    "})()"
)

BATCH3 = (
    "(function(){"
    "globalThis._hookFiredCount=0;"
    "_track('hook_install_replace_return', function(){"
    "  _C.addInts.implementation=function(a,b){_hookFiredCount++;return 9999;};"
    "  return _C.addInts(7,11);"
    "});"
    "_track('hook_callOriginal_modified',  function(){"
    "  _C.addInts.implementation=function(a,b){return _C.addInts.callOriginal(a*100,b*100)+1;};"
    "  return _C.addInts(7,11);"
    "});"
    "_track('hook_unhook_returns_orig',    function(){"
    "  _C.addInts.implementation=null;"
    "  return _C.addInts(7,11);"
    "});"
    "_track('hook_rehook_after_unhook',    function(){"
    "  _C.addInts.implementation=function(a,b){return -1;};"
    "  var v=_C.addInts(7,11);"
    "  _C.addInts.implementation=null;"
    "  return v;"
    "});"
    "_track('hook_fired_at_least_once',    function(){return _hookFiredCount>=1;});"
    "_track('cast_repeated_same_class',    function(){"
    "  var a=Java.cast(_displayOop,'java/lang/String');"
    "  var b=Java.cast(_displayOop,'java/lang/String');"
    "  return Object.getPrototypeOf(a)===Object.getPrototypeOf(b)?'proto_shared':'NEW_PROTO';"
    "});"
    "_track('cast_with_dotted_classname',  function(){"
    "  var c=Java.cast(_displayOop,'java.lang.String');"
    "  return c&&c.$class==='java/lang/String'?'normalized':'BAD:'+(c&&c.$class);"
    "});"
    "_track('multi_overload_int_dispatch', function(){"
    "  var s1=_I.toString(42);"
    "  return s1&&s1.$class==='java/lang/String'?'ok':'BAD:'+s1;"
    "});"
    "_track('multi_overload_2arg_dispatch',function(){"
    "  var s1=_I.toString(255,16);"
    "  if(!s1||!s1.$oop)return 'NOT_PROXY';"
    "  var d=Java.toString(s1.$oop);"
    "  return d==='ff'?'ok':'BAD:'+d;"
    "});"
    "_track('err_use_unknown_class',       function(){"
    "  try{Java.use('not.real.X');return 'NO_THROW';}catch(e){return 'threw_ok';}"
    "});"
    "_track('err_overload_wrong_sig',      function(){"
    "  try{_C.addInts.overload('(JJ)J');return 'NO_THROW';}catch(e){return 'threw_ok';}"
    "});"
    "return 'batch3_ok';"
    "})()"
)

DRAIN = "(function(){return JSON.stringify(globalThis._stress||{});})()"

EXPECTATIONS = {
    'prim_int_arg_int_return':      lambda v: v == 42,
    'prim_int_4args_int_return':    lambda v: v == 10,
    'prim_long_arg_long_return':    lambda v: v == 'long_hex',
    'prim_void_return':             lambda v: v == 'undefined',
    'prim_int_no_args':             lambda v: v == -889275714,
    'prim_long_no_args':            lambda v: v == 'long_hex',
    'prim_int_static_chain':        lambda v: v == 12345,
    'str_length':                   lambda v: isinstance(v, int) and v > 0,
    'str_isEmpty':                  lambda v: v is False,
    'str_charAt':                   lambda v: isinstance(v, int) and v == ord('t'),
    'str_equals_self':              lambda v: v is True,
    'str_equals_null':              lambda v: v is False,
    'str_equals_empty_jsstr':       lambda v: v is False,
    'str_equals_unicode':           lambda v: v is False,
    'str_equals_hex_looking':       lambda v: v is False,
    'arr_byte_via_getBytes':        lambda v: isinstance(v, str) and v.startswith('len='),
    'arr_char_via_toCharArray':     lambda v: isinstance(v, str) and v.startswith('len='),
    'arr_object_via_split':         lambda v: isinstance(v, str) and v.startswith('cast_ok'),
    'arr_object_pass_through':      lambda v: v == 'oop_ok',
    'arr_empty_split':              lambda v: v == 'ok len=1',
    'boxed_int_valueOf':            lambda v: v == 'proxy_ok',
    'boxed_int_intValue':           lambda v: v == 42,
    'boxed_long_valueOf':           lambda v: v == 'proxy_ok',
    'hook_install_replace_return':  lambda v: v == 9999,
    'hook_callOriginal_modified':   lambda v: v == 1801,
    'hook_unhook_returns_orig':     lambda v: v == 18,
    'hook_rehook_after_unhook':     lambda v: v == -1,
    'hook_fired_at_least_once':     lambda v: v is True,
    'cast_repeated_same_class':     lambda v: v == 'proto_shared',
    'cast_with_dotted_classname':   lambda v: v == 'normalized',
    'multi_overload_int_dispatch':  lambda v: v == 'ok',
    'multi_overload_2arg_dispatch': lambda v: v == 'ok',
    'err_use_unknown_class':        lambda v: v == 'threw_ok',
    'err_overload_wrong_sig':       lambda v: v == 'threw_ok',
}


def parse_reply(out):
    for ln in out.splitlines():
        if "[agent.reply]" in ln and "msg=" in ln:
            return ln.split("msg=", 1)[1].strip()
    return None


def eval_js(pid, js, label):
    r = subprocess.run([PROBE, "agent", str(pid), "eval", js],
                       capture_output=True, text=True, timeout=30)
    raw = parse_reply(r.stdout)
    if not raw:
        print(f"[FAIL] {label}: no reply"); print(r.stdout[:300]); return None
    return raw


def main():
    target_jdk = os.environ.get("MARROW_TEST_JDK", "17")
    java = find_java(target_jdk)
    if not java:
        print(f"[SKIP] no JDK {target_jdk}"); return 0
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
        print("[FAIL] no PID"); p.kill(); return 1

    subprocess.run([PROBE, "inject", str(pid), AGENT], capture_output=True, timeout=15)
    time.sleep(1.5)

    print(f"=== JDK {target_jdk}  PID={pid} ===")
    for batch_name, batch_js in [("setup", SETUP), ("batch1", BATCH1),
                                 ("batch2", BATCH2), ("batch3", BATCH3)]:
        rep = eval_js(pid, batch_js, batch_name)
        if rep is None:
            p.kill(); return 1
        ok = (batch_name + "_ok") in rep or "setup_ok" in rep
        print(f"  {batch_name}: {'ran' if ok else 'reply=' + rep[:80]}")

    raw = eval_js(pid, DRAIN, "drain")
    p.kill()
    if not raw: return 1
    try:
        outer = json.loads(raw)
        d = json.loads(outer) if isinstance(outer, str) else outer
    except Exception as e:
        print(f"[parse] {e}\n{raw}"); return 1

    print()
    fails = []
    for k, expected in EXPECTATIONS.items():
        v = d.get(k)
        try: ok = expected(v)
        except Exception: ok = False
        mark = " ok " if ok else "FAIL"
        print(f"  [{mark}] {k:36s} {v}")
        if not ok: fails.append((k, v))
    print()
    if fails:
        print(f"FAILED {len(fails)}/{len(EXPECTATIONS)} on JDK {target_jdk}")
        for k, v in fails: print(f"  {k}: {v}")
    else:
        print(f"ALL {len(EXPECTATIONS)} CHECKS PASS on JDK {target_jdk}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
