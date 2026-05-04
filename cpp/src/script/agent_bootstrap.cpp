// agent_bootstrap.cpp — JS bootstrap source extracted from agent_js.cpp.
// Lives in its own TU so the bootstrap text doesn't bloat agent_js and so
// large additions aren't constrained by the MSVC ~16K-per-literal limit
// (a TU can host arbitrarily many concatenated literals).
//
// Edit this file to evolve the high-level Java.* facade. agent_js.cpp uses
// `extern const char* k_java_bootstrap;` to pull it in.

namespace marrow {

const char* k_java_bootstrap = R"JS(

// --- Frida compatibility shims ---------------------------------------
// Duktape doesn't have an event loop, so setTimeout/setInterval are
// synchronous: callbacks fire immediately. Most Frida scripts that wrap
// their setup in setTimeout(fn, 0) just need a way to defer until after
// the script body parses — that's already true here, so we run inline.
if (typeof setTimeout === "undefined") {
    setTimeout = function(fn, _ms) {
        try { fn(); } catch (e) {
            if (typeof Marrow !== "undefined" && Marrow.log)
                Marrow.log("[setTimeout] cb threw: " + (e && e.message || e));
        }
        return 0;
    };
    setInterval  = setTimeout;
    clearTimeout = function() {};
    clearInterval = function() {};
}
if (typeof console === "undefined") {
    console = {
        log:   function(m) { Marrow.log("[console] " + m); },
        warn:  function(m) { Marrow.log("[console.warn] " + m); },
        error: function(m) { Marrow.log("[console.error] " + m); }
    };
}

var Java = {
    _hookCounter: 0x80000000,

    // PDB-less JavaCalls::call resolver. Returns the VA on success.
    // Triangulates from 5 sibling JNIEnv vtable entries (CallStatic*MethodA),
    // applies a structural filter (tiny wrapper: 1 call, ret, <=20 insns),
    // then verifies dynamically using java.lang.Math.abs(-7)=>7 (a JDK
    // builtin guaranteed to exist).
    //
    // After verification, the chosen VA is set into g_sym.javacalls_call
    // and g_sym.ready=true (frozen) via _setJavaCallsCall, so subsequent
    // _invokeJC calls use it.
    _jcCallCache: null,
    _jcResolverActive: false,
    _jcResolveTried: false,
    resolveJavaCallsCall: function() {
        if (Java._jcCallCache) return Java._jcCallCache;
        Java._jcResolverActive = true;
        var _Math = Java.use("java.lang.Math");
        var _absH = _Math.abs.overload("(I)I");
        var _absAddr = Java._parseHex(_absH.address);
        try {
        // Universal fallback: invoke via call_stub directly. Works across
        // ALL JDKs because StubRoutines::_call_stub_return_address is
        // exposed via vmStructs on every JDK. We try this LAST after
        // pattern/triangulation paths fail, but compute the entry now so
        // the catch path can use it.
        var _tryCallStubFallback = function(addrForVerify) {
            var retAddr = Marrow._callStubReturnAddress();
            if (!retAddr) return null;
            var retVa = parseInt(retAddr, 16);
            var b = Marrow._readMem("0x" + (retVa - 512).toString(16), 512);
            var entryOff = -1;
            for (var i = 0; i + 4 <= b.length; i++) {
                if ((b[i]&0xff) === 0x55 && (b[i+1]&0xff) === 0x48 &&
                    (b[i+2]&0xff) === 0x8b && (b[i+3]&0xff) === 0xec)
                    entryOff = i;  // last match
            }
            if (entryOff < 0) return null;
            var stubVa = "0x" + (retVa - 512 + entryOff).toString(16);
            var rv = "";
            try {
                rv = Marrow._invokeViaCallStub(stubVa, addrForVerify.lo,
                    addrForVerify.hi, "I", "I", [-7]);
            } catch (e) { rv = "throw"; }
            if (typeof rv === "string" && rv.indexOf("value:0x7}") >= 0)
                return stubVa;
            return null;
        };

        // Fast path: byte-pattern match. JC::call's body is so tight on
        // OpenJDK release builds (sub rsp, 0x38; arg shuffle; lea rcx,
        // [rip+disp] for &call_helper; call os_exception_wrapper; epilogue)
        // that a 33-byte signature with 8 wildcards uniquely identifies it
        // on JDK 11/17/21/25 release. Try this FIRST -- pattern-registry's
        // 16-byte alignment preference avoids mid-function collisions.
        var jcPat = "48 83 ec 38 4c 89 4c 24 20 4d 8b c8 4c 8b c2 48 " +
                    "8b d1 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 83 " +
                    "c4 38 c3";
        if (Marrow._registerSymbolPattern("__jc_call_pat", jcPat)) {
            var patVa = Marrow._resolveSymbol("__jc_call_pat");
            if (patVa && patVa !== "0x0") {
                // Verify with neverCalled-equivalent check via Math.abs.
                var Math2 = Java.use("java.lang.Math");
                var absH2 = Math2.abs.overload("(I)I");
                var addr2 = Java._parseHex(absH2.address);
                var prev2 = Marrow._setJavaCallsCall(patVa);
                var r2 = "";
                try { r2 = Marrow._invokeJC(addr2.lo, addr2.hi, "I", "I", [-7], "", false); }
                catch (e) { r2 = "throw"; }
                if (typeof r2 === "string" && r2.indexOf("value:0x7}") >= 0) {
                    Java._jcCallCache = patVa;
                    Java._jcByVal = false;
                    return patVa;
                }
                Marrow._setJavaCallsCall(prev2);
            }
        }

        var SLOTS = [116, 119, 131, 134, 143];  // CallStatic{Obj,Bool,Int,Long,Void}MethodA
        var entries = [];
        for (var i = 0; i < SLOTS.length; i++) {
            var v = Marrow._jniVtableSlot(SLOTS[i]);
            if (typeof v === "string" && v.indexOf("0x") === 0) entries.push(v);
        }
        if (entries.length < 3) throw new Error("vtable read failed");

        function gather(va, maxd) {
            var v = {}, q = [{va:va, d:0}];
            while (q.length) {
                var n = q.shift();
                if (v[n.va] !== undefined) continue;
                if (n.d > maxd) continue;
                v[n.va] = n.d;
                if (n.d === maxd) continue;
                var sc = Marrow._xrefScan(n.va, 256);
                for (var i = 0; i < sc.calls.length; i++)
                    if (v[sc.calls[i]] === undefined) q.push({va:sc.calls[i], d:n.d+1});
            }
            return v;
        }
        var maps = entries.map(function(e){ return gather(e, 4); });
        var first = maps[0], d2 = [], d3 = {};
        for (var va in first) {
            var depths = [first[va]], ok = true;
            for (var i = 1; i < maps.length; i++) {
                if (maps[i][va] === undefined) { ok = false; break; }
                depths.push(maps[i][va]);
            }
            if (!ok) continue;
            var aE2=true, aE3=true;
            for (var j = 0; j < depths.length; j++) {
                if (depths[j] !== 2) aE2 = false;
                if (depths[j] !== 3) aE3 = false;
            }
            if (aE2) d2.push(va);
            if (aE3) d3[va] = true;
        }
        var matches = [];
        for (var i = 0; i < d2.length; i++) {
            var sc = Marrow._xrefScan(d2[i], 64);
            if (sc.calls.length === 1 && sc.stopReason === "ret" &&
                sc.insnsWalked <= 20 && d3[sc.calls[0]])
                matches.push(d2[i]);
        }
        if (matches.length === 0) {
            // Fall back to call_stub. Stub bypasses JC::call entirely and
            // accepts raw oop arguments directly (interpreter reads them
            // from stack as oops, not jobjects -- no make_local required).
            // Verified across primitive + L args + instance receivers.
            var stubVa = _tryCallStubFallback(_absAddr);
            if (stubVa) {
                Java._callStubCache = stubVa;
                Java._jcCallCache = "stub:" + stubVa;
                return Java._jcCallCache;
            }
            throw new Error("no JC::call structural matches " +
                            "(d2=" + d2.length + ", d3=" + Object.keys(d3).length + ")");
        }

        // Disambiguate via firing: install inline hooks on all matches,
        // trigger a known static JNI invocation (Math.abs), counts. Only
        // candidates ON the runtime JNI static path fire. Structural-only
        // matches that aren't actually on the path stay at count=0 (avoids
        // SEH-non-recoverable hangs from picking those for verification).
        var Math_ = Java.use("java.lang.Math");
        var absH = Math_.abs.overload("(I)I");
        var addr = Java._parseHex(absH.address);
        var hookIds = {};
        var dbgInstall = [];
        for (var i = 0; i < matches.length; i++) {
            var hid = Marrow._inlineHook(matches[i]);
            hookIds[matches[i]] = hid;
            dbgInstall.push(matches[i] + "=>id" + hid);
        }
        // Run a known JNI invocation that goes through jni_invoke_static.
        // Use the single-overload handle (absH) -- Math.abs has 4 overloads
        // so the multi-handle isn't directly callable.
        var probeR = "?";
        try { probeR = "" + absH(-7); } catch (e) { probeR = "threw:" + (e.message||e); }
        var firedMatches = [];
        var dbgCounts = [];
        for (var i = 0; i < matches.length; i++) {
            var c = Marrow._inlineHookCount(hookIds[matches[i]]);
            Marrow._inlineUnhook(hookIds[matches[i]]);
            dbgCounts.push(matches[i] + "=" + c);
            if (c > 0) firedMatches.push(matches[i]);
        }
        Java._jcDebug = {install:dbgInstall, probe:probeR, counts:dbgCounts,
                         structural:matches.slice(), fired:firedMatches.slice()};
        // Verify each surviving candidate via Math.abs(-7) -> 7. Try BOTH
        // methodHandle ABIs: 16-byte by-ref (JDK 12+) and 8-byte by-value
        // (JDK 8/11). Cache the convention in Java._jcByVal so subsequent
        // _invokeJC calls use the right one.
        var winner = null;
        var winnerByVal = false;
        for (var i = 0; i < firedMatches.length && !winner; i++) {
            var prev = Marrow._setJavaCallsCall(firedMatches[i]);
            // Try 16-byte by-ref first (the default).
            var r1 = "";
            try { r1 = Marrow._invokeJC(addr.lo, addr.hi, "I", "I", [-7], "", false); }
            catch (e) { r1 = "throw"; }
            if (typeof r1 === "string" && r1.indexOf("value:0x7}") >= 0) {
                winner = firedMatches[i];
                winnerByVal = false;
                break;
            }
            // Try 8-byte by-value (JDK 8/11 layout).
            var r2 = "";
            try { r2 = Marrow._invokeJC(addr.lo, addr.hi, "I", "I", [-7], "", true); }
            catch (e) { r2 = "throw"; }
            if (typeof r2 === "string" && r2.indexOf("value:0x7}") >= 0) {
                winner = firedMatches[i];
                winnerByVal = true;
                break;
            }
            Marrow._setJavaCallsCall(prev);
        }
        if (!winner) {
            var stubVa = _tryCallStubFallback(_absAddr);
            if (stubVa) {
                Java._callStubCache = stubVa;
                Java._jcCallCache = "stub:" + stubVa;
                return Java._jcCallCache;
            }
            throw new Error(
                "no JC::call candidate verified; structural=" + matches.length +
                " firing=" + firedMatches.length);
        }
        Java._jcCallCache = winner;
        Java._jcByVal = winnerByVal;
        return winner;
        } finally { Java._jcResolverActive = false; }
    },
)JS"
// Mid-fragment split (MSVC ~16K raw-string limit).
R"JS(

    // Java.use("Target") -> proxy with method handles + class fields
    // Cached per-name; rebuilding is expensive on classes with many methods
    // (java/lang/String has ~140) and the proxy is immutable.
    _useCache: {},
    use: function(name) {
        var cached = Java._useCache[name];
        if (cached) return cached;
        var k = Marrow.findClass(name);
        if (!k) throw new Error("class not found: " + name);
        var methods = Marrow.listMethods(k);
        // Use a name->arr map without prototype pollution; Object's
        // Object.prototype methods (toString, hashCode, valueOf, …)
        // shadow plain map lookups otherwise.
        var byName = {};
        var has = Object.prototype.hasOwnProperty;
        for (var i = 0; i < methods.length; ++i) {
            var m = methods[i];
            if (!has.call(byName, m.name)) byName[m.name] = [];
            byName[m.name].push(m);
        }
        var cls = { $name: name, $klass: k };
        var self = this;
        // For each method name, install a property that returns a method
        // handle. If only one overload exists -> handle is directly
        // operable. Otherwise caller must use .overload(sig).
        Object.keys(byName).forEach(function(mname) {
            var overloads = byName[mname];
            // Constructors are surfaced as `cls.$init` (Frida convention).
            var jsKey = (mname === "<init>") ? "$init" :
                        (mname === "<clinit>") ? "$clinit" : mname;
            cls[jsKey] = self._makeHandle(cls, mname, overloads);
        });
        // T.$new(args) — Frida-style: TLAB-allocate a fresh instance,
        // run its constructor, return the cast'd proxy. For overloaded
        // constructors, picks the overload whose parameter list matches
        // the JS arg shape (count + per-position primitive vs object).
        cls.$new = function() {
            var args = Array.prototype.slice.call(arguments);
            var oop  = Marrow._allocInstance(cls.$klass);
            if (!oop || oop === "0x0")
                throw new Error("$new: alloc failed for " + name);
            var inst = Java.cast(oop, name);
            if (cls.$init) {
                var single = (typeof cls.$init === 'function')
                           ? cls.$init
                           : Java._pickOverload(cls.$init, args, name);
                Java.invoke(single, oop, args);
            }
            return inst;
        };
        Java._useCache[name] = cls;
        return cls;
    },

    _makeHandle: function(cls, name, overloads) {
        // The "handle" is a function-shaped object with overload + impl.
        var handle = {
            $name: name,
            $overloads: overloads,
            $cls: cls,
            // Two calling conventions, both Frida-compatible:
            //
            //   .overload("(II)V")               // single JVM-internal sig
            //   .overload("int", "int")          // variadic Frida type names
            //   .overload("[Ljavax.net.ssl.KeyManager;", ...)
            //
            // The variadic form matches by argument list only (return type
            // is whatever the matching overload declares). Equivalent to
            // how Frida resolves overloads in copy-pasted Android scripts.
            overload: function() {
                var hit = null;
                if (arguments.length === 1 &&
                    typeof arguments[0] === 'string' &&
                    arguments[0].charAt(0) === '(') {
                    // JVM-internal sig: full match including return type.
                    var sig = arguments[0];
                    for (var i = 0; i < overloads.length; ++i)
                        if (overloads[i].sig === sig) { hit = overloads[i]; break; }
                } else {
                    // Frida-style variadic: build "(...)" arg fragment and
                    // match overloads by arg list, ignoring return type.
                    var parts = [];
                    for (var i = 0; i < arguments.length; ++i)
                        parts.push(Java._fridaTypeToJvm(arguments[i]));
                    var argsBody = '(' + parts.join('') + ')';
                    for (var i = 0; i < overloads.length; ++i)
                        if (overloads[i].sig.indexOf(argsBody) === 0) {
                            hit = overloads[i]; break;
                        }
                }
                if (!hit) {
                    var asked = (arguments.length === 1 &&
                                 arguments[0].charAt(0) === '(')
                              ? arguments[0]
                              : '(' + Array.prototype.slice.call(arguments)
                                          .join(', ') + ')';
                    throw new Error(
                        "no overload " + asked + " of " +
                        cls.$name + "." + name + "; available: " +
                        overloads.map(function(o){return o.sig}).join(", "));
                }
                return Java._makeSingle(cls, name, hit);
            }
        };
        // If exactly one overload, mirror its API directly so user can do
        // `cls.method.implementation = fn` without .overload(...).
        if (overloads.length === 1) {
            var single = Java._makeSingle(cls, name, overloads[0]);
            // Inherit overload-method but otherwise expose single's API.
            single.overload = handle.overload;
            return single;
        }
        // Multi-overload: make the handle directly callable so
        // `Cls.method(args)` / `instance.method(args)` work without
        // explicit .overload(...). Frida's pattern: pick the overload
        // whose param list matches the JS arg shape, then route through
        // the resolved single. _pickOverload does the matching using
        // the same logic as $new() constructor dispatch.
        //
        // .implementation = fn is unsupported on this multi-overload
        // handle by design — replacing "all overloads" is ambiguous.
        // User must say `Cls.method.overload("(I)V").implementation =`.
        var callable = function() {
            var args = Array.prototype.slice.call(arguments);
            var picked = Java._pickOverload(handle, args, cls.$name);
            return picked.apply(this, args);
        };
        callable.$name      = name;
        callable.$overloads = overloads;
        callable.$cls       = cls;
        callable.overload   = handle.overload;
        Object.defineProperty(callable, 'implementation', {
            set: function() {
                throw new Error(
                    cls.$name + "." + name + " has " + overloads.length +
                    " overloads — pick one explicitly: " +
                    "Cls." + name + ".overload(\"sig\").implementation = fn. " +
                    "Available signatures: " +
                    overloads.map(function(o){return o.sig}).join(", "));
            },
            configurable: true
        });
        return callable;
    },
)JS"
// MSVC ~16K split.
R"JS(

    _makeSingle: function(cls, name, m) {
        var addr = Java._parseHex(m.addr);
        var isInstance = (name !== "<clinit>");
        var parsed = Java.parseSig(m.sig);
        var argTypes = parsed.args;
        var retType  = { type: parsed.ret };

        // The handle IS a callable function. Calling it as `cls.method(args)`
        // invokes the method as static. Instance binding (call with thisOop)
        // is layered on top by Java.cast -- see below.
        //
        // Frida-compatible auto-callOriginal: when invoked from inside this
        // hook's own handler, transparently route through callOriginal
        // (per-thread reentry guard) so `Cls.method(args)` doesn't recurse
        // into the same handler.
        var single = function() {
            var args = Array.prototype.slice.call(arguments);
            if (single.$cookie != null && Java._activeCookies[single.$cookie]) {
                // We're inside our own hook handler. Route through callOriginal.
                // Pass `single` as `this` so callOriginal sees `this.$cookie`.
                return single.callOriginal.apply(single, args);
            }
            return Java._unwrap(Java.invokeStatic(single, args),
                                  single.$returnClass);
        };

        single.argumentTypes = argTypes;
        single.returnType    = retType;
        // Frida-parity: auto-cast L-typed returns. Null for primitive /
        // void / array returns — _unwrap then leaves the value as-is.
        single.$returnClass  = Java._returnClassFromSig(m.sig);
        // Carry class + method metadata so Java.invokeStatic can route
        // through the JNI surface when PDB is unavailable. Frida-style
        // direct calls `Cls.method(args)` then work without setup.
        single.$class  = cls.$name;          // JVM-internal slashed form
        single.$method = { name: name, sig: m.sig, addr: m.addr };
        single.$sig    = m.sig;
        single.$name         = name;
        single.$sig          = m.sig;
        single.$cls          = cls;
        single.$method       = m;
        single.$overloads    = [m];
        single.address       = m.addr;

        // implementation setter — fn or null — preserves Frida semantics.
        // SYNC mode: handler runs from JVM thread under Duktape mutex; its
        // return value replaces the method's return (skip_orig path in
        // the trampoline).
        Object.defineProperty(single, "implementation", {
            set: function(fn) {
                if (fn === null) { Java._unhook(this, addr); return; }
                if (typeof fn !== "function")
                    throw new Error("implementation must be a function or null");
                Java._installOrUpdateImpl(this, cls, name, m, addr, isInstance,
                                          [fn], /*replace=*/true, /*sync=*/true);
            },
            configurable: true
        });

        // ASYNC mode: handler queued in ring, fires on Java.drain().
        // Original always runs; this is the cheap observer path.
        single.attach = function(fn) {
            if (typeof fn !== "function")
                throw new Error("attach: fn must be a function");
            Java._installOrUpdateImpl(this, cls, name, m, addr, isInstance,
                                      [fn], /*replace=*/false, /*sync=*/false);
            return this;
        };
        single.detachAll = function() {
            if (this.$cookie != null && Java._impls[this.$cookie])
                Java._impls[this.$cookie].fns = [];
            return this;
        };
        // Frida-equivalent: invoke the ORIGINAL method body from inside a
        // hook. Sets a per-thread reentry guard so the trampoline skips
        // the user handler on the recursive call, then routes through the
        // JNI surface (which goes through the patched entry — but the
        // guard makes dispatch a no-op, leaving the tail-jmp to orig_fie
        // to run the unmodified body).
        //
        // Usage:
        //   T.method.implementation = function(a, b) {
        //       // intercept...
        //       return T.method.callOriginal(this, a, b);
        //   };
        //
        // For static methods, pass null as `thisArg`. Receiver goes
        // through Java.invokeStatic (PDB path) or the JNI surface
        // route (PDB-less). Currently primitive-arg static methods
        // are best-supported; instance + object args use the same
        // chain as Java.invoke and inherit its boundaries.
        single.callOriginal = function() {
            var args = Array.prototype.slice.call(arguments);
            var thisArg = (m.isInstance) ? args.shift() : null;
            var cookie = this && this.$cookie;
            if (cookie == null) {
                // Not yet hooked — just call directly.
                return m.isInstance ? Java.invoke(single, thisArg, args)
                                    : Java.invokeStatic(single, args);
            }
            // Trampoline tail-jmps to original when ctx->skip_orig stays 0.
            // The reentry guard makes dispatch skip the handler entirely
            // on the recursive call, so original body runs end-to-end.
            // No bytecode mutation needed under the new sync architecture.
            Marrow._setReentryGuard(cookie, +1);
            try {
                if (!m.isInstance) {
                    var p = Java.parseSig(m.sig);
                    var raw = Marrow._invokeJNI(cls.$name, name, m.sig,
                                                   p.ret, args);
                    // _invokeJNI returns "value:0x..." / "value:true" /
                    // "ok" / "0x..." (for object). Parse here — Java._unwrap
                    // expects the different "{type:N,value:0x..}" format.
                    if (typeof raw !== "string") return raw;
                    if (raw === "ok") return undefined;
                    if (raw.indexOf("value:") === 0) {
                        var v = raw.substring(6);
                        if (v === "true")  return true;
                        if (v === "false") return false;
                        if (v.indexOf("0x") === 0) {
                            // For long return, keep hex string for precision.
                            if (p.ret === 'J') return v;
                            var n = parseInt(v, 16);
                            // Sign-extend 32-bit ints.
                            if ((p.ret === 'I' || p.ret === 'B' ||
                                 p.ret === 'S') && n >= 0x80000000) {
                                n -= 0x100000000;
                            }
                            return n;
                        }
                        return v;
                    }
                    return raw;   // L/[ : raw oop hex; null if "0x0"
                }
                return Java.invoke(single, thisArg, args);
            } finally {
                Marrow._setReentryGuard(cookie, -1);
            }
        };
        // Frida convention: handle.call(this, a, b) is the canonical way
        // to invoke the original from inside a replaced implementation.
        // We alias it to callOriginal so existing scripts work.
        single.call = single.callOriginal;
        single.setReturn = function(value) {
            var ret = Java.parseSig(m.sig).ret;
            var ok = false;
            if (value === null && (ret === 'L' || ret === '[')) {
                ok = Marrow._setReturnNull(addr.lo, addr.hi);
            } else if (typeof value === "number" &&
                       (ret === 'I' || ret === 'B' || ret === 'S' ||
                        ret === 'C' || ret === 'Z')) {
                ok = Marrow._setReturnInt(addr.lo, addr.hi, value);
            } else if (value === undefined && ret === 'V') {
                Marrow._muteMethod(addr.lo, addr.hi);
                ok = true;
            } else {
                throw new Error("setReturn: unsupported value=" +
                                value + " for return type " + ret);
            }
            if (!ok) throw new Error("setReturn: bytecode patch failed");
            Marrow.log("Java.setReturn: " + cls.$name + "." + name +
                         m.sig + " = " + value);
            return ok;
        };
        return single;
    },

    // Allocate a new Java String from a JS string. Sequence:
    //   1. TLAB-allocate a char[len] in the target heap.
    //   2. Write each JS UTF-16 code unit into the array (2 bytes per char).
    //   3. Call String.valueOf(char[]) via JavaCalls — returns a String oop.
    // Returns the oop hex on success, or null when the JavaCalls path is
    // unavailable (no PDB). Caller surfaces an actionable error.
    _jstring: function(jsStr) {
        if (typeof jsStr !== "string") return null;
        if (!Java._jcReady()) return null;
        var arrOop = Marrow._allocCharArray(jsStr.length);
        if (!arrOop || arrOop === "0x0") return null;
        var dataOff = Marrow._charArrayDataOffset();
        var base = parseInt(arrOop, 16) + dataOff;
        // Write UTF-16 code units little-endian. Done via a flat byte buffer.
        var bytes = new Array(jsStr.length * 2);
        for (var i = 0; i < jsStr.length; ++i) {
            var cc = jsStr.charCodeAt(i);
            bytes[i * 2]     = cc & 0xFF;
            bytes[i * 2 + 1] = (cc >> 8) & 0xFF;
        }
        if (bytes.length > 0) {
            Marrow._writeMem("0x" + base.toString(16), bytes);
        }
        // Call String.valueOf(char[]) — picks the [C overload explicitly.
        var STR = Java.use("java/lang/String");
        var voHandle = STR.valueOf;
        if (voHandle && typeof voHandle.overload === "function") {
            voHandle = voHandle.overload("([C)Ljava/lang/String;");
        }
        // voHandle is now a callable single handle. It returns the unwrapped
        // String oop because retType is L; _unwrap converts T_OBJECT to a hex
        // string (or null).
        var resultOop = voHandle(arrOop);
        return resultOop;
    },

)JS"
// Mid-fragment split (MSVC ~16K raw-string limit).
R"JS(

    // Java.registerClass(spec) -> classProxy
    // Frida-equivalent for defining a Java class whose method bodies are
    // implemented by JS callbacks. Strategy:
    //   1. Clone a donor class (default: Greeter.class — single answer()
    //      returning int) via klass_cloner. The clone gets a new Klass*
    //      registered in CLDG so Java.use(name) finds it.
    //   2. Initialize the cloned class (forces link_class so methods get
    //      _i2i_entry and become callable).
    //   3. For each user method, install handler via .implementation = fn.
    //
    // Uses clone_klass_deep — Method/ConstMethod/bytecode live in agent-
    // owned pages, isolated from the donor. .setReturn / .implementation
    // on the new class no longer leaks into the donor.
    //
    // For value-returning methods, call cls.method.setReturn(value) AFTER
    // registerClass to plant a constant return; the JS implementation
    // still fires on every invocation as a side-effect callback.
    //
    // spec = {
    //   name: 'MyClass',          // must not collide with existing class
    //   donor: 'Greeter',          // optional; defaults to Greeter (must have
    //                              // matching method shape — same names+sigs
    //                              // as the methods the user wants to define)
    //   methods: {
    //     answer: function() { Marrow.log('answered'); return 99; }
    //                              // JS callback fires on every call; for
    //                              // primitive returns, the function's return
    //                              // value (Number) is auto-applied via
    //                              // setReturn IF it can be encoded.
    //   }
    // }
    registerClass: function(spec) {
        if (!spec || !spec.name)
            throw new Error("registerClass: spec.name is required");
        var donorName = spec.donor || "Greeter";
        var newName   = spec.name;
        var methods   = spec.methods || {};

        // Step 1: deep-clone donor — Methods/ConstMethods in agent pages.
        var donor = Java.use(donorName);
        if (!donor)
            throw new Error("registerClass: donor " + donorName + " not loaded");
        var cloneInfo = Marrow.cloneClassDeep(donor.$klass, newName);
        if (!cloneInfo)
            throw new Error("registerClass: deep-clone failed");

        // Step 2: drop the cached use proxy so the new lookup builds with
        // the new Klass; init via PDB-driven initialize.
        delete Java._useCache[newName];
        try { Java._initializeKlassByName(newName); }
        catch (e) { Marrow.log("[registerClass] init warn: " + e); }

        var cls = Java.use(newName);

        // Step 3+4: wire user callbacks. For each method, set the JS
        // implementation. If the user fn returns a constant, also pre-set
        // it via setReturn for primitive methods (so Java callers see it).
        Object.keys(methods).forEach(function(mname) {
            var handle = cls[mname];
            if (!handle)
                throw new Error("registerClass: " + newName + " has no method " + mname);
            var fn = methods[mname];
            if (typeof fn !== "function")
                throw new Error("registerClass: methods." + mname + " must be a function");
            handle.implementation = fn;
        });
        return cls;
    },

    // Java.deoptimizeEverything() — clears Method::_code on every loaded
    // method so future dispatch routes through the interpreter, not
    // stale JIT'd nmethods. Call before installing hooks on hot methods
    // to ensure the patched _i2i_entry is actually visited. Returns the
    // number of methods cleared.
    deoptimizeEverything: function() {
        return Marrow._deoptimizeAll();
    },

    // Drive HotSpot's InstanceKlass::initialize on the most-recently-
    // defined class. Resolves the InstanceKlass::initialize and
    // JavaThread::current addresses from PDB and invokes them via
    // _callNative. Uses ClassWalker's most-recent entry as the target —
    // works because defineClass appends to the SystemDictionary tail.
    // Resolves Klass by name via SystemDictionary scan, then drives
    // InstanceKlass::initialize through agent_javacall's PDB-aware path.
    // No bootstrap-side caching of native addresses — agent_javacall
    // re-resolves per call to dodge DbgHelp state drift across modules.
    _initializeKlassByName: function(className) {
        var k = Marrow.findClass(className);
        if (!k)
            throw new Error("_initializeKlassByName: " + className + " not loaded");
        var ok = Marrow._initializeKlass(k);
        if (!ok)
            throw new Error("_initializeKlassByName: native init failed for " + className);
    },

    // Java.openClassFile(path, className?) -> { load(loader?) }
    // Frida-style: read a .class file from disk, give back a handle whose
    // .load() injects it into the JVM via ClassLoader.defineClass and
    // drives InstanceKlass::initialize so methods get _i2i_entry set.
    //
    // className defaults to the basename of `path` minus ".class". Pass
    // explicitly when the file is renamed or in a package.
    //
    // Requires JavaCalls path (PDB available). Throws otherwise.
    openClassFile: function(path, className) {
        if (!Java._jcReady())
            throw new Error("openClassFile: JavaCalls path unavailable (no jvm.dll.pdb)");
        var bytes = Marrow._readFile(path);
        if (!bytes)
            throw new Error("openClassFile: cannot read " + path);
        if (!className) {
            className = path.replace(/.*[\/\\]/, "").replace(/\.class$/, "");
        }
        var handleName = className;
        var handleBytes = bytes;
        return {
            $bytes: bytes,
            $path: path,
            $name: className,
            load: function(classLoaderOop) {
                // Pure-internal path: no Java implementation in the chain.
                // JVM_DefineClass is HotSpot's C entry that JNI's Java
                // bindings ultimately call into; we go straight to it.
                // No byte[] allocation in the heap, no ClassLoader.java,
                // no SystemDictionary->ClassLoader round-trip.
                var loaderHex = (classLoaderOop && classLoaderOop.$oop)
                              ? classLoaderOop.$oop
                              : classLoaderOop || null;
                var classMirrorOop = Marrow._defineClassNative(
                    handleName.replace(/\//g, "."),  // JVM_DefineClass uses dotted names
                    bytes, loaderHex);
                if (!classMirrorOop || classMirrorOop === "0x0")
                    throw new Error("openClassFile.load: JVM_DefineClass returned null");
                // JVM_DefineClass loads but does NOT link/init the class.
                // Drive InstanceKlass::initialize directly so methods get
                // _i2i_entry populated and become invocable.
                Java._initializeKlassByName(handleName);
                return classMirrorOop;
            }
        };
    },

    // Java.perform(fn) — Frida's idiom: run setup code with errors caught
    // and reported, no JVM-attach machinery (we attach lazily anyway).
    perform: function(fn) {
        try { fn(); }
        catch (e) {
            Marrow.log("[Java.perform] threw: " +
                          (e && e.stack ? e.stack : e));
            throw e;
        }
    },

    // Java.array(typeChar, jsArr) — allocate a Java array initialised
    // from a JS Array. typeChar is one of I/J/F/D/B/S/C/Z/L. Returns the
    // wide oop hex of the new array, ready to pass to Java.invoke as an
    // L-typed argument. Throws on unsupported types.
    array: function(typeChar, jsArr) {
        if (!Array.isArray(jsArr))
            throw new Error("Java.array: 2nd arg must be a JS Array");
        var n = jsArr.length;
        var oopHex = Marrow._allocTypeArray(typeChar, n);
        if (!oopHex || oopHex === "0x0")
            throw new Error("Java.array: alloc failed for [" + typeChar);
        var dataOff = (typeChar === 'C' || typeChar === 'S') ? 16
                    : (typeChar === 'I' || typeChar === 'F') ? 16
                    : (typeChar === 'J' || typeChar === 'D') ? 16
                    : 16;
        var elemSize = (typeChar === 'B' || typeChar === 'Z') ? 1
                     : (typeChar === 'C' || typeChar === 'S') ? 2
                     : (typeChar === 'I' || typeChar === 'F') ? 4
                     : (typeChar === 'J' || typeChar === 'D') ? 8 : 4;
        var base = parseInt(oopHex, 16) + dataOff;
        var bytes = new Array(n * elemSize);
        for (var i = 0; i < n; ++i) {
            var v = jsArr[i];
            if (typeChar === 'J' || typeChar === 'D') {
                var u = (typeof v === 'string')
                      ? parseInt(v, v.indexOf('0x') === 0 ? 16 : 10)
                      : v;
                // 64-bit write via two 32-bit halves; JS Number handles
                // up to 2^53 cleanly which suffices for typical longs.
                var lo = u & 0xFFFFFFFF;
                var hi = (typeof u === 'number')
                       ? Math.floor(u / 0x100000000) & 0xFFFFFFFF
                       : 0;
                bytes[i*8+0] =  lo        & 0xFF;
                bytes[i*8+1] = (lo >>> 8) & 0xFF;
                bytes[i*8+2] = (lo >>>16) & 0xFF;
                bytes[i*8+3] = (lo >>>24) & 0xFF;
                bytes[i*8+4] =  hi        & 0xFF;
                bytes[i*8+5] = (hi >>> 8) & 0xFF;
                bytes[i*8+6] = (hi >>>16) & 0xFF;
                bytes[i*8+7] = (hi >>>24) & 0xFF;
            } else if (elemSize === 4) {
                var iv = (v|0) >>> 0;
                bytes[i*4+0] =  iv        & 0xFF;
                bytes[i*4+1] = (iv >>> 8) & 0xFF;
                bytes[i*4+2] = (iv >>>16) & 0xFF;
                bytes[i*4+3] = (iv >>>24) & 0xFF;
            } else if (elemSize === 2) {
                var sv = v & 0xFFFF;
                bytes[i*2+0] =  sv       & 0xFF;
                bytes[i*2+1] = (sv >>> 8) & 0xFF;
            } else {
                bytes[i] = v & 0xFF;
            }
        }
        if (n > 0) Marrow._writeMem("0x" + base.toString(16), bytes);
        return oopHex;
    },

    // Decode JavaCalls "{type:N, value:0xV}" result into a useful JS value.
    // Bare strings or already-unwrapped values pass through unchanged.
    _unwrap: function(r, returnTypeSig) {
        // returnTypeSig is one of:
        //   undefined / null  → no auto-cast (raw oop hex for T_OBJECT/T_ARRAY)
        //   "java/lang/X"     → bare class name; for T_OBJECT, Java.cast applies
        //   "[Ljava/lang/X;"  → array sig fragment; for T_ARRAY, _castArray applies
        //   "[I", "[B", ...   → primitive-element array sig fragments
        //
        // Backward compat: callers that still pass a bare class name for
        // T_OBJECT keep working. Array auto-cast only fires when the caller
        // passes the full "[..." fragment.
        if (typeof r !== "string") return r;
        var m = r.match(/^\{type:(\d+),\s*value:0x([0-9a-f]+)\}$/);
        if (!m) return r;
        var type = parseInt(m[1], 10);
        var hex  = m[2];
        switch (type) {
            case 14: return undefined;                 // T_VOID
            case 4:  return hex !== "0";               // T_BOOLEAN
            case 5: case 8: case 9: case 10: {         // T_CHAR/BYTE/SHORT/INT
                var n = parseInt(hex.slice(-8), 16);
                if (n >= 0x80000000) n -= 0x100000000; // sign-extend
                return n;
            }
            case 11: return "0x" + hex;                // T_LONG (precision)
            case 6: case 7: return "0x" + hex;         // T_FLOAT/T_DOUBLE bits
            case 12: case 13:                          // T_OBJECT / T_ARRAY
                // The C++ JNI/JC surface emits type=12 for everything
                // reference-typed including arrays; type=13 isn't actually
                // produced. We dispatch on the return type signature
                // string instead: leading '[' → array, otherwise plain
                // class. Falls back to raw oop hex if the cast / array
                // decode fails.
                if (hex === "0") return null;
                var ooph = "0x" + hex;
                if (returnTypeSig) {
                    try {
                        return (returnTypeSig.charAt(0) === '[')
                             ? Java._castArray(ooph, returnTypeSig)
                             : Java.cast(ooph, returnTypeSig);
                    } catch (e) { return ooph; }
                }
                return ooph;
            default: return r;
        }
    },

    // Eagerly decode a Java array into a JS array enhanced with $oop,
    // $length, $elementSig — supports both iteration ([i], length) and
    // pass-through to other Java methods (their _coerceArg sees $oop).
    //
    // Element decode policy:
    //   primitive arrays ([I, [B, [J, [D, ...) → Number per slot
    //   object arrays ([Ljava/lang/X;)         → cast'd proxies per slot
    //
    // Bound at 4096 elements to keep one-shot decodes from blowing
    // duktape memory on huge byte[] payloads. For larger arrays we keep
    // $oop and $length set but $truncated=true; caller can chunk via
    // Marrow._readArray(oop, kind, n) directly.
    _castArray: function(oopHex, sigFragment) {
        // sigFragment like "[Ljava/lang/String;" or "[B" or "[[I".
        // Skip leading '['s to find the element kind.
        var depth = 0;
        while (depth < sigFragment.length && sigFragment.charAt(depth) === '[')
            ++depth;
        var elem = sigFragment.charAt(depth);
        var elemClass = null;
        if (elem === 'L') {
            // Strip leading 'L' + trailing ';'.
            elemClass = sigFragment.substring(depth + 1, sigFragment.length - 1);
        }
        var EAGER_LIMIT = 4096;
        // Marrow._readArray returns null for invalid oops, an array
        // otherwise. Type-letter argument matches the element kind.
        var elemTypeChar = elem;
        // Multi-dimensional arrays decode as object array (each elem is
        // another array oop).
        if (depth > 1) elemTypeChar = 'L';
        var raw = null;
        try { raw = Marrow._readArray(oopHex, elemTypeChar, EAGER_LIMIT); }
        catch (e) { /* fall through with empty */ }
        var out = (raw && raw.length) ? raw.slice() : [];
        // For object-element arrays, decode each oop into a cast'd
        // proxy. Skips nulls and oops we can't decode.
        if (elemTypeChar === 'L' && elemClass) {
            for (var i = 0; i < out.length; ++i) {
                var v = out[i];
                if (typeof v !== 'string' || v === '0x0') { out[i] = null; continue; }
                try { out[i] = Java.cast(v, elemClass); }
                catch (e) { /* leave raw */ }
            }
        }
        out.$oop = oopHex;
        out.$elementSig = sigFragment.substring(depth);
        out.$depth = depth;
        out.$truncated = (raw && raw.length === EAGER_LIMIT) ? true : false;
        return out;
    },
)JS"
// MSVC ~16K split point.
R"JS(

    // Convert a Frida-style Java type string ("int", "java.lang.String",
    // "[Ljavax.net.ssl.KeyManager;") to a JVM-internal type signature
    // letter / fragment ("I", "Ljava/lang/String;", "[Ljavax/net/ssl/KeyManager;").
    // Used by .overload(...) variadic form.
    _fridaTypeToJvm: function(t) {
        var prim = {
            "void": "V", "int": "I", "long": "J", "double": "D", "float": "F",
            "byte": "B", "char": "C", "short": "S", "boolean": "Z"
        };
        if (Object.prototype.hasOwnProperty.call(prim, t)) return prim[t];
        // Already an array signature (starts with '[') — just slash it.
        if (t.charAt(0) === '[') return t.replace(/\./g, '/');
        // Plain class name in dotted or slashed form → wrap as Lname;.
        return 'L' + t.replace(/\./g, '/') + ';';
    },

    // Extract the return type's auto-cast hint from a JVM method
    // signature. _unwrap discriminates by the leading char:
    //   "(II)Ljava/lang/String;" → "java/lang/String" (bare class)
    //   "(II)[Ljava/lang/X;"     → "[Ljava/lang/X;"   (array sig fragment)
    //   "(II)[I"                 → "[I"               (prim array fragment)
    //   "(II)I"                  → null               (primitive — no cast)
    //   "(II)V"                  → null               (void)
    _returnClassFromSig: function(sig) {
        var rp = sig.indexOf(')');
        if (rp < 0) return null;
        var ret = sig.substring(rp + 1);
        if (ret.charAt(0) === 'L' && ret.charAt(ret.length - 1) === ';')
            return ret.substring(1, ret.length - 1);
        if (ret.charAt(0) === '[') return ret;       // array sig — full fragment
        return null;
    },
)JS"
// MSVC ~16K split point — concatenation joins next fragment.
R"JS(
    // Pick the overload whose signature matches the JS argument shape.
    // Match rules: arg count must match, and each JS arg's "kind"
    // (number / string-as-hex-oop / boolean) must align with the
    // signature letter (primitive vs L/[ object).
    _pickOverload: function(handle, jsArgs, className) {
        var overloads = handle.$overloads || [];
        if (overloads.length === 0)
            throw new Error("no overloads on " + className);

        function classify(v) {
            if (typeof v === 'boolean') return 'prim';
            if (typeof v === 'number')  return 'prim';
            if (typeof v === 'string')  return 'oop'; // hex / JS literal
            if (v === null || v === undefined) return 'oop';
            // Java.cast'd instance proxy: has $oop / $class / $klass.
            if (typeof v === 'object' && v.$oop) return 'oop';
            return 'unknown';
        }

        var jsKinds = jsArgs.map(classify);
        var best = null;
        var bestScore = -1;
        for (var i = 0; i < overloads.length; ++i) {
            var sig = overloads[i].sig;
            var rp  = sig.indexOf(')');
            // Parse arg-type letters between '(' and ')'.
            var letters = [];
            for (var j = 1; j < rp; ++j) {
                var c = sig.charAt(j);
                if (c === '[') {
                    while (sig.charAt(j) === '[') ++j;
                    if (sig.charAt(j) === 'L')
                        while (j < rp && sig.charAt(j) !== ';') ++j;
                    letters.push('L');
                } else if (c === 'L') {
                    while (j < rp && sig.charAt(j) !== ';') ++j;
                    letters.push('L');
                } else {
                    letters.push(c);
                }
            }
            if (letters.length !== jsKinds.length) continue;
            // Score per arg: matching kind = +1.
            var score = 0;
            for (var k = 0; k < letters.length; ++k) {
                var sigKind = (letters[k] === 'L') ? 'oop' : 'prim';
                if (jsKinds[k] === sigKind) score++;
            }
            if (score > bestScore) {
                bestScore = score;
                best = overloads[i];
            }
        }
        if (!best)
            throw new Error("$new: no constructor of " + className +
                            " matches arity=" + jsArgs.length);
        return Java._makeSingle(handle.$cls, handle.$name || '<init>', best);
    },

    // Bind a static-method handle to a specific receiver. Returned function
    // does Java.invoke(h, oopHex, args) and unwraps the result.
    _bindMethod: function(handle, oopHex) {
        var bound = function() {
            var args = Array.prototype.slice.call(arguments);
            return Java._unwrap(Java.invoke(handle, oopHex, args),
                                  handle.$returnClass);
        };
        bound.$bound        = true;
        bound.$boundOop     = oopHex;
        bound.$method       = handle.$method;
        bound.$sig          = handle.$sig;
        bound.$returnClass  = handle.$returnClass;
        bound.argumentTypes = handle.argumentTypes;
        bound.returnType    = handle.returnType;
        return bound;
    },

    _impls: {},

    _parseHex: function(hex) {
        // hex like "0x1234abcd5678" -> {lo: u32, hi: u32}
        var s = hex.indexOf("0x") === 0 ? hex.slice(2) : hex;
        if (s.length <= 8) return { lo: parseInt(s, 16), hi: 0 };
        var hi = parseInt(s.slice(0, s.length - 8), 16);
        var lo = parseInt(s.slice(s.length - 8), 16);
        return { lo: lo, hi: hi };
    },

)JS"
// MSVC ~16K split point — concatenation joins next fragment.
R"JS(
    // Wrap an oop into an instance proxy with direct property access per the
    // class's declared instance fields. Read: `inst.score`. Write: `inst.score = 99`.
    // Setters auto-convert JS Numbers → hex strings for J/D so 64-bit longs JustWork.
    // Oop-typed fields read as hex string; for nested objects, re-cast manually:
    //   var nested = Java.cast(inst.someRef, 'OtherClass');
    // Per-class instance-fields metadata cache. _klassFields walks the field
    // stream which is expensive (CP touching → potential SuspendAll); cache
    // once per class lifetime.
    _classFieldsCache: {},
    // Per-class proxy *prototype* cache. We build the prototype with field
    // accessors + bound methods ONCE per class, then every Java.cast on
    // that class is just Object.create(proto) + 3 own-property assigns.
    // Without this, each L-typed return autocast was paying ~50 defineProperty
    // calls for a class like Certificate — measured at ~420 us/cast on
    // JDK 17. With it: ~5 us/cast. Hot-loop friendly.
    _castProtoCache: {},

    // Build the shared prototype for `className`: defines accessors that
    // read this.$oop, and binds instance methods that route via this.$oop
    // to Java.invoke. Called at most once per class lifetime.
    _buildCastProto: function(cls, className) {
        var proto = {};
        var fields = Java._classFieldsCache[className];
        if (!fields) {
            try {
                fields = Marrow._klassFields(cls.$klass, false);
                Java._classFieldsCache[className] = fields;
            } catch (e) {
                Marrow.log('[cast] field enum failed for ' + className + ': ' + e);
                return proto;  // bare proto — caller still gets $oop/$class
            }
        }
        for (var i = 0; i < fields.length; ++i) {
            (function(fname, sig) {
                var sigChar = sig ? sig.charAt(0) : '\0';
                var isString = sig === 'Ljava/lang/String;';
                Object.defineProperty(proto, fname, {
                    get: function() {
                        var raw = Java.readField(this.$oop, className, fname);
                        if (isString && typeof raw === 'string' &&
                            raw.indexOf('0x') === 0 && raw !== '0x0') {
                            try { return Java.toString(raw); }
                            catch (e) { return raw; }
                        }
                        return raw;
                    },
                    set: function(v) {
                        if ((sigChar === 'J' || sigChar === 'D') && typeof v === 'number') {
                            v = (v < 0 ? '-0x' + Math.abs(v).toString(16)
                                       : '0x' + v.toString(16));
                        }
                        if (isString && typeof v === 'string' &&
                            v.indexOf('0x') !== 0) {
                            var allocated = Java._jstring(v);
                            if (allocated) v = allocated;
                            else throw new Error(
                                "field set: cannot allocate Java String " +
                                "(no JavaCalls); pass an oop hex instead");
                        }
                        Java.writeField(this.$oop, className, fname, v);
                    },
                    enumerable: true,
                    configurable: true
                });
                if (isString) {
                    Object.defineProperty(proto, '$oop_' + fname, {
                        get: function() {
                            return Java.readField(this.$oop, className, fname);
                        },
                        configurable: true
                    });
                }
            })(fields[i].name, fields[i].sig);
        }
        // Bind instance methods. Use _bindMethodOnThis variant which reads
        // the receiver oop from `this.$oop` instead of closing over a
        // particular instance — that's what makes the prototype shareable.
        var seen = {};
        for (var k in cls) {
            if (!Object.prototype.hasOwnProperty.call(cls, k)) continue;
            if (k.charAt(0) === '$') continue;
            if (k === '<init>' || k === '<clinit>') continue;
            if (seen[k]) continue;
            var h = cls[k];
            if (typeof h !== 'function') continue;
            seen[k] = true;
            if (!Object.prototype.hasOwnProperty.call(proto, k)) {
                proto[k] = Java._bindMethodOnThis(h);
            }
        }
        return proto;
    },

    cast: function(oopHex, classRef) {
        // Accept either a class name string ("java/lang/String" or
        // "java.lang.String") or a Java.use'd handle (whose $name carries
        // the JVM-internal slashed form). Frida-style: Java.cast(oop, T)
        // where T = Java.use(...) is common in copy-pasted scripts.
        var className = (typeof classRef === 'string')
            ? classRef
            : (classRef && classRef.$name ? classRef.$name : null);
        if (!className)
            throw new Error("Java.cast: second arg must be a class name " +
                            "string or a Java.use() handle");
        var cls = Java.use(className);
        className = cls.$name;
        // Fetch or lazily build the shared prototype for this class.
        var proto = Java._castProtoCache[className];
        if (!proto) {
            proto = Java._buildCastProto(cls, className);
            Java._castProtoCache[className] = proto;
        }
        // Per-instance object: $oop + $class + $klass on top of the shared
        // accessor / method prototype. Object.create + 3 prop assigns is
        // ~5 us in Duktape vs the ~420 us of the per-instance defineProperty
        // loop we used before this change.
        var instance = Object.create(proto);
        instance.$oop = oopHex;
        instance.$class = className;
        instance.$klass = cls.$klass;
        return instance;
    },

    // Like _bindMethod but reads the receiver from `this.$oop` at call
    // time instead of capturing it in a closure. Lives on a Java.cast
    // prototype so all instances of the same class share the same bound
    // function. Handles both single-overload and multi-overload handles —
    // for the latter we re-pick on every call based on JS arg shapes.
    _bindMethodOnThis: function(handle) {
        var isMulti = handle && handle.$overloads &&
                      handle.$overloads.length > 1 &&
                      !handle.$method;  // single has $method, multi doesn't
        var bound = function() {
            var args = Array.prototype.slice.call(arguments);
            var thisOop = this && this.$oop ? this.$oop : "0x0";
            var resolved = isMulti
                ? Java._pickOverload(handle, args,
                                       handle.$cls && handle.$cls.$name || '?')
                : handle;
            return Java._unwrap(Java.invoke(resolved, thisOop, args),
                                  resolved.$returnClass);
        };
        bound.$bound        = true;
        bound.$method       = handle.$method;
        bound.$sig          = handle.$sig;
        bound.$returnClass  = handle.$returnClass;
        bound.argumentTypes = handle.argumentTypes;
        bound.returnType    = handle.returnType;
        return bound;
    },

    // Frida-style: enumerate all instances of a class.
    // callbacks = { onMatch: function(instance), onComplete: function(),
    //               limit?: int, safe?: bool }
    //
    // Heap scan runs WITHOUT thread suspension by default — findInstances
    // reads memory chunk-by-chunk under SEH so concurrent mutator activity
    // can't crash the scanner. Tradeoff: a freshly-allocated instance
    // racing against the scan may be missed (caller can re-run). Pass
    // `safe: true` to opt into the legacy SuspendAll behaviour for cases
    // where strict consistency is required.
    choose: function(name, callbacks) {
        var cls   = Java.use(name);
        var limit = callbacks.limit || 0;
        var oops  = callbacks.safe
                  ? Java.safe(function(){ return Marrow.findInstances(cls.$klass, limit); })
                  : Marrow.findInstances(cls.$klass, limit);
        for (var i = 0; i < oops.length; ++i) {
            var instance = Java.cast(oops[i], name);
            try { callbacks.onMatch(instance); }
            catch (e) { Marrow.log("[choose.onMatch err] " + e); }
        }
        if (callbacks.onComplete) {
            try { callbacks.onComplete(); }
            catch (e) { Marrow.log("[choose.onComplete err] " + e); }
        }
        return oops.length;
    },

    // Filtered heap walker. The C side reads each candidate's field
    // inside a SEH-protected try/catch (see agent_heapfilter.cpp), so
    // a moving object during the scan just fails to match — no crash.
    // No global suspend needed; pass {safe:true} as a 6th positional
    // (or use Java.safe yourself) for strict consistency.
    findBy: function(className, fieldName, type, expectedValue, limit, safe) {
        var cls = Java.use(className);
        if (safe) {
            return Java.safe(function() {
                return Marrow._findInstancesByField(
                    cls.$klass, fieldName, type || 'I',
                    expectedValue, limit || 0);
            });
        }
        return Marrow._findInstancesByField(
            cls.$klass, fieldName, type || 'I',
            expectedValue, limit || 0);
    },

    // Race-free CP dump — the ConstantPool is constantly being mutated by
    // the interpreter as it resolves CP entries (Symbol* → Klass*/Method*).
    // Reading it without freezing the JVM segfaults. Wrap it.
    cpDump: function(className, maxEntries) {
        var cls = Java.use(className);
        return Java.safe(function() {
            return Marrow._cpDump(cls.$klass, maxEntries || 64);
        });
    },

    // Frida-style: enumerate ClassLoaderData entries.
    // callbacks = { onMatch: function({addr, klasses}), onComplete }
    enumerateClassLoaders: function(callbacks) {
        var loaders = Marrow.classLoaders();
        for (var i = 0; i < loaders.length; ++i) {
            try { callbacks.onMatch(loaders[i]); }
            catch (e) { Marrow.log("[loader.onMatch err] " + e); }
        }
        if (callbacks.onComplete) {
            try { callbacks.onComplete(); }
            catch (e) { Marrow.log("[loader.onComplete err] " + e); }
        }
        return loaders.length;
    },

    // Inspect which methods of a class are currently JIT-compiled.
    // Returns array of {name, sig, jitCompiled, codePtr}.
    checkJit: function(className) {
        var cls = Java.use(className);
        return Marrow.checkJit(cls.$klass);
    },

    // Install counting hook on every method of class. Returns
    // {cookieBase, methods: [{name, sig, cookie}]}. Read counts via
    // Marrow.readCount(cookie) or `Java.readTraces(...)` helper.
    traceClass: function(className, cookieBase) {
        var cls = Java.use(className);
        var ms = Marrow.listMethods(cls.$klass);
        var base = cookieBase || 0xC0DE0000;
        var n = Marrow._traceClass(cls.$klass, base);
        var out = [];
        for (var i = 0; i < ms.length; ++i) {
            out.push({ name: ms[i].name, sig: ms[i].sig,
                       cookie: base + i });
        }
        return { cookieBase: base, installed: n, methods: out };
    },

    readTraces: function(traceResult) {
        var stats = [];
        for (var i = 0; i < traceResult.methods.length; ++i) {
            var m = traceResult.methods[i];
            var c = Marrow.readCount(m.cookie);
            if (c > 0) stats.push({ name: m.name, sig: m.sig, count: c });
        }
        stats.sort(function(a,b){ return b.count - a.count; });
        return stats;
    },

    // L1 clone of a class (registered in CLDG). Returns the clone Klass
    // hex addr — JS code can chain to other ops, e.g. install hooks on
    // the clone's methods independently from the donor.
    cloneClass: function(donorClassName, newName) {
        var donor = Java.use(donorClassName);
        var c = Marrow.cloneClass(donor.$klass, newName);
        return c;
    },

    // Heap snapshot: top N most-populated classes by instance count.
    // Returns [{name, count, klass}].
    snapshotHeap: function(topN) {
        return Marrow.snapshotHeap(topN || 32);
    },

    // Heap diff: snapshot now, return helper to compare against a future
    // snapshot. Frida-style "diff snapshots" use case for leak hunting.
    snapshotForDiff: function() {
        var s1 = Java.snapshotHeap(2000);
        var by1 = {};
        s1.forEach(function(e){ by1[e.name] = e.count; });
        return {
            takenAt: s1.length + " classes seen",
            diff: function() {
                var s2 = Marrow.snapshotHeap(2000);
                var changes = [];
                s2.forEach(function(e){
                    var was = by1[e.name] || 0;
                    if (e.count !== was)
                        changes.push({name:e.name, before:was, after:e.count, delta:e.count-was});
                });
                changes.sort(function(a,b){ return Math.abs(b.delta) - Math.abs(a.delta); });
                return changes;
            }
        };
    },

    // Hardware-watchpoint on a static reference field of a class. Returns
    // a cookie usable with `Java.unwatch(cookie)`. Each write triggers an
    // event drainable via `Java.drainWatches()`.
    //
    // NOTE: this is a UNIQUE feature not in Frida — we use real CPU
    // debug registers (DR0-DR3) for byte-level write detection without
    // patching method bodies.
    watchField: function(className, fieldName, length) {
        var cls = Java.use(className);
        // Resolve the mirror oop + field offset → absolute slot address.
        var ref = Marrow.readStaticRef(cls.$klass, fieldName);
        if (!ref) throw new Error("field not found / null: " + fieldName);
        // Currently we watch the holding slot inside the mirror. The
        // mirror oop + field offset is already a stable address. Decode
        // raw addr from cls.$klass + field offset via reading mirror.
        // For MVP: derive from Marrow._fieldSlot binding — but we don't
        // have one yet. Workaround: derive via _muteMethod-style probing
        // is overkill. Add helper below in C++.
        var slot = Marrow._fieldSlotAddr(cls.$klass, fieldName);
        if (!slot) throw new Error("field slot address unresolved");
        var p = Java._parseHex(slot);
        return Marrow.watchAddr(p.lo, p.hi, length || 4, 0);
    },
    unwatch: function(cookie) { return Marrow.unwatch(cookie); },
    drainWatches: function() { return Marrow.drainWatches(); },

    // Hotkey API. Frida has nothing analogous — this is unique to marrow.
    // Register a callback for a Win32 virtual-key code. The agent's poll
    // thread observes 0→1 transitions; the callback fires once per press
    // when the user calls Java.tickKeys() (or Java.drainKeys() for raw
    // events). VKs: 0x70..0x7B = F1..F12, 0x41='A', etc.
    _keyHandlers: {},
    onKey: function(vk, fn) {
        if (typeof fn !== "function")
            throw new Error("onKey: fn must be a function");
        Marrow._registerKey(vk);
        Java._keyHandlers[vk] = fn;
    },
    drainKeys: function() {
        return Marrow._drainKeys();
    },
    // Drain pending key events and invoke registered handlers. Returns
    // count of handler invocations.
    tickKeys: function() {
        var ev = Marrow._drainKeys();
        var fired = 0;
        for (var i = 0; i < ev.length; ++i) {
            var fn = Java._keyHandlers[ev[i].vk];
            if (!fn) continue;
            for (var k = 0; k < ev[i].delta; ++k) {
                try { fn.call(null, ev[i].vk); ++fired; }
                catch (e) { Marrow.log("[onKey err vk=" + ev[i].vk + "] " + e); }
            }
        }
        return fired;
    },
)JS"
// MSVC enforces a ~16k limit per string literal; split here and let the
// preprocessor concatenate the two raw-string fragments into one chunk.
R"JS(

    // Parse a JVM method signature like "(IJLjava/lang/String;[B)V" into
    // {args: [{type, className?}, ...], ret: 'V'}. Each arg is an object;
    // L types carry the className so drain can auto-cast oop args.
    parseSig: function(sig) {
        var i = 0, args = [];
        if (sig.charAt(0) !== '(') throw new Error("bad sig: " + sig);
        ++i;
        while (i < sig.length && sig.charAt(i) !== ')') {
            var c = sig.charAt(i);
            if (c === 'L') {
                ++i;
                var start = i;
                while (i < sig.length && sig.charAt(i) !== ';') ++i;
                args.push({ type: 'L', className: sig.slice(start, i) });
                ++i;  // skip ';'
            } else if (c === '[') {
                var depth = 0;
                while (i < sig.length && sig.charAt(i) === '[') { ++depth; ++i; }
                var elem = sig.charAt(i);
                if (elem === 'L') {
                    ++i;
                    var astart = i;
                    while (i < sig.length && sig.charAt(i) !== ';') ++i;
                    args.push({ type: '[', depth: depth,
                                elementType: 'L', className: sig.slice(astart, i) });
                    ++i;
                } else {
                    args.push({ type: '[', depth: depth, elementType: elem });
                    ++i;
                }
            } else {
                args.push({ type: c });
                ++i;
            }
        }
        return { args: args, ret: sig.charAt(i + 1) || 'V' };
    },

    // Decode args from the captured stack at hook entry. For interpreted
    // methods, args sit at [rsp+8]+ as 8-byte slots (long/double take 2).
    // For JIT-compiled callers, args live in registers — that path is
    // partially supported via Java.regs(cookie) ∪ stack snapshot.
    //
    // NOTE: this is a best-effort decoder. Returns array of {type, raw,
    // value} entries; `value` is null for unknown/oop types where caller
    // should chain with Marrow.readStaticString or similar.
    // Helper: convert hex qword to typed primitive value per JVM type tag.
    // Auto-cast L types to instance proxy (Frida-style — direct field access).
    _decodeSlot: function(arg, raw) {
        var t = arg.type;
        if (t === 'I' || t === 'B' || t === 'S' || t === 'C' || t === 'Z') {
            var lo = parseInt(raw.slice(-8), 16);
            if (lo >= 0x80000000 && t === 'I') lo -= 0x100000000;
            return lo;
        }
        if (t === 'L') {
            // Auto-cast to instance proxy. If the className is unknown or
            // class not loaded, fall back to raw oop hex.
            try { return Java.cast(raw, arg.className); }
            catch (e) { return raw; }
        }
        return raw; // J/D/F/[ → caller-side decode
    },

    // Decode args from the captured snapshot at hook entry.
    // - If via=0 (interpreter), args sit on the operand stack at
    //   [rsp+8]+ in REVERSE signature order, with 'this' farthest.
    // - If via=1 (JIT compiled-entry), args live in registers per
    //   HotSpot's Java calling convention. On Win x64 HotSpot uses:
    //     instance method receiver: rcx
    //     args[0..5]: rdx, r8, r9, rdi, rsi, then stack
    //   (This is the "shifted-from-Win-x64" Java ABI; verified
    //   empirically by hooking a JIT'd method and watching which
    //   reg holds a known monotonic int.)
    decodeArgs: function(cookie, sig, isInstance, thisClassName) {
        var parsed = (typeof sig === 'string') ? Java.parseSig(sig) : sig;
        var via = Marrow._lastVia(cookie);
        if (via === 0) return Java._decodeArgsInterp(cookie, parsed, isInstance, thisClassName);
        if (via === 1) return Java._decodeArgsCompiled(cookie, parsed, isInstance, thisClassName);
        return null;
    },

    decodeArgsAt: function(cookie, sig, isInstance, eventIndex, thisClassName) {
        var parsed = (typeof sig === 'string') ? Java.parseSig(sig) : sig;
        var via = Marrow._lastVia(cookie, eventIndex);
        if (via === 0) return Java._decodeArgsInterpAt(cookie, parsed, isInstance, eventIndex, thisClassName);
        if (via === 1) return Java._decodeArgsCompiledAt(cookie, parsed, isInstance, eventIndex, thisClassName);
        return null;
    },

    _decodeArgsInterp: function(cookie, parsed, isInstance, thisClassName) {
        var stk = Marrow._lastStack(cookie);
        if (!stk) return null;
        var slots = [];
        var idx = 1; // skip retaddr
        for (var i = parsed.args.length - 1; i >= 0; --i) {
            var arg = parsed.args[i];
            var raw = stk[idx];
            var entry = { type: arg.type, raw: raw, value: Java._decodeSlot(arg, raw) };
            if (arg.type === 'J' || arg.type === 'D') ++idx;
            ++idx;
            slots.push(entry);
        }
        slots.reverse();
        if (isInstance && idx <= stk.length - 1) {
            var thisOop = stk[idx];
            var thisVal = thisOop;
            if (thisClassName) {
                try { thisVal = Java.cast(thisOop, thisClassName); } catch (e) {}
            }
            slots.unshift({ type: 'L', raw: thisOop, value: thisVal, note: 'this' });
        }
        return slots;
    },

    _decodeArgsCompiled: function(cookie, parsed, isInstance, thisClassName) {
        var R = Java.regs(cookie);
        if (!R) return null;
        var argRegs = ['r8', 'r9', 'rdi', 'rsi'];
        var slots = [];
        if (isInstance) {
            var thisVal = R.rcx;
            if (thisClassName) {
                try { thisVal = Java.cast(R.rcx, thisClassName); } catch (e) {}
            }
            slots.push({ type: 'L', raw: R.rcx, value: thisVal, note: 'this' });
        }
        for (var i = 0; i < parsed.args.length && i < argRegs.length; ++i) {
            var arg = parsed.args[i];
            var raw = R[argRegs[i]];
            slots.push({ type: arg.type, raw: raw, value: Java._decodeSlot(arg, raw) });
        }
        return slots;
    },

    // eventIndex-aware variants used by decodeArgsAt / drain ring iteration.
    _decodeArgsInterpAt: function(cookie, parsed, isInstance, eventIndex, thisClassName) {
        var stk = Marrow._lastStack(cookie, eventIndex);
        if (!stk) return null;
        var slots = [];
        var idx = 1;
        for (var i = parsed.args.length - 1; i >= 0; --i) {
            var arg = parsed.args[i];
            var raw = stk[idx];
            var entry = { type: arg.type, raw: raw, value: Java._decodeSlot(arg, raw) };
            if (arg.type === 'J' || arg.type === 'D') ++idx;
            ++idx;
            slots.push(entry);
        }
        slots.reverse();
        if (isInstance && idx <= stk.length - 1) {
            var thisOop = stk[idx];
            var thisVal = thisOop;
            if (thisClassName) {
                try { thisVal = Java.cast(thisOop, thisClassName); } catch (e) {}
            }
            slots.unshift({ type: 'L', raw: thisOop, value: thisVal, note: 'this' });
        }
        return slots;
    },

    _regsAt: function(cookie, eventIndex) {
        var arr = Marrow._lastRegs(cookie, eventIndex);
        if (!arr) return null;
        var names = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                     "r8","r9","r10","r11","r12","r13","r14","r15"];
        var o = {};
        for (var i = 0; i < 16; ++i) o[names[i]] = arr[i];
        return o;
    },

    _decodeArgsCompiledAt: function(cookie, parsed, isInstance, eventIndex, thisClassName) {
        var R = Java._regsAt(cookie, eventIndex);
        if (!R) return null;
        var argRegs = ['r8', 'r9', 'rdi', 'rsi'];
        var slots = [];
        if (isInstance) {
            var thisVal = R.rcx;
            if (thisClassName) {
                try { thisVal = Java.cast(R.rcx, thisClassName); } catch (e) {}
            }
            slots.push({ type: 'L', raw: R.rcx, value: thisVal, note: 'this' });
        }
        for (var i = 0; i < parsed.args.length && i < argRegs.length; ++i) {
            var arg = parsed.args[i];
            var raw = R[argRegs[i]];
            slots.push({ type: arg.type, raw: raw, value: Java._decodeSlot(arg, raw) });
        }
        return slots;
    },

    // Read latest captured CPU registers from the most recent invocation
    // of a hooked method. Returns object {rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,
    // r8..r15} of hex strings, or null if cookie unknown / no fires yet.
    regs: function(cookie) {
        var arr = Marrow._lastRegs(cookie);
        if (!arr) return null;
        var names = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                     "r8","r9","r10","r11","r12","r13","r14","r15"];
        var o = {};
        for (var i = 0; i < 16; ++i) o[names[i]] = arr[i];
        return o;
    },

)JS"
// Mid-fragment split — MSVC raw-string ~16K limit; concatenated literals
// produce one logical bootstrap string at compile time.
R"JS(

    // Latest stack snapshot at method entry (16 qwords starting at
    // caller-pushed retaddr). Useful for interpreter frame inspection.
    stack: function(cookie) {
        return Marrow._lastStack(cookie);
    },

    // Read one instance field from a live oop. klassName is resolved and
    // cached per call site to avoid repeated ClassWalker scans.
    _klassCache: {},
    readField: function(oopHex, klassName, fieldName) {
        var k = Java._klassCache[klassName];
        if (!k) {
            k = Marrow.findClass(klassName);
            if (!k) return null;
            Java._klassCache[klassName] = k;
        }
        // Auto-suspend the JVM around reads on java/lang/String specifically:
        // its ConstantPool is being actively rewritten by interpreter constant
        // resolution, and find_field walking the live CP races with that.
        // Other classes (Target, etc) are stable — fast path skips the freeze.
        if (klassName === "java/lang/String") {
            return Java.safe(function() {
                return Marrow._readInstanceField(oopHex, k, fieldName);
            });
        }
        return Marrow._readInstanceField(oopHex, k, fieldName);
    },

    // Mutate one instance field. value type must match the field signature:
    //   I/B/S/C/Z/F → JS Number
    //   J/D/L/[     → hex string "0x..." (full 64-bit precision)
    writeField: function(oopHex, klassName, fieldName, value) {
        var k = Java._klassCache[klassName];
        if (!k) {
            k = Marrow.findClass(klassName);
            if (!k) return false;
            Java._klassCache[klassName] = k;
        }
        return Marrow._writeInstanceField(oopHex, k, fieldName, value);
    },

    // ---- Method invocation (calls Java method from JS) ------------
    // T.staticMethod.call(arg0, ...) and T.method.callOn(thisOop, arg0, ...).
    // Returns RAX as a hex string. Up to 4 args (Java ABI register limit).
    // Pass arg oop refs as hex strings; primitives as JS numbers.
    _argToLoHi: function(v) {
        if (typeof v === "number") {
            var lo = (v | 0) >>> 0;
            var hi = (v < 0) ? 0xFFFFFFFF : 0;
            return { lo: lo, hi: hi };
        }
        if (typeof v === "string" && v.indexOf("0x") === 0) {
            return Java._parseHex(v);
        }
        return { lo: 0, hi: 0 };
    },
    // Coerce a JS value to the form _invokeJC / _invokeJNI expect:
    //   primitives → JS Number / String unchanged
    //   instance proxy {$oop} → its oop hex string
    //   plain JS string ("hello") → auto-allocated Java String oop
    //   "0x..." hex string → unchanged (raw oop)
    //   anything else → unchanged (caller's problem)
    //
    // The plain-string allocation is what makes Frida-style calls like
    // `cf.generateCertificate(bis); cf.toString()` and
    // `keyStore.setCertificateEntry("ca", ca)` work without manual
    // Java._jstring sprinkles. _jstring requires the JavaCalls path —
    // when unavailable we leave the string as-is and let the C++ side
    // surface whatever error the underlying method throws.
    _coerceArg: function(v) {
        if (v && typeof v === 'object' && typeof v.$oop === 'string')
            return v.$oop;
        if (typeof v === 'string' && v.indexOf('0x') !== 0) {
            try {
                var oop = Java._jstring(v);
                if (oop) return oop;
            } catch (e) { /* fall through with original string */ }
        }
        return v;
    },
    _coerceArgs: function(arr) {
        if (!arr) return arr;
        var out = [];
        for (var i = 0; i < arr.length; ++i) out.push(Java._coerceArg(arr[i]));
        return out;
    },
    invoke: function(method, thisOop /* hex or proxy */, args /* array */) {
        // Allow passing a Java.cast proxy directly as `thisOop`.
        if (thisOop && typeof thisOop === 'object' && thisOop.$oop)
            thisOop = thisOop.$oop;
        var addrHex = method.address || method.addr ||
                      (method.$method && method.$method.addr);
        var addr = Java._parseHex(addrHex);
        var argv = Java._coerceArgs(args || []);
        // JavaCalls path with receiver: works for interpreted methods too.
        if (Java._jcReady() && thisOop && thisOop !== "0x0") {
            var sig = method["$sig"];
            if (typeof sig !== "string") {
                var inner = method["$method"];
                sig = inner ? inner.sig : "()V";
            }
            if (typeof sig !== "string") sig = "()V";
            var rp = sig.indexOf(")");
            var argLetters = "";
            for (var i = 1; i < rp; ++i) {
                var c = sig.charAt(i);
                if (c === '[') {
                    while (sig.charAt(i) === '[') ++i;
                    if (sig.charAt(i) === 'L')
                        while (i < rp && sig.charAt(i) !== ';') ++i;
                    argLetters += "L";
                } else if (c === 'L') {
                    while (i < rp && sig.charAt(i) !== ';') ++i;
                    argLetters += "L";
                } else {
                    argLetters += c;
                }
            }
            if (argLetters.length === argv.length) {
                var ret = (rp >= 0 && rp + 1 < sig.length)
                          ? sig.charAt(rp + 1) : "V";
                if (ret === "[") ret = "L";
                return Java._unwrap(Marrow._invokeJC(
                    addr.lo, addr.hi, ret, argLetters, argv, thisOop),
                    method.$returnClass || Java._returnClassFromSig(sig));
            }
        }
        var a0 = Java._argToLoHi(argv[0]),
            a1 = Java._argToLoHi(argv[1]),
            a2 = Java._argToLoHi(argv[2]),
            a3 = Java._argToLoHi(argv[3]);
        return Marrow._invokeInstance(
            addr.lo, addr.hi, thisOop || "0x0",
            a0.lo, a0.hi, a1.lo, a1.hi, a2.lo, a2.hi, a3.lo, a3.hi);
    },
    // Java.invokeStatic(method, args) — picks the best path automatically:
    //   - If a PDB-resolved JavaCalls path is available, use it (works for
    //     both interpreted and JIT-compiled methods, no c2i hassles).
    //     CAVEAT: arg passing not yet wired — only zero-arg static methods
    //     work via this path. Falls back if args are present.
    //   - Otherwise: legacy _invokeStatic which routes through
    //     _from_compiled_entry. Crashes for never-JIT'd methods.
    invokeStatic: function(method, args) {
        // Frida-style magic dispatch: route primitive-arg calls through
        // the JNI surface. Object args are deferred to the JavaCalls
        // path because narrow-oop wrapping inside _invokeJNI's
        // NewLocalRef path doesn't yet handle compressed oops on JDK 17.
        if (method && method.$class && method.$method) {
            var sig = method.$method.sig;
            var p   = Java.parseSig(sig);
            var hasObj = p.args.indexOf('L') >= 0 || p.args.indexOf('[') >= 0
                          || p.ret === 'L' || p.ret === '[';
            if (!hasObj) {
                return Java._unwrap(Marrow._invokeJNI(
                    method.$class, method.$method.name, sig, p.ret, args || []),
                    method.$returnClass || Java._returnClassFromSig(sig));
            }
            // Falls through to JavaCalls path for oop args.
        }
        // Method-handle wrappers expose the address under .address (Frida
        // convention); some older callers may pass .addr directly.
        var addrHex = method.address || method.addr ||
                      (method.$method && method.$method.addr);
        var addr = Java._parseHex(addrHex);
        var argv = Java._coerceArgs(args || []);
        // JavaCalls path: PDB resolved + primitive args only (no oops yet).
        if (Java._jcReady()) {
            var sig = method["$sig"];
            if (typeof sig !== "string") {
                var inner = method["$method"];
                sig = inner ? inner.sig : "()V";
            }
            if (typeof sig !== "string") sig = "()V";
            var rp = sig.indexOf(")");
            // Extract arg-type letters between '(' and ')'. Each L<class>;
            // and array type collapses to a single 'L' for our encoder.
            var argLetters = "";
            for (var i = 1; i < rp; ++i) {
                var c = sig.charAt(i);
                if (c === '[') {
                    while (sig.charAt(i) === '[') ++i;
                    if (sig.charAt(i) === 'L') {
                        while (i < rp && sig.charAt(i) !== ';') ++i;
                    }
                    argLetters += "L";
                } else if (c === 'L') {
                    while (i < rp && sig.charAt(i) !== ';') ++i;
                    argLetters += "L";
                } else {
                    argLetters += c;
                }
            }
            if (argLetters.length === argv.length) {
                var ret = (rp >= 0 && rp + 1 < sig.length)
                          ? sig.charAt(rp + 1) : "V";
                if (ret === "[") ret = "L";
                return Java._unwrap(Marrow._invokeJC(
                    addr.lo, addr.hi, ret, argLetters, argv),
                    method.$returnClass || Java._returnClassFromSig(sig));
            }
            // fall through to legacy thunk if oop args present.
        }
        var a0 = Java._argToLoHi(argv[0]),
            a1 = Java._argToLoHi(argv[1]),
            a2 = Java._argToLoHi(argv[2]),
            a3 = Java._argToLoHi(argv[3]);
        return Marrow._invokeStatic(
            addr.lo, addr.hi,
            a0.lo, a0.hi, a1.lo, a1.hi, a2.lo, a2.hi, a3.lo, a3.hi);
    },

    // Cache: probe PDB once. _javaCallStatus returns a string with ready:1
    // when PDB resolution succeeded for jvm.dll.
    _jcReadyCache: null,
    _jcReady: function() {
        if (Java._jcReadyCache !== null) return Java._jcReadyCache;
        try {
            var s = Marrow._javaCallStatus();
            Java._jcReadyCache = s.indexOf("ready:1") >= 0;
        } catch (e) { Java._jcReadyCache = false; }
        return Java._jcReadyCache;
    },

)JS"
// Split here — MSVC ~16K raw-string limit. Concatenation joins the next
// fragment seamlessly into the same string literal.
R"JS(
    // ---- Thread suspension (foundation for safe ops) --------------
    // Java.safe(closure) suspends all OTHER threads in the process,
    // runs closure, resumes. Use for any op that reads heap state that
    // might race with concurrent JVM mutation (e.g., scanning live CP).
    suspendAll: function() { return Marrow._suspendAll(); },
    resumeAll: function() { return Marrow._resumeAll(); },
    safe: function(closure) {
        Marrow._suspendAll();
        try { return closure(); }
        finally { Marrow._resumeAll(); }
    },

    // ---- Array reading -------------------------------------------
    // Java.readArray(oopHex, type, max) returns JS array of decoded
    // elements. type: I/J/F/D/B/S/C/Z (primitive) or L/[ (oop refs).
    // J/D returned as hex strings (Number can't hold).
    readArray: function(oopHex, type, max) {
        return Marrow._readArray(oopHex, type || 'I', max || 0);
    },

    // ---- String decoding -----------------------------------------
    // Java.toString(oopHex) decodes a java.lang.String oop into UTF-8.
    // Internally suspends all threads briefly to avoid CP-mutation
    // races during the first call's StringReader init.
    toString: function(oopHex) { return Marrow._toString(oopHex); },

    // ---- Mouse polling (Frida has no equivalent — game-modding) --
    _mouseHandlers: {},
    onClick: function(button, fn) {
        if (typeof fn !== "function")
            throw new Error("onClick: fn must be a function");
        Marrow._registerMouse(button);
        Java._mouseHandlers[button] = fn;
    },
    mousePos: function() { return Marrow._mousePos(); },
    drainMouse: function() { return Marrow._drainMouse(); },
    tickMouse: function() {
        var ev = Marrow._drainMouse();
        var fired = 0;
        for (var i = 0; i < ev.length; ++i) {
            var fn = Java._mouseHandlers[ev[i].button];
            if (!fn) continue;
            for (var k = 0; k < ev[i].delta; ++k) {
                try { fn.call(null, ev[i].button); ++fired; }
                catch (e) { Marrow.log("[onClick err btn=" + ev[i].button + "] " + e); }
            }
        }
        return fired;
    },

    // ---- Bytecode dump -------------------------------------------
    // Java.dumpBytecode(method) returns array of byte values (0..255).
    // Returns null for native/abstract methods (codeSize == 0).
    dumpBytecode: function(method) {
        var addr = Java._parseHex(method.addr);
        return Marrow._dumpBytecode(addr.lo, addr.hi);
    },

    // ---- JIT force-compile ---------------------------------------
    // Java.forceCompile(method) bumps the invocation counter past the
    // compile threshold. Next interpreter dispatch will trigger JIT.
    // Returns false if MethodCounters not yet allocated (call the
    // method at least once first to allocate them).
    forceCompile: function(method) {
        var addr = Java._parseHex(method.addr);
        return Marrow._forceCompile(addr.lo, addr.hi);
    },

    // ---- Toast (Windows tray balloon notification) ---------------
    toast: function(title, body) {
        return Marrow.toast(title || "marrow", body || "");
    },

    // ---- Round 5 high-level wrappers ---------------------------------

    // Java.codeCache(maxN) → all JIT'd nmethods reachable from loaded classes
    // Returns [{nmethod, size, method, name}] sorted by size desc.
    codeCache: function(maxN) {
        var arr = Marrow._codeCache(maxN || 256);
        arr.sort(function(a, b){ return b.size - a.size; });
        return arr;
    },

    // Java.fields(className, includeStatic) → all field metadata
    fields: function(className, includeStatic) {
        var cls = Java.use(className);
        return Marrow._klassFields(cls.$klass,
                                      includeStatic === undefined ? true : !!includeStatic);
    },

    // Java.threads() — JS view of all JavaThreads
    threads: function() { return Marrow.threads(); },

    // Java.mhDump(oop) / Java.callsiteTarget(oop) — invoke API helpers
    mhDump: function(oopHex) { return Marrow._mhDump(oopHex); },
    callsiteTarget: function(oopHex) { return Marrow._callsiteTarget(oopHex); },

    // Java.watchAll([{addr, length}, ...]) — watch up to 4 addresses
    watchAll: function(addrs) { return Marrow._watchAll(addrs); },
    unwatchAll: function(cookies) { return Marrow._unwatchAll(cookies); },

    // Java.lockOwner(oop) — who holds the monitor on this object
    lockOwner: function(oopHex) {
        var s = Marrow._monitorState(oopHex);
        if (!s) return null;
        return { state: s.state, owner: s.owner, mark: s.mark };
    },

    // Java.readMem(addr, n) — raw memory read for pointer chasing
    readMem: function(addrHex, n) { return Marrow._readMem(addrHex, n); },
    writeMem: function(addrHex, bytes) { return Marrow._writeMem(addrHex, bytes); },

    // Frida-equivalent symbolicator: methodPtr (hex) → "ClassName.method(sig)".
    methodName: function(methodPtrHex) {
        var info = Marrow._methodName(methodPtrHex);
        if (!info) return null;
        return info.className + '.' + info.name + info.sig;
    },

    // NativePointer wrapper — Frida-equivalent ergonomic API for raw VAs.
    //   var p = Java.ptr('0x12345678');
    //   p.add(8).readU32();
    //   p.readUtf8(64);
    //   p.writeBytes([0x90, 0x90]);
    ptr: function(va) {
        var addrHex;
        if (typeof va === 'number') addrHex = '0x' + va.toString(16);
        else if (typeof va === 'string') addrHex = va.indexOf('0x') === 0 ? va : '0x' + va;
        else if (va && va.$addr) addrHex = va.$addr;       // already a NativePointer
        else throw new Error('Java.ptr: bad address ' + va);

        var addrNum = parseInt(addrHex.slice(2), 16);
        var p = {
            $addr: addrHex,
            toString: function() { return this.$addr; },

            // Arithmetic — produce a new NativePointer.
            add: function(n) { return Java.ptr('0x' + (addrNum + n).toString(16)); },
            sub: function(n) { return Java.ptr('0x' + (addrNum - n).toString(16)); },

            // Reads.
            readU8:  function() { return Marrow._readMem(addrHex, 1)[0]; },
            readU16: function() {
                var b = Marrow._readMem(addrHex, 2); return b[0] | (b[1] << 8);
            },
            readU32: function() {
                var b = Marrow._readMem(addrHex, 4);
                return ((b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24)) >>> 0);
            },
            readU64: function() {
                // returns hex string for full precision
                var b = Marrow._readMem(addrHex, 8);
                var hi = ((b[4] | (b[5]<<8) | (b[6]<<16) | (b[7]<<24)) >>> 0).toString(16);
                var lo = ((b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24)) >>> 0).toString(16);
                while (lo.length < 8) lo = '0' + lo;
                return '0x' + hi + lo;
            },
            readBytes: function(n) { return Marrow._readMem(addrHex, n); },
            readUtf8: function(n) {
                var b = Marrow._readMem(addrHex, n || 256);
                var s = '', i = 0;
                while (i < b.length && b[i] !== 0) { s += String.fromCharCode(b[i] & 0xff); ++i; }
                return s;
            },

            // Writes.
            writeBytes: function(bytes) { return Marrow._writeMem(addrHex, bytes); },
            writeU8:  function(v) { return Marrow._writeMem(addrHex, [v & 0xff]); },
            writeU16: function(v) { return Marrow._writeMem(addrHex, [v & 0xff, (v >> 8) & 0xff]); },
            writeU32: function(v) {
                return Marrow._writeMem(addrHex,
                    [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff]);
            }
        };
        return p;
    },

    // Java.opstack(cookie, n) — N qwords from captured operand stack
    opstack: function(cookie, n) {
        return Marrow._opstackRead(cookie, n || 4);
    },

    // Java.onNative(va_hex, fn) OR Java.onNative(va_hex, {onEnter, onLeave})
    //   - Function form (legacy): fn(rcx, rdx, r8, r9, evt) on every entry.
    //   - Object form (Frida-equivalent): onEnter and/or onLeave handlers.
    //     onEnter(rcx, rdx, r8, r9, evt); onLeave(retVal, evt) where retVal
    //     is the hex string of RAX at function exit.
    // User calls Java.tickNative() periodically to drain both rings.
    _nativeHandlers: {},
    onNative: function(va_hex, fnOrSpec) {
        var spec;
        if (typeof fnOrSpec === "function") {
            spec = { onEnter: fnOrSpec };
        } else if (fnOrSpec && typeof fnOrSpec === "object") {
            spec = fnOrSpec;
        } else {
            throw new Error("onNative: 2nd arg must be a function or {onEnter,onLeave}");
        }
        var hookId = Marrow._inlineHookV2(va_hex);
        if (hookId < 0) return -1;
        Java._nativeHandlers[hookId] = spec;
        return hookId;
    },
    // ---- Round 6 high-level wrappers ---------------------------------

    // Java.explore(oopHex, depth, opts?) — recursive object inspection.
    // The C-side _explore catches per-field read errors via SEH so a
    // moving object during the walk doesn't crash; default path runs
    // without thread suspension. Pass {safe:true} for strict consistency.
    explore: function(oopHex, depth, opts) {
        if (opts && opts.safe) {
            return Java.safe(function() {
                return Marrow._explore(oopHex, depth || 1);
            });
        }
        return Marrow._explore(oopHex, depth || 1);
    },

    // Java.traceAll(classPattern, methodPattern, cookieBase, maxN)
    // Substring-match. Pre-installs counting hooks on every match.
    traceAll: function(classPat, methodPat, cookieBase, maxN) {
        return Marrow._traceMatching(classPat || "", methodPat || "",
                                        cookieBase || 0xD0DE0000, maxN || 256);
    },

    // Java.backtrace(cookie, max) — call stack at last hook fire.
    backtrace: function(cookie, max) {
        return Marrow._backtrace(cookie, max || 16);
    },

    // Java.hooks(min, max) — list installed hook counters.
    hooks: function(min, max) {
        return Marrow._hookCounts(min || 0, max);
    },

    // Java.threadName(threadObjOop) — decode java.lang.Thread.name.
    threadName: function(threadObj) {
        return Marrow._threadName(threadObj);
    },

    // Java.threadsNamed() — combine threads() with threadName resolution.
    threadsNamed: function() {
        var ts = Marrow.threads();
        for (var i = 0; i < ts.length; ++i) {
            try { ts[i].name = Marrow._threadName(ts[i].threadObj); }
            catch (e) { ts[i].name = "?"; }
        }
        return ts;
    },

    // Java.threadsRich({frames, names, symbolicate}) — combine threads,
    // threadName, stackWalk, and methodName into a single call. Frames
    // capped at `frames` (default 8). `names: true` decodes Thread.name
    // (slow on first call due to StringReader init). `symbolicate: true`
    // resolves each frame's methodPtr to "Class.method(sig)".
    threadsRich: function(opts) {
        opts = opts || {};
        var maxFrames    = opts.frames || 8;
        var withNames    = opts.names !== false;
        var withSymbols  = opts.symbolicate !== false;

        var ts = Marrow.threads();
        var out = [];
        for (var i = 0; i < ts.length; ++i) {
            var t = ts[i];
            var entry = {
                addr: t.addr,
                tid: t.tid || t.os_tid,
                state: t.state || t.state_name,
                name: '',
                frames: []
            };
            if (withNames && t.threadObj && t.threadObj !== '0x0') {
                try { entry.name = Marrow._threadName(t.threadObj) || ''; }
                catch (e) {}
            }
            try {
                var raw = Marrow._stackWalk(t.addr, maxFrames);
                for (var k = 0; k < raw.length; ++k) {
                    var f = raw[k];
                    var fr = { methodPtr: f.methodPtr, kind: f.kind, rbp: f.rbp, retPc: f.retPc };
                    if (withSymbols && f.kind === 'interp' && f.methodPtr !== '0x0') {
                        try {
                            var info = Marrow._methodName(f.methodPtr);
                            if (info) fr.symbol = info.className + '.' + info.name + info.sig;
                        } catch (e) {}
                    }
                    entry.frames.push(fr);
                }
            } catch (e) {}
            out.push(entry);
        }
        return out;
    },

    // Java.systemPropsOop() — oop of System.props (java.util.Properties).
    systemPropsOop: function() { return Marrow._systemPropsOop(); },

    // Java.heapRegions(minMB) — major writable memory regions in process.
    heapRegions: function(minMB) {
        return Marrow._heapRegions(minMB || 1);
    },

    // Java.heapScan(nameSubstr, max) — find oops of any class matching name.
    heapScan: function(nameSubstr, max) {
        return Marrow._heapScanByName(nameSubstr || "", max || 100);
    },

)JS"
// Split — MSVC ~16K raw-string limit. Concatenation joins fragments.
R"JS(
    // ---- Round 7 high-level wrappers ---------------------------------

    // Java.memscan(modName, "13 37 ?? ??", limit) — byte-pattern memory scan.
    memscan: function(moduleName, pattern, limit) {
        return Marrow._memscan(moduleName || "", pattern, limit || 32);
    },

    // Java.redefineMethod(method, [bytecode bytes]) — wholesale bytecode swap.
    redefineMethod: function(method, bytecode) {
        var addr = Java._parseHex(method.addr);
        return Marrow._redefineMethod(addr.lo, addr.hi, bytecode);
    },

    // ---- Symbol resolution (PDB-less workflow) -----------------------
    // resolve_symbol() in C tries: PDB → GetProcAddress(jvm.dll,name) →
    // pattern registry. The first two work automatically. The registry
    // is populated by the user via Java.registerSymbolPattern() to enable
    // pattern-based resolution for INTERNAL HotSpot symbols on JREs that
    // ship without debug images.
    //
    // Java.resolveSymbol("JVM_DefineClass") -> hex VA or null
    resolveSymbol: function(name) {
        return Marrow._resolveSymbol(name);
    },
    // Java.registerSymbolPattern("JavaCalls::call", "48 89 5c 24 ?? ...") -> bool
    registerSymbolPattern: function(name, pattern) {
        return Marrow._registerSymbolPattern(name, pattern);
    },
    // Java.extractRawBytes("JVM_DefineClass", 32) -> "48 89 5c 24 08 ..."
    // Reads first N bytes of a resolvable symbol. Useful for capturing a
    // pattern on a debug-image machine (or any machine for exported syms).
    extractRawBytes: function(name, len) {
        return Marrow._extractRawBytes(name, len || 32);
    },
    // Java.symbolPatterns — names currently in the registry.
    symbolPatterns: function() {
        return Marrow._listSymbolPatterns();
    },

    // ---- Trace scenarios: pre-wired hook bundles (Frida-equivalent) -----

    tickNative: function() {
        var fired = 0;
        for (var k in Java._nativeHandlers) {
            var hookId = +k;
            var spec = Java._nativeHandlers[hookId];
            if (spec.onEnter) {
                var ev = Marrow._onNativeDrain(hookId, 32);
                for (var i = 0; i < ev.length; ++i) {
                    try {
                        var e = ev[i];
                        spec.onEnter(e.rcx, e.rdx, e.r8, e.r9, e);
                        ++fired;
                    } catch (err) {
                        Marrow.log("[onNative.enter err id=" + hookId + "] " + err);
                    }
                }
            }
            if (spec.onLeave) {
                var lv = Marrow._onNativeDrainLeave(hookId, 32);
                for (var j = 0; j < lv.length; ++j) {
                    try {
                        var l = lv[j];
                        spec.onLeave(l.rax, l);
                        ++fired;
                    } catch (err) {
                        Marrow.log("[onNative.leave err id=" + hookId + "] " + err);
                    }
                }
            }
        }
        return fired;
    },

    // Java.reload(scriptText?) — wipe all hooks + reset Java.* to defaults
    // by re-evaluating the bootstrap from C. Optionally eval user script after.
    reload: function(scriptText) {
        var ok = Marrow._reloadBootstrap();
        if (typeof ok === 'string') {
            Marrow.log('[reload] bootstrap eval failed: ' + ok);
            return false;
        }
        if (scriptText) {
            try { eval(scriptText); }  // jshint ignore:line
            catch (e) { Marrow.log('[reload] user script err: ' + e); return false; }
        }
        return true;
    },

    // Unhook a method — drops JS handlers + asks C side to restore the
    // original bytecode and method entries (best-effort).
    _unhook: function(handle, addr) {
        if (handle.$cookie != null && Java._impls[handle.$cookie]) {
            delete Java._impls[handle.$cookie];
        }
        handle.$cookie = null;
        try { Marrow._uninstallImpl(addr.lo, addr.hi); } catch (e) {}
    },

    // Shared installer for `implementation =` and `attach()`. Reuses the
    // same cookie when adding to an existing chain so we don't keep
    // installing fresh hooks on the same method.
    // Per-cookie counter of active handler invocations on the current
    // (sync-locked) thread. The wrapper installed in _installOrUpdateImpl
    // bumps this around the user handler call. The proxy `single()` reads
    // it to detect "we're inside our own hook handler" and auto-routes
    // through callOriginal -- giving Frida-style `Cls.method(args)` from
    // inside `.implementation` semantics.
    _activeCookies: {},
    _wrapHandlerFn: function(cookie, fn) {
        return function() {
            Java._activeCookies[cookie] = (Java._activeCookies[cookie] || 0) + 1;
            try { return fn.apply(this, arguments); }
            finally {
                var d = Java._activeCookies[cookie] - 1;
                if (d <= 0) delete Java._activeCookies[cookie];
                else Java._activeCookies[cookie] = d;
            }
        };
    },
    _installOrUpdateImpl: function(handle, cls, name, m, addr, isInstance,
                                    fns, replace, sync) {
        // Wrap each user fn so we can detect active-handler state from
        // proxy `single()` calls (auto-callOriginal for Frida semantics).
        var wrappedFns = fns;  // gets re-wrapped after we know the cookie below
        var existingCookie = handle.$cookie;
        if (existingCookie != null && Java._impls[existingCookie]) {
            var rec = Java._impls[existingCookie];
            var wf = fns.map(function(f){ return Java._wrapHandlerFn(existingCookie, f); });
            if (replace) rec.fns = wf;
            else rec.fns = rec.fns.concat(wf);
            return existingCookie;
        }
        // Use C-side counter so cookies are stable across Java.reload
        // (reload re-evals the bootstrap and resets JS state, but C
        // state — including g_js_impl entries from prior installs —
        // persists; reusing a cookie would collide with stale entries).
        var cookie = Marrow._nextCookie();
        // Pass sig + sync flag so the C side can decode args + populate
        // ctx->replace_rax for sync hooks. `replace` AND `sync` together
        // means full Frida-equivalent .implementation = fn semantics.
        var info = Marrow._installImpl(addr.lo, addr.hi, cookie,
                                          cls.$name + "." + name + m.sig,
                                          m.sig, !!sync,
                                          !!isInstance, cls.$name);
        // No bytecode mutation needed: the trampoline's skip_orig path
        // (sync mode) returns directly to caller without running the
        // method body. Async observers tail-jmp to orig — body runs.
        var wrappedFns0 = fns.map(function(f){
            return Java._wrapHandlerFn(cookie, f);
        });
        Java._impls[cookie] = {
            fns: wrappedFns0,          // ARRAY of wrapped handlers (chain)
            sig: m.sig,
            isInstance: isInstance,
            thisClassName: cls.$name,  // for auto-cast of `this`
            label: cls.$name + "." + name + m.sig,
            jitDetour: (info && typeof info==='object') ? info : null
        };
        handle.$cookie = cookie;
        var jit = (info && info.jitDetourId>=0)
                ? (" jitDetour=" + info.jitDetourVa) : " jit=none";
        Marrow.log("Java.implementation: " + cls.$name + "." + name +
                     m.sig + " hooked (cookie=" + cookie + ", chain=" +
                     fns.length + ", origCode=" + (info?info.origCode:"?") + jit + ")");
        return cookie;
    },

    // Drain accumulated invocations. Per cookie, iterates AT MOST the ring
    // capacity (16 slots) — older fires were overwritten. Without this cap
    // hot-tick targets at MHz rates produced delta values in the millions,
    // each redecoded against the same 16 ring slots — pegging the agent
    // and timing out IPC. Returns the number of events DECODED (not the
    // raw fire count which is in events[i].delta).
    _RING_CAP: 16,
    drain: function() {
        var events = Marrow._drainImplEvents();
        var decoded_total = 0;
        for (var i = 0; i < events.length; ++i) {
            var e = events[i];
            var rec = Java._impls[e.cookie];
            if (!rec || !rec.fns || !rec.fns.length) continue;
            var head = Marrow._ringHead(e.cookie);
            var n = (e.delta > Java._RING_CAP) ? Java._RING_CAP : e.delta;
            var startIdx = head - n;
            for (var k = 0; k < n; ++k) {
                var eventIndex = startIdx + k;
                var decoded = null;
                try {
                    decoded = Java.decodeArgsAt(e.cookie, rec.sig, rec.isInstance,
                                                 eventIndex, rec.thisClassName);
                } catch (err) {
                    Marrow.log("[js] decode failed: " + err);
                }
                var thisArg = null, posArgs = [];
                if (decoded && decoded.length) {
                    var start = 0;
                    if (rec.isInstance && decoded[0].note === 'this') {
                        thisArg = decoded[0].value;
                        start = 1;
                    }
                    for (var j = start; j < decoded.length; ++j) {
                        posArgs.push(decoded[j].value);
                    }
                }
                for (var h = 0; h < rec.fns.length; ++h) {
                    try { rec.fns[h].apply(thisArg, posArgs); }
                    catch (err) {
                        Marrow.log("[js] impl[" + h + "] " + rec.label +
                                     " threw: " + err);
                    }
                }
                decoded_total++;
            }
        }
        return decoded_total;
    }
};

// Auto-bootstrap _invokeJC: on first call (per agent load), trigger the
// PDB-less JC::call resolver if the existing g_sym.javacalls_call (likely
// set by the static xref heuristic to a wrong VA on JRE without PDB)
// hasn't been verified.
//
// Re-entry note: Java.resolveJavaCallsCall internally calls _invokeJC for
// verification. The Java._jcResolverActive flag (set inside the resolver)
// short-circuits this wrapper so the resolver's own calls bypass the
// auto-bootstrap and reach the raw _invokeJC directly.
(function () {
    if (typeof Marrow === "undefined" || !Marrow._invokeJC) return;
    if (Marrow._invokeJCRaw) return;       // already wrapped
    Marrow._invokeJCRaw = Marrow._invokeJC;
    Marrow._invokeJC = function () {
        if (!Java._jcCallCache && !Java._jcResolverActive &&
            !Java._jcResolveTried) {
            Java._jcResolveTried = true;     // one-shot -- don't retry on failure
            try { Java.resolveJavaCallsCall(); } catch (e) { /* ignored */ }
        }
        var args = Array.prototype.slice.call(arguments);
        // call_stub fallback path (typically JDK 8): cache contains
        // "stub:0x...". Dispatch via _invokeViaCallStub which accepts raw
        // oops (no make_local, no JNI surface). Args layout:
        //   (lo, hi, ret, argTypes, argv, recv).
        if (Java._callStubCache) {
            var lo = args[0], hi = args[1];
            var ret = args[2] || "V";
            var argTypes = args[3] || "";
            var argv = args[4] || [];
            var recv = args[5] || "";
            return Marrow._invokeViaCallStub(Java._callStubCache, lo, hi,
                                                ret, argTypes, argv, recv);
        }
        // Inject the ABI flag (7th positional arg) when callers haven't
        // supplied it. The resolver caches Java._jcByVal at verification.
        if (args.length < 7 && Java._jcByVal) {
            while (args.length < 7) args.push(args.length === 5 ? "" : false);
            args[6] = !!Java._jcByVal;
        }
        return Marrow._invokeJCRaw.apply(this, args);
    };
    // call_stub-based invocation on JDK 8 / older: opt-in via direct API
    // Marrow._invokeViaCallStub(stubVa, methodLo, methodHi, ret,
    //                              argTypes, argv, recv).
    // The resolver caches the stub entry in Java._callStubCache when JC::call
    // can't be found. _invokeJC remains JNI-routed via Java.invoke fallback.
})();
)JS";

} // namespace marrow
