// Frida-style instrumentation script for the running Target process.
//
// Drop this into the agent's eval pipeline; the running Target loops
// `t.tick(counter)` every 500 ms in the background, and these hooks
// react to that traffic in real time.
//
// API style mirrors Frida-Java; project-specific extensions live under
// Marrow.* (heap reads, field accessors, raw _invokeJNI, etc.)

Java.perform(function () {
    console.log("[script] booting hooks");

    var Target   = Java.use("Target");
    var Callable = Java.use("Callable");

    // 1) Observe Target.tick(int) -- async observer; original always runs.
    //    .attach() handlers fire from a lock-free ring; pump with Java.drain().
    Java._tickCount = 0;
    Target.tick.attach(function (n) {
        Java._tickCount++;
        if (Java._tickCount <= 3 || Java._tickCount % 5 === 0) {
            console.log("[obs] tick(" + n + ")  total observed = " + Java._tickCount);
        }
    });

    // 2) Sync replacer: Callable.addInts now returns a+b+1000.
    Callable.addInts.implementation = function (a, b) {
        var orig = Callable.addInts.callOriginal(a, b);
        console.log("[hijack] addInts(" + a + "," + b + ") orig=" + orig + " -> " + (orig + 1000));
        return orig + 1000;
    };

    // 3) Constant replacer: Callable.alsoNever() returns 42L instead of
    //    its baked-in 0xDEADBEEFCAFEBABE. Verify with _invokeJNI below.
    Callable.alsoNever.implementation = function () { return 42; };

    // 4) Sanity-fire each hook once via _invokeJNI and capture results.
    Java._results = {};
    Java._results.addInts_3_4 = Marrow._invokeJNI(
        "Callable", "addInts", "(II)I", "I", [3, 4]);   // expects 1007
    Java._results.alsoNever   = Marrow._invokeJNI(
        "Callable", "alsoNever", "()J", "J", []);       // expects 42
    Java._results.neverCalled = Marrow._invokeJNI(
        "Callable", "neverCalled", "()I", "I", []);     // unhooked -> CAFEBABE

    console.log("[script] ready, hooks active on Target.tick / Callable.addInts / Callable.alsoNever");
});

// Drain the .attach observer ring -- Python driver calls this after a
// short sleep so the running Target.tick() observations get flushed.
function pollDrain() {
    Java.drain();
    return JSON.stringify({
        tickCount:  Java._tickCount,
        addInts_3_4: String(Java._results.addInts_3_4),
        alsoNever:  String(Java._results.alsoNever),
        neverCalled: String(Java._results.neverCalled)
    });
}
