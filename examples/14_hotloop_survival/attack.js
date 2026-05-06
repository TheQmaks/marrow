// Hook App.score with a callOriginal-based handler that runs INSIDE
// the JVM's hot loop. The handler is invoked on every call,
// recursively dispatches the original via callOriginal, and adds
// salt to the return value.
//
// Pre-v0.4 toolkits would observe this falling off a cliff after
// HotSpot tier-up's the method (around iter 200-2000). v0.5 stays
// 100% across the full 50,000-iter loop.

var App = Java.use('App');

var hits     = 0;
var misses   = 0;     // outer calls where handler didn't fire
var lastSeen = -1;

App.score.implementation = function(a, b) {
    hits++;
    if (a !== lastSeen + 1) misses += (a - lastSeen - 1);
    lastSeen = a;
    // callOriginal recursively invokes the real method body without
    // re-entering this handler (per-thread reentry guard handles the
    // skip-cb side of dispatch).
    return App.score.callOriginal(a, b) + 7;
};

// Run a probe pass to see the hook is firing before HotSpot warms up.
Marrow.log('hotloop_survival: hook installed, App.score now adds +7');

// Drain after the loop completes (App.main does Thread.sleep(2s) at the
// end). User runs `marrow agent <pid> eval` again with this snippet:
//
//   (function(){
//     return JSON.stringify({hits: hits, misses: misses, lastSeen: lastSeen});
//   })()
//
// Expected on v0.5: hits=50000, misses=0, lastSeen=49999.
// Pre-v0.4 baseline: hits ~3000-5000, misses=45000+.
