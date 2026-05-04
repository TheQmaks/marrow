// Trace EVERY method in App and rank by invocation count.
var trace = Java.traceClass('App', 0xC0DE0000);
Marrow.log('installed ' + trace.installed + ' counters');

// Wait a bit (in real flow: Thread.sleep then call again from CLI):
// after 5 seconds:
var stats = Java.readTraces(trace);
Marrow.log('hot methods:');
for (var i = 0; i < stats.length; ++i) {
    Marrow.log('  ' + stats[i].name + stats[i].sig + ' = ' + stats[i].count);
}
// Expected output:
//   hot()V    = ~50000
//   warm()V   = ~1000
//   cold()V   = ~1000
//   unused()V = 0   (never called)
// → instantly identifies the hot path without source / debugger.
