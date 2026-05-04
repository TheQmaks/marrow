// Watch the counter field via DR0 (CPU debug register, byte-level write detect).
// Every write triggers an event with the faulting RIP — that RIP is in the
// JIT-compiled / interpreted code of WHICHEVER method wrote to it.
var cookie = Java.watchField('App', 'counter', 4);
Marrow.log('watching App.counter (cookie=' + cookie + ')');

// Periodically:
var events = Java.drainWatches();
for (var i = 0; i < events.length; ++i) {
    var e = events[i];
    var mod = Marrow.moduleAt(e.faultRip);
    Marrow.log('write @ rip=' + e.faultRip +
                 (mod ? ' module=' + mod.name + '+' + mod.offset : ''));
}
// Output: every write to counter shows the RIP and module.
// → instantly localizes ALL writers without instrumenting each method.
// HW-level — no overhead while not writing, no false positives.
