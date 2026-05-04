// F1 toggles godmode, F2 heals to 100. Pure marrow — no JNI/keyboard plugin.
var App = Java.use('App');

Java.onKey(0x70 /*F1*/, function() {
    var cur = Java.readField(App.$klass, 'App', 'godmode');  // static
    // Static reads from class mirror — Java._fieldSlotAddr handles it.
    // For boolean static fields we use writeStaticRef pattern.
    // Actually simpler: just keep toggling state in JS + write each tick.
    Java.writeField(App.$klass, 'App', 'godmode', cur ? 0 : 1);
    Marrow.toast('cheat', cur ? 'godmode OFF' : 'godmode ON');
});

Java.onKey(0x71 /*F2*/, function() {
    Java.writeField(App.$klass, 'App', 'health', 100);
    Marrow.toast('cheat', 'healed to 100');
});

Marrow.log('F1=godmode toggle, F2=heal');

// User presses F1 anywhere on the desktop → app's godmode flips.
// Periodically: Java.tickKeys(); to drain handlers.
