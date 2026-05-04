// cheat.js — showcase of the post-Frida-refactor agent API.
// Run against the existing target/Target.java.
//
// Demonstrates:
//   1. `Java.choose` delivers cast'd instance proxies directly.
//   2. Field reads return native JS values
//      (int → JS number, String → JS string auto-decoded).
//   3. Field writes accept JS values directly
//      (int literal, JS string — the latter allocates a Java String
//      via TLAB char[] + String.valueOf using JavaCalls + PDB).
//   4. Hooks (commented below) bind `this` automatically.
//
// We mutate every Target match because Java.choose may surface multiple
// oops with the matching narrow_klass (live instance + a stray header
// pattern in some auxiliary region). Mutating all of them guarantees the
// live one gets the change.

var T = Java.use('Target');
var hits = 0;

Java.choose('Target', { onMatch: function(t) {
    try {
        t.tag      = 0xCAFEBABE;            // direct int — encoding handled
        t.greeting = 'OWNED by marrow';   // JS string → Java String
        hits++;
    } catch (e) {
        Marrow.log('skip ' + t.$oop + ': ' + e);
    }
}});

Marrow.log('mutated ' + hits + ' Target instance(s)');

// Hook tick(int n) — `this` is the receiver proxy. Read/mutate fields
// directly, no manual cast. Uncomment to engage:
//
// T.tick.implementation = function(n) {
//     Marrow.log('tick #' + n + ' tag=0x' + (this.tag >>> 0).toString(16));
//     if (n > 50) this.greeting = 'pwn at ' + n;
// };
