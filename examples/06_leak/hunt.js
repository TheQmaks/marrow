// Take a snapshot of heap class histogram, wait 10 sec, diff.
// Shows which classes are GROWING fastest — instant leak fingerprint.
var diff = Java.snapshotForDiff();
Marrow.log('snapshot taken: ' + diff.takenAt);

// User waits ~10 seconds, then:
Marrow.log('=== leak diff (top 5 growth) ===');
var changes = diff.diff();
for (var i = 0; i < Math.min(5, changes.length); ++i) {
    var c = changes[i];
    Marrow.log('  ' + c.name + ': ' + c.before + ' → ' + c.after +
                 ' (Δ' + (c.delta > 0 ? '+' : '') + c.delta + ')');
}
// Expected:
//   java/lang/String:        50000 → 60000 (Δ+10000)
//   [B (byte[]):             50000 → 60000 (Δ+10000)
//   java/util/HashMap$Node:    100 →   100 (Δ0)
// → instantly: "Strings + byte[] are leaking; check String allocation paths"
