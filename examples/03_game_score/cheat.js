// Find live Game instance, max stats. Direct field access — no .value boilerplate.
Java.choose('Game', {
    onMatch: function(g) {
        Marrow.log('found Game @ ' + g.$oop +
                     ': score=' + g.score + ' health=' + g.health);
        g.score = 99999;
        g.health = 9999;
        Marrow.log('after: score=' + g.score + ' health=' + g.health);
    }
});
