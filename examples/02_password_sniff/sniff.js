// Hook checkPassword and log every attempt.
// User types passwords interactively; we see them in the agent log.
var App = Java.use('App');
attempts = [];
App.checkPassword.implementation = function(input) {
    // 'input' here is decoded String oop hex; convert via _toString.
    var plain = Marrow._toString(input);
    attempts.push(plain);
    Marrow.log('[passwd] attempt: "' + plain + '"');
};

// drain periodically: Java.drain();
// attempts array accumulates every password user typed.
