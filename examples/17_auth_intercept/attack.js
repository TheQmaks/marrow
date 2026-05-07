// Hook login() to log creds AND force a true return regardless of
// what was passed in. Sync .implementation runs from the calling
// thread under Duktape mutex; the boolean return value flows back
// through the trampoline's replace_rax path.
//
// This script demonstrates two things at once:
//   - Argument inspection (decode user/pass strings).
//   - Return-value replacement (always allow).
var App = Java.use('App');

App.login.implementation = function(user, pass) {
    var u = Java.toString(user);
    var p = Java.toString(pass);
    Marrow.log('login attempt: user=' + u + ' pass=' + p + ' -> FORCED true');
    return true;
};

Marrow.log('hook installed: App.login -> always true + log creds');
