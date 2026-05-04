// hook authorize(User, Permission). Decode оба object args, мутируем оба.
var App = Java.use('App');

App.authorize.implementation = function(userOop, permOop) {
    var u = Java.cast(userOop, 'User');
    var p = Java.cast(permOop, 'Permission');

    Marrow.log('authorize: user=' + Java.toString(u.name) + '/' + u.age +
                 '/' + Java.toString(u.email) +
                 ' perm=' + Java.toString(p.resource) + ' write=' + p.canWrite);

    if (u.age < 18) { u.age = 99; }
    p.canWrite = 1;
};
