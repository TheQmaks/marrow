// Direct hooks — no trace helper. User picks классы и методы сам.
var URL = Java.use('java/net/URL');
var Conn = Java.use('java/net/HttpURLConnection');

URL.openConnection.implementation = function() {
    Marrow.log('URL.openConnection on ' + Java.toString(this.toString()));
};

Conn.setRequestMethod.implementation = function(method) {
    Marrow.log('  method=' + Java.toString(method));
};

Conn.setRequestProperty.implementation = function(key, value) {
    Marrow.log('  header ' + Java.toString(key) + '=' + Java.toString(value));
};
