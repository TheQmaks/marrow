// Hook Cipher.doFinal directly — no pre-baked trace helper, just the primitive.
// args[0] is the plaintext byte[] arg before encryption.
var Cipher = Java.use('javax/crypto/Cipher');

Cipher.doFinal.implementation = function(input) {
    // input is the byte[] oop hex. Decode to ASCII (Latin1 for demo).
    var bytes = Java.readArray(input, 'B', 256);
    var s = '';
    for (var i = 0; i < bytes.length; ++i) s += String.fromCharCode(bytes[i] & 0xff);
    Marrow.log('PLAINTEXT: ' + s);
};
