// Hook the pinned TrustManager's checkServerTrusted to a no-op.
// Once the .implementation is set the next call returns cleanly
// instead of throwing SecurityException, and the app prints
// "BYPASSED" instead of "PINNED: CERT_PINNED".
//
// Inner class names: javac emits App$PinnedTrustManager for the
// inner static class. Marrow's Java.use accepts both dot and
// slash notation; '$' is preserved verbatim.
var App = Java.use('App');
App.checkServerTrusted.implementation = function(chain, authType) {
    Marrow.log('TLS pinning bypassed');
    // void return: trampoline skip_orig RETs without running orig.
};
Marrow.log('hook installed: App.checkServerTrusted -> noop');
