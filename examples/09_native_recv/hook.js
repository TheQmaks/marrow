// Inline hook on ws2_32!recv. Shows args every recv call:
// rcx=socket, rdx=buf, r8=len, r9=flags
var recvAddr = Marrow.symbolAt('ws2_32.dll', 'recv');
Marrow.log('ws2_32!recv @ ' + recvAddr);

var hookId = Java.onNative(recvAddr, function(rcx, rdx, r8, r9) {
    Marrow.log('[recv] socket=' + rcx + ' buf=' + rdx + ' len=' + r8);
    // Optionally read first 32 bytes after recv returns:
    // (need post-call hook for that; we have pre-call only via V2 shim)
});
Marrow.log('hooked recv, hookId=' + hookId);

// Periodically:
Java.tickNative();   // fires registered handlers per buffered event
// → see every TCP read from JVM side, including SSL-wrapped ones via libssl
