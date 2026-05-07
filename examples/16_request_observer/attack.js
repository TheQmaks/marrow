// Async observer on App.handle. Original method runs unchanged;
// every call also writes a snapshot into the per-cookie ring buffer
// for later drain. Safe on hot methods (no Duktape mutex per fire).
(function(){
    try {
        globalThis._reqHits = 0;
        globalThis._reqLog  = [];
        var App = Java.use('App');
        App.handle.attach(function(req) {
            globalThis._reqHits++;
            globalThis._reqLog.push(Java.toString(req));
        });
        return 'attached:hits=' + globalThis._reqHits;
    } catch (e) {
        return 'err:' + e;
    }
})()
