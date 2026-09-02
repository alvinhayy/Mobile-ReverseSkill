/*
 * ironsky-log.js — tangkap semua header Ironsky-* yang dikirim SDK SecIron.
 * Menjawab: nilai `Ironsky-Events` apa saja yang muncul selama runtime.
 * Authorized engagement use only.
 */
(function () {
    const hits = Object.create(null);

    function armIronsky() {
        Java.perform(function () {
            try {
                const URLC = Java.use('java.net.URLConnection');
                ['setRequestProperty', 'addRequestProperty'].forEach(function (mn) {
                    URLC[mn].implementation = function (k, v) {
                        try {
                            if (k && /^ironsky/i.test(k)) {
                                const key = k + '=' + v;
                                if (!hits[key]) { hits[key] = 1; send('IRONSKY-HDR ' + k + ': ' + v); }
                            }
                        } catch (e) {}
                        return this[mn](k, v);
                    };
                });
                send('armed Ironsky header capture (URLConnection)');
            } catch (e) { send('URLConnection hook failed: ' + e); }
        });
    }
    let d = false;
    const t = setInterval(function () {
        if (d) { clearInterval(t); return; }
        try { if (typeof Java === 'undefined' || !Java.available) return; d = true; clearInterval(t); armIronsky(); }
        catch (e) {}
    }, 25);
})();
