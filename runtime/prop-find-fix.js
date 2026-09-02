/*
 * prop-find-fix.js — tutup jalur baca properti yang lolos dari emu-bypass.js.
 * Authorized engagement use only. Harus di-concat SETELAH emu-bypass.js
 * (memakai `spoofValue` dan `fromRasp` dari sana).
 *
 * MASALAH
 * -------
 * bionic modern membaca properti dengan dua langkah:
 *
 *     const prop_info* pi = __system_property_find("ro.boot.qemu");
 *     __system_property_read_callback(pi, cb, cookie);
 *
 * emu-bypass.js menyaring `__system_property_read_callback` berdasarkan
 * returnAddress. Tapi callback itu sering dipanggil dari DALAM libc, sehingga
 * returnAddress-nya libc — bukan modul RASP. Akibatnya filter tidak pernah
 * cocok dan nilai asli (`ro.boot.qemu=1`, `ro.hardware.gralloc=ranchu`,
 * `ro.hardware.egl=emulation`) lolos apa adanya. Itu terlihat di probe-emu.js
 * sebagai baris `PROPCB` tanpa `SPOOF propcb` yang menyertainya.
 *
 * SOLUSI
 * ------
 * Ikat identitas berdasarkan `prop_info*`, bukan berdasarkan siapa pemanggil
 * callback-nya: catat pointer yang dikembalikan `__system_property_find` ketika
 * DIPANGGIL DARI RASP, lalu palsukan nilainya saat pointer itu dibaca. Dengan
 * begitu pembacaan oleh stack grafis (yang tidak lewat RASP) tetap jujur.
 */

(function () {

const piName = {};          // prop_info*  ->  nama properti (hanya milik RASP)
const pffKeep = [];

const findFn = (function () {
    try { return Module.findGlobalExportByName('__system_property_find'); }
    catch (e) { return null; }
})();

if (findFn) {
    Interceptor.attach(findFn, {
        onEnter(a) {
            this.rasp = fromRasp(this.returnAddress);
            try { this.n = a[0].readCString(); } catch (e) { this.n = null; }
        },
        onLeave(rv) {
            if (!this.rasp || !this.n || rv.isNull()) return;
            piName[rv.toString()] = this.n;
        }
    });
    send('armed __system_property_find (pi tracking)');
}

const cbFn = (function () {
    try { return Module.findGlobalExportByName('__system_property_read_callback'); }
    catch (e) { return null; }
})();

if (cbFn) {
    const T = ['pointer', 'pointer', 'pointer', 'uint32'];
    const reported = {};
    Interceptor.attach(cbFn, {
        onEnter(a) {
            const key = a[0].toString();
            const name = piName[key];
            if (!name) return;                     // bukan pembacaan milik RASP

            const orig = a[1];
            const origFn = new NativeFunction(orig, 'void', T);
            const wrapper = new NativeCallback(function (cookie, np, vp, serial) {
                let v = '';
                try { v = vp.readCString() || ''; } catch (e) {}
                const nv = spoofValue(name, v);
                if (nv !== null && nv !== v) {
                    const s = Memory.allocUtf8String(nv);
                    pffKeep.push(s);
                    if (!reported[name]) {
                        reported[name] = 1;
                        send('SPOOF pi-cb ' + name + ': "' + v + '" -> "' + nv + '"');
                    }
                    return origFn(cookie, np, s, serial);
                }
                return origFn(cookie, np, vp, serial);
            }, 'void', T);
            pffKeep.push(wrapper);
            a[1] = wrapper;
        }
    });
    send('armed __system_property_read_callback (pi-bound)');
}

})();
