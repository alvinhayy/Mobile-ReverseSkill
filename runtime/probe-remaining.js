/*
 * probe-remaining.js — cari sinyal emulator yang MASIH lolos.
 * emu-bypass.js sudah menutup properti, device node, artefak file, dan Build.*,
 * tapi IronSky tetap mengirim `event_emulator_android` (risk MM100004).
 *
 * Di sini: log SEMUA akses file & properti yang berasal dari modul proteksi
 * (tanpa filter kata kunci), plus jalur Java yang lazim dipakai untuk
 * fingerprint emulator (sensor, telephony, CPU, GL renderer).
 *
 * Authorized engagement use only. Jalankan via runtime/drive.py.
 */

const RASP_RE = /libAppGuard\.so|libRiskStub\.so|libappsec\.so/i;
const raspCache = Object.create(null);
const seen = Object.create(null);

function fromRasp(a) {
    if (!a) return false;
    try {
        const m = Process.findModuleByAddress(a);
        if (!m) return false;
        if (!(m.name in raspCache)) raspCache[m.name] = RASP_RE.test(m.name);
        return raspCache[m.name];
    } catch (e) { return false; }
}
function once(k, m) { if (!seen[k]) { seen[k] = 1; send(m); } }
function gx(n) { try { return Module.findGlobalExportByName(n); } catch (e) { return null; } }

// --- semua properti yang dibaca RASP (tanpa filter) --------------------------
const spg = gx('__system_property_get');
if (spg) Interceptor.attach(spg, {
    onEnter(a) { this.r = fromRasp(this.returnAddress); this.n = a[0].readCString(); this.b = a[1]; },
    onLeave() {
        if (!this.r || !this.n) return;
        let v = ''; try { v = this.b.readCString() || ''; } catch (e) {}
        once('p' + this.n, 'PROP ' + this.n + ' = "' + v + '"');
    }
});

// --- semua file yang dibuka/diperiksa RASP (tanpa filter) --------------------
[['open', 0], ['open64', 0], ['__open_2', 0], ['openat', 1], ['__openat_2', 1],
 ['access', 0], ['faccessat', 1], ['stat', 0], ['lstat', 0], ['fopen', 0],
 ['readlink', 0], ['opendir', 0]].forEach(function (x) {
    const p = gx(x[0]); if (!p) return;
    try {
        Interceptor.attach(p, {
            onEnter(a) {
                if (!fromRasp(this.returnAddress)) return;
                let s = null; try { s = a[x[1]].readCString(); } catch (e) {}
                if (s) once('f' + s, 'FILE ' + x[0] + '("' + s + '")');
            }
        });
    } catch (e) {}
});

// --- uname / sysinfo --------------------------------------------------------
const un = gx('uname');
if (un) Interceptor.attach(un, {
    onEnter(a) { this.r = fromRasp(this.returnAddress); this.b = a[0]; },
    onLeave() {
        if (!this.r) return;
        try {
            const f = [];
            for (let i = 0; i < 5; i++) f.push(this.b.add(i * 65).readCString());
            once('uname', 'UNAME ' + JSON.stringify(f));
        } catch (e) {}
    }
});

// --- Java: sensor / telephony / GL ------------------------------------------
function armJava() {
    Java.perform(function () {
        try {
            const SM = Java.use('android.hardware.SensorManager');
            SM.getSensorList.implementation = function (t) {
                const r = this.getSensorList(t);
                once('sensors', 'SENSORS getSensorList(' + t + ') -> size=' + r.size());
                return r;
            };
            send('armed SensorManager');
        } catch (e) {}

        try {
            const TM = Java.use('android.telephony.TelephonyManager');
            ['getNetworkOperatorName', 'getSimOperatorName', 'getDeviceId',
             'getSubscriberId', 'getLine1Number', 'getSimSerialNumber'].forEach(function (mn) {
                try {
                    TM[mn].overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            const r = ov.apply(this, arguments);
                            once('tm' + mn, 'TELEPHONY ' + mn + '() -> ' + r);
                            return r;
                        };
                    });
                } catch (e) {}
            });
            send('armed TelephonyManager');
        } catch (e) {}

        try {
            const GLES = Java.use('android.opengl.GLES20');
            GLES.glGetString.implementation = function (n) {
                const r = this.glGetString(n);
                once('gl' + n, 'GL glGetString(0x' + n.toString(16) + ') -> ' + r);
                return r;
            };
            send('armed GLES20.glGetString');
        } catch (e) {}

        send('java probes ready');
    });
}
let jd = false;
const jp = setInterval(function () {
    if (jd) { clearInterval(jp); return; }
    try { if (typeof Java === 'undefined' || !Java.available) return; jd = true; clearInterval(jp); armJava(); }
    catch (e) {}
}, 25);

send('probe-remaining ready');
