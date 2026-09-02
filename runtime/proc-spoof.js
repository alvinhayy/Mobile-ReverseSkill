/*
 * proc-spoof.js — tutup kebocoran emulator lewat /proc yang masih tersisa.
 * Authorized engagement use only.
 *
 * Teridentifikasi dari probe-remaining.js (file yang dibaca RASP tanpa filter):
 *
 *   /proc/self/mounts -> /dev/block/vdd1   (perangkat blok virtio, tidak ada di HP fisik)
 *   /proc/version     -> kleaf@build-host, kernel "-android15-8-4k-Wild"
 *
 * Pendekatan: tukar POINTER PATH-nya, bukan isi file. Jauh lebih sederhana dan
 * aman daripada memalsukan fd/hasil read(): kita arahkan RASP ke salinan bersih
 * yang sudah disiapkan di cache app (dimiliki uid app, jadi bisa dibaca).
 *
 * Hanya berlaku untuk pemanggil di dalam modul proteksi — proses lain (dan app
 * itu sendiri) tetap melihat /proc yang asli, jadi tidak ada efek samping.
 */

(function () {

const PS_RASP = /libAppGuard\.so|libRiskStub\.so|libappsec\.so/i;
const psCache = Object.create(null);
const psKeep = [];

function psFromRasp(a) {
    if (!a) return false;
    try {
        const m = Process.findModuleByAddress(a);
        if (!m) return false;
        if (!(m.name in psCache)) psCache[m.name] = PS_RASP.test(m.name);
        return psCache[m.name];
    } catch (e) { return false; }
}
function psGx(n) { try { return Module.findGlobalExportByName(n); } catch (e) { return null; } }

const CACHE = '/data/data/com.example.targetapp/cache';
const FAKE_MOUNTS = Memory.allocUtf8String(CACHE + '/.m');
const FAKE_VERSION = Memory.allocUtf8String(CACHE + '/.v');
psKeep.push(FAKE_MOUNTS, FAKE_VERSION);

// /proc/self/mounts, /proc/mounts, /proc/<pid>/mounts, /etc/mtab
const MOUNTS_RE = /^\/proc\/(self|\d+)\/mounts$|^\/proc\/mounts$|^\/etc\/mtab$/;
const VERSION_RE = /^\/proc\/version$/;

function swap(path) {
    if (MOUNTS_RE.test(path)) return FAKE_MOUNTS;
    if (VERSION_RE.test(path)) return FAKE_VERSION;
    return null;
}

const seenSwap = Object.create(null);

[['fopen', 0], ['fopen64', 0], ['open', 0], ['open64', 0], ['__open_2', 0],
 ['openat', 1], ['__openat_2', 1]].forEach(function (spec) {
    const p = psGx(spec[0]);
    if (!p) return;
    const idx = spec[1];
    try {
        Interceptor.attach(p, {
            onEnter(a) {
                if (!psFromRasp(this.returnAddress)) return;
                let s = null;
                try { s = a[idx].readCString(); } catch (e) { return; }
                if (!s) return;
                const rep = swap(s);
                if (!rep) return;
                a[idx] = rep;
                const k = spec[0] + s;
                if (!seenSwap[k]) {
                    seenSwap[k] = 1;
                    send('PROC-SWAP ' + spec[0] + '("' + s + '") -> ' + rep.readCString());
                }
            }
        });
    } catch (e) {}
});

send('proc-spoof ready (mounts + version)');

})();
