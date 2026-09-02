/*
 * maps-spoof.js — hilangkan jejak emulator di /proc/self/maps.
 * Authorized engagement use only.
 *
 * Sumber deteksi terakhir yang tersisa: RASP membaca /proc/self/maps, dan di
 * sana ada 22 baris yang menyebut emulator secara eksplisit —
 *
 *   /vendor/lib64/egl/libEGL_emulation.so, libGLESv1_CM_emulation.so,
 *   libGLESv2_emulation.so, /vendor/lib64/hw/mapper.ranchu.so,
 *   /dev/goldfish_address_space, /product/overlay/RanchuCommonOverlay.apk
 *
 * Ini tidak bisa ditutup lewat spoof properti atau device node, karena berasal
 * dari pustaka yang memang ter-mmap oleh stack grafis nyata.
 *
 * Pendekatan: RENAME, bukan hapus. Menghapus baris meninggalkan lompatan
 * alamat yang justru mencurigakan dan bisa merusak logika parsing RASP; kita
 * hanya mengganti nama path menjadi padanan Mali/Exynos yang wajar, lalu
 * mengarahkan RASP ke salinan itu. Snapshot dibuat ulang setiap kali dibuka,
 * jadi isinya tetap mengikuti keadaan proses saat itu.
 *
 * Harus di-concat SETELAH emu-bypass.js (memakai `fromRasp`).
 */

(function () {

const CACHE = '/data/data/com.example.targetapp/cache/.mp';
const FAKE = Memory.allocUtf8String(CACHE);
const keep = [FAKE];

const RENAME = [
    [/libEGL_emulation\.so/g,        'libEGL_mali.so'],
    [/libGLESv1_CM_emulation\.so/g,  'libGLESv1_CM_mali.so'],
    [/libGLESv2_emulation\.so/g,     'libGLESv2_mali.so'],
    [/libGLES_emulation\.so/g,       'libGLES_mali.so'],
    [/mapper\.ranchu\.so/g,          'mapper.exynos5.so'],
    [/gralloc\.ranchu\.so/g,         'gralloc.exynos5.so'],
    [/goldfish_address_space/g,      'mali_address_space'],
    [/goldfish_pipe[a-z_]*/g,        'mali_pipe'],
    [/goldfish_sync/g,               'mali_sync'],
    [/RanchuCommonOverlay/g,         'SamsungCommonOverlay'],
    [/ranchu/g,                      'exynos5'],
    [/goldfish/g,                    'mali'],
    [/qemu_pipe/g,                   'mali_pipe']
];

function sanitise(text) {
    let out = text;
    RENAME.forEach(function (r) { out = out.replace(r[0], r[1]); });
    return out;
}

function snapshot() {
    try {
        const real = File.readAllText('/proc/self/maps');
        File.writeAllText(CACHE, sanitise(real));
        return true;
    } catch (e) {
        send('maps snapshot failed: ' + e);
        return false;
    }
}

const MAPS_RE = /^\/proc\/(self|\d+)\/maps$/;
const seen = Object.create(null);

[['fopen', 0], ['fopen64', 0], ['open', 0], ['open64', 0], ['__open_2', 0],
 ['openat', 1], ['__openat_2', 1]].forEach(function (spec) {
    let p;
    try { p = Module.findGlobalExportByName(spec[0]); } catch (e) { return; }
    if (!p) return;
    const idx = spec[1];
    try {
        Interceptor.attach(p, {
            onEnter(a) {
                if (!fromRasp(this.returnAddress)) return;
                let s = null;
                try { s = a[idx].readCString(); } catch (e) { return; }
                if (!s || !MAPS_RE.test(s)) return;
                if (!snapshot()) return;
                a[idx] = FAKE;
                if (!seen[s]) { seen[s] = 1; send('MAPS-SWAP ' + spec[0] + '("' + s + '") -> ' + CACHE); }
            }
        });
    } catch (e) {}
});

send('maps-spoof ready');

})();
