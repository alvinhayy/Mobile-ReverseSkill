/*
 * emu-bypass.js — neutralise SecIron IronSky's emulator detection.
 * Authorized engagement use only. Run via runtime/drive.py.
 *
 * Strategy: the RASP reaches its "Run on Emulator" verdict from three signal
 * families, all observed live with runtime/probe-emu.js:
 *
 *   1. properties   ro.boot.qemu=1, ro.kernel.qemu=1, ro.hardware*=ranchu,
 *                   ro.hardware.egl=emulation, ro.product.model=sdk_gphone64_arm64
 *   2. device nodes /dev/qemu_pipe, /dev/socket/qemud, /dev/goldfish_*
 *   3. EGL libs     /vendor/lib64/egl/lib*_emulation.so
 *
 * We lie about all three, but ONLY when the caller's return address lies inside
 * a protection module. That keeps the real graphics stack and the Flutter
 * engine seeing the truth, so rendering still works.
 */
'use strict';

const VERBOSE = true;

// ---------------------------------------------------------------------------
// Protection-module address ranges — the filter that keeps the lie scoped.
// ---------------------------------------------------------------------------
const RASP_RE = /libAppGuard\.so|libRiskStub\.so|libappsec\.so|libapproov\.so/i;

/*
 * Resolve the owning module on demand rather than caching a range list up
 * front: the RASP reads ro.product.model at ~0.4s, well before a periodic
 * refresh would have populated anything, so a prebuilt list silently misses
 * every early probe. Results are memoised per module name.
 */
const raspCache = Object.create(null);

function fromRasp(addr) {
    if (!addr) return false;
    try {
        const m = Process.findModuleByAddress(addr);
        if (!m) return false;
        const k = m.name;
        if (!(k in raspCache)) raspCache[k] = RASP_RE.test(k);
        return raspCache[k];
    } catch (e) { return false; }
}

function gx(n) { try { return Module.findGlobalExportByName(n); } catch (e) { return null; } }

const log = (m) => { if (VERBOSE) send(m); };
const keepAlive = [];   // prevent GC of spoofed C strings

// ---------------------------------------------------------------------------
// 1. Properties
// ---------------------------------------------------------------------------
const PROP_MAP = {
    'ro.kernel.qemu': '0',
    'ro.boot.qemu': '0',
    'ro.hardware': 'exynos850',
    'ro.boot.hardware': 'exynos850',
    'ro.hardware.egl': 'mali',
    'ro.hardware.gralloc': 'exynos850',
    'ro.hardware.vulkan': 'mali',
    'ro.hardware.power': 'exynos850',
    'ro.boot.hardware.vulkan': 'mali',
    'ro.product.board': 'exynos850',
    'ro.product.model': 'SM-A536B',
    'ro.product.name': 'a32nsxx',
    'ro.product.device': 'a32',
    'ro.product.brand': 'samsung',
    'ro.product.manufacturer': 'samsung',
    'ro.product.system.model': 'SM-A536B',
    'ro.product.vendor.model': 'SM-A536B',
    'ro.build.characteristics': 'nosdcard',
    // SM-A536B tidak pernah mendapat Android 16 — SDK 36 + model itu sendiri
    // sudah merupakan kombinasi yang mustahil dan menandakan emulator.
    // Hanya terlihat oleh pemanggil RASP, jadi tidak mengganggu app.
    'ro.build.version.sdk': '33',
    'ro.build.version.release': '13',
    'ro.build.product': 'a32',
    'ro.build.flavor': 'a32nsxx-user',
    'ro.serialno': 'R58N70ABCDE',
    'ro.boot.serialno': 'R58N70ABCDE',
    'ro.bootmode': 'unknown',
    'ro.boot.mode': 'normal'
};
const FP = 'samsung/a32nsxx/a32:13/TP1A.220624.014/A325FXXU2CWB1:user/release-keys';
['ro.build.fingerprint', 'ro.system.build.fingerprint', 'ro.vendor.build.fingerprint',
 'ro.odm.build.fingerprint', 'ro.bootimage.build.fingerprint', 'ro.product.build.fingerprint'
].forEach(k => PROP_MAP[k] = FP);

const EMU_VAL_RE = /qemu|goldfish|ranchu|emulation|emulator|sdk_gphone|generic|vbox|genymotion/i;

function spoofValue(name, value) {
    if (Object.prototype.hasOwnProperty.call(PROP_MAP, name)) return PROP_MAP[name];
    if (name.indexOf('ro.boot.qemu') === 0 || name.indexOf('qemu.') === 0) return '';
    if (value && EMU_VAL_RE.test(value)) return 'unknown';
    return null;
}

const spg = gx('__system_property_get');
if (spg) {
    Interceptor.attach(spg, {
        onEnter(a) {
            this.rasp = fromRasp(this.returnAddress);
            this.n = a[0].readCString();
            this.buf = a[1];
        },
        onLeave(rv) {
            if (!this.rasp || !this.n) return;
            let cur = '';
            try { cur = this.buf.readCString() || ''; } catch (e) {}
            const nv = spoofValue(this.n, cur);
            if (nv === null || nv === cur) return;
            try {
                this.buf.writeUtf8String(nv);
                rv.replace(nv.length);
                log('SPOOF prop ' + this.n + ': "' + cur + '" -> "' + nv + '"');
            } catch (e) {}
        }
    });
    send('armed __system_property_get');
}

const sprc = gx('__system_property_read_callback');
if (sprc) {
    const cbType = ['pointer', 'pointer', 'pointer', 'uint32'];
    Interceptor.attach(sprc, {
        onEnter(a) {
            if (!fromRasp(this.returnAddress)) return;
            const orig = a[1];
            const origFn = new NativeFunction(orig, 'void', cbType);
            const wrapper = new NativeCallback(function (cookie, name, value, serial) {
                let n = '', v = '';
                try { n = name.readCString() || ''; v = value.readCString() || ''; } catch (e) {}
                const nv = spoofValue(n, v);
                if (nv !== null && nv !== v) {
                    const s = Memory.allocUtf8String(nv);
                    keepAlive.push(s);
                    log('SPOOF propcb ' + n + ': "' + v + '" -> "' + nv + '"');
                    return origFn(cookie, name, s, serial);
                }
                return origFn(cookie, name, value, serial);
            }, 'void', cbType);
            keepAlive.push(wrapper);
            a[1] = wrapper;
        }
    });
    send('armed __system_property_read_callback');
}

// ---------------------------------------------------------------------------
// 2 + 3. Files: qemu device nodes and EGL emulation libraries
// ---------------------------------------------------------------------------
/*
 * Deliberately narrow. /dev/goldfish_sync, /dev/goldfish_pipe* and the
 * /vendor/lib64/egl/*_emulation.so libraries are opened by the REAL graphics
 * stack — hiding those crashes the Flutter raster thread ("Bad access due to
 * invalid address"). Only the nodes the RASP probes as emulator tells, and
 * artifacts that never exist on a genuine device, are hidden here.
 */
const DENY_RE = /\/dev\/qemu_pipe|socket\/qemud|qemu_trace|ttVM_x86|vbox86|bluestacks|BstSharedFolder|nemusf|fstab\.nox|init\.nox|ueventd\.nox/i;

function armPathFn(fn, idx) {
    const p = gx(fn);
    if (!p) return;
    try {
        Interceptor.attach(p, {
            onEnter(a) {
                this.hide = false;
                if (!fromRasp(this.returnAddress)) return;
                let s = null;
                try { s = a[idx].readCString(); } catch (e) {}
                if (s && DENY_RE.test(s)) { this.hide = true; this.path = s; }
            },
            onLeave(rv) {
                if (!this.hide) return;
                if (rv.toInt32() >= 0) {
                    log('HIDE ' + fn + '("' + this.path + '")  ' + rv + ' -> -1');
                    rv.replace(ptr(-1));
                }
            }
        });
    } catch (e) {}
}

[['open', 0], ['open64', 0], ['__open_2', 0], ['openat', 1], ['__openat_2', 1],
 ['access', 0], ['faccessat', 1], ['stat', 0], ['stat64', 0], ['lstat', 0],
 ['fopen', 0], ['fopen64', 0]].forEach(x => armPathFn(x[0], x[1]));
send('armed file hiding');

// ---------------------------------------------------------------------------
// 4. Java layer.
// android.os.Build.* are `static final String` fields populated from
// SystemProperties when the class initialises — inside zygote, long before our
// native hooks exist. Spoofing properties therefore never reaches them, so the
// RASP's Java half still sees sdk_gphone64_arm64/ranchu. Rewrite the fields
// directly, and hook SystemProperties.get for anything read later.
// ---------------------------------------------------------------------------
const BUILD_FIELDS = {
    FINGERPRINT: FP,
    MODEL: 'SM-A536B',
    PRODUCT: 'a32nsxx',
    DEVICE: 'a32',
    BOARD: 'exynos850',
    BRAND: 'samsung',
    MANUFACTURER: 'samsung',
    HARDWARE: 'exynos850',
    HOST: 'SWDD6719',
    USER: 'dpi',
    TAGS: 'release-keys',
    TYPE: 'user',
    DISPLAY: 'TP1A.220624.014.A325FXXU2CWB1',
    ID: 'TP1A.220624.014',
    SERIAL: 'R58N70ABCDE',
    BOOTLOADER: 'A325FXXU2CWB1'
};

function spoofJava() {
    Java.perform(function () {
        let done = 0;
        try {
            const B = Java.use('android.os.Build');
            Object.keys(BUILD_FIELDS).forEach(function (f) {
                try {
                    const fld = B[f];
                    if (fld && fld.value !== BUILD_FIELDS[f]) { fld.value = BUILD_FIELDS[f]; done++; }
                } catch (e) {}
            });
            send('Build spoofed (' + done + ' fields): MODEL=' + B.MODEL.value +
                 ' HARDWARE=' + B.HARDWARE.value + ' FINGERPRINT=' + B.FINGERPRINT.value);
        } catch (e) { send('Build spoof failed: ' + e); }

        try {
            const SP = Java.use('android.os.SystemProperties');
            SP.get.overload('java.lang.String').implementation = function (k) {
                const v = this.get(k);
                const nv = spoofValue(k, v);
                if (nv !== null && nv !== v) { log('SPOOF jprop ' + k + ': "' + v + '" -> "' + nv + '"'); return nv; }
                return v;
            };
            SP.get.overload('java.lang.String', 'java.lang.String').implementation = function (k, d) {
                const v = this.get(k, d);
                const nv = spoofValue(k, v);
                if (nv !== null && nv !== v) { log('SPOOF jprop ' + k + ': "' + v + '" -> "' + nv + '"'); return nv; }
                return v;
            };
            send('armed SystemProperties.get');
        } catch (e) { send('SystemProperties hook failed: ' + e); }
    });
}

/*
 * At spawn time (pre-resume) the ART VM does not exist yet, so the `Java`
 * binding is not even defined — referencing it throws. Poll until the runtime
 * is up, then spoof once. The RASP reads Build/model at ~2.5s, so a 25ms poll
 * lands comfortably ahead of it.
 */
let javaDone = false;
const javaPoll = setInterval(function () {
    if (javaDone) { clearInterval(javaPoll); return; }
    try {
        if (typeof Java === 'undefined' || !Java.available) return;
        javaDone = true;
        clearInterval(javaPoll);
        spoofJava();
    } catch (e) { /* VM not ready yet */ }
}, 25);

// ---------------------------------------------------------------------------
// Visibility: report anything RASP-originated that still smells like emulator.
// ---------------------------------------------------------------------------
let n = 0;
setInterval(function () { send("tick " + (++n)); }, 2000);

send('emu-bypass ready');
