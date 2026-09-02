/*
 * probe-emu.js — log the emulator-relevant signals the RASP reads.
 * Authorized engagement use only. Run via runtime/drive.py.
 */
'use strict';

const EMU_RE = /qemu|goldfish|ranchu|emu|generic|sdk_gphone|vbox|genymotion|bluestacks|nox/i;
const seen = {};

function once(k, m) {
    if (seen[k]) return;
    seen[k] = 1;
    send(m);
}

function gx(n) { try { return Module.findGlobalExportByName(n); } catch (e) { return null; } }

// --- properties -------------------------------------------------------------
const spg = gx('__system_property_get');
if (spg) {
    Interceptor.attach(spg, {
        onEnter(a) { this.n = a[0].readCString(); this.buf = a[1]; },
        onLeave() {
            let v = '';
            try { v = this.buf.readCString() || ''; } catch (e) {}
            if (EMU_RE.test(this.n || '') || EMU_RE.test(v)) {
                once('p:' + this.n + '=' + v, 'PROP ' + this.n + ' = "' + v + '"');
            }
        }
    });
    send('armed __system_property_get');
}

const sprc = gx('__system_property_read_callback');
if (sprc) {
    Interceptor.attach(sprc, {
        onEnter(a) {
            this.cb = a[1];
            this.orig = a[1];
            const self = this;
            // wrap the callback so we can see name/value
            this.replacement = new NativeCallback(function (cookie, name, value, serial) {
                try {
                    const n = name.readCString() || '', v = value.readCString() || '';
                    if (EMU_RE.test(n) || EMU_RE.test(v))
                        once('c:' + n + '=' + v, 'PROPCB ' + n + ' = "' + v + '"');
                } catch (e) {}
                return new NativeFunction(self.orig, 'void',
                    ['pointer', 'pointer', 'pointer', 'uint32'])(cookie, name, value, serial);
            }, 'void', ['pointer', 'pointer', 'pointer', 'uint32']);
            a[1] = this.replacement;
        }
    });
    send('armed __system_property_read_callback');
}

// --- file probes ------------------------------------------------------------
['open', 'open64', 'openat', '__openat_2', 'access', 'stat', 'lstat', 'faccessat'].forEach(function (fn) {
    const p = gx(fn);
    if (!p) return;
    // path arg index: openat/faccessat take (dirfd, path, ...)
    const idx = /openat|faccessat/.test(fn) ? 1 : 0;
    try {
        Interceptor.attach(p, {
            onEnter(a) {
                let s = null;
                try { s = a[idx].readCString(); } catch (e) {}
                if (s && EMU_RE.test(s)) once('f:' + fn + s, 'FILE ' + fn + '("' + s + '")');
            }
        });
    } catch (e) {}
});
send('armed file probes');

// --- Java Build fields ------------------------------------------------------
setTimeout(function () {
    if (!Java.available) { send('java unavailable'); return; }
    Java.perform(function () {
        try {
            const B = Java.use('android.os.Build');
            send('Build.FINGERPRINT = ' + B.FINGERPRINT.value);
            send('Build.MODEL       = ' + B.MODEL.value);
            send('Build.HARDWARE    = ' + B.HARDWARE.value);
            send('Build.PRODUCT     = ' + B.PRODUCT.value);
        } catch (e) { send('Build read failed: ' + e); }

        try {
            const SP = Java.use('android.os.SystemProperties');
            SP.get.overload('java.lang.String').implementation = function (k) {
                const v = this.get(k);
                if (EMU_RE.test(k) || EMU_RE.test(v || ''))
                    once('j:' + k + '=' + v, 'JPROP ' + k + ' = "' + v + '"');
                return v;
            };
            SP.get.overload('java.lang.String', 'java.lang.String').implementation = function (k, d) {
                const v = this.get(k, d);
                if (EMU_RE.test(k) || EMU_RE.test(v || ''))
                    once('j2:' + k + '=' + v, 'JPROP2 ' + k + ' = "' + v + '"');
                return v;
            };
            send('armed SystemProperties.get');
        } catch (e) { send('SystemProperties fail: ' + e); }
    });
}, 1200);

// --- heartbeat --------------------------------------------------------------
let n = 0;
setInterval(function () { send('tick ' + (++n)); }, 2000);

send('probe ready');
