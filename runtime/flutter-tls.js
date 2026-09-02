/*
 * the target app (- Flutter/BoringSSL TLS verification bypass (arm64)
 * Authorized engagement use only.
 *
 * WHY THE USUAL TOOLING DOES NOTHING HERE
 * --------------------------------------
 * This is a Flutter app. Dart's HttpClient does NOT use the Android system
 * trust store, javax.net.ssl.TrustManager, OkHttp, or Conscrypt. It uses a
 * BoringSSL copy statically linked into libflutter.so. Consequently:
 *
 *   - objection's `android sslpinning disable`  -> no effect
 *   - frida-multiple-unpinning / universal scripts -> no effect
 *   - installing a CA into the system trust store  -> no effect
 *
 * The only thing that works at this layer is patching BoringSSL's chain
 * verification inside libflutter.so, which is what this script does.
 *
 * libflutter.so is stripped, so we locate the target function by finding the
 * "ssl_client" string in .rodata and walking ADRP/ADD cross-references in
 * .text - the technique used by NVISO's disable-flutter-tls-verification.
 *
 * NOTE ON APPROOV (read this before assuming success)
 * ---------------------------------------------------
 * Patching BoringSSL defeats *transport* validation, but this app layers
 * Approov's own pinning ON TOP, in Dart:
 *     _pinnedSecurityContext@843380239
 *     _pinningFailureCallback@843380239
 *     SecurityContext_SetTrustedCertificatesBytes
 * Approov compares the leaf public key against pins it fetches from its own
 * service. That check runs in compiled Dart, above this hook, and will still
 * fail. See runtime/README.md - the supported route is to have the Approov
 * admin register your mitm CA / issue a dev key, not to fight the SDK.
 *
 * Usage:
 *   frida -U -f com.example.targetapp -l rasp-bypass.js -l flutter-tls.js
 */

'use strict';

(function () {   // IIFE: avoid clashing with rasp-bypass.js in frida's shared global scope

const _legacyFind = Module['find' + 'ExportByName'];
function resolveExport(moduleName, symbol) {
    try {
        if (moduleName === null || moduleName === undefined) {
            if (typeof Module.findGlobalExportByName === 'function')
                return Module.findGlobalExportByName(symbol);
        } else {
            if (typeof Process.findModuleByName === 'function') {
                const m = Process.findModuleByName(moduleName);
                if (m && typeof m.findExportByName === 'function')
                    return m.findExportByName(symbol);
            }
        }
        if (typeof _legacyFind === 'function')
            return _legacyFind.call(Module, moduleName, symbol);
    } catch (e) {}
    return null;
}

const log = (m) => console.log('[tls] ' + m);

function hex(p) { return p.toString(); }

// ---------------------------------------------------------------------------
// Locate libflutter.so - it may not be loaded at spawn time, so we retry on
// dlopen if it's not present yet.
// ---------------------------------------------------------------------------
function findFlutter() {
    const m = Process.findModuleByName('libflutter.so');
    return m || null;
}

// ---------------------------------------------------------------------------
// Find occurrences of a NUL-terminated string inside a module's mapped range.
// ---------------------------------------------------------------------------
function findStringAddrs(mod, str) {
    const pattern = Array.from(str, (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ')
                  + ' 00';

    // Scanning base..base+size blindly throws "access violation": a module's
    // declared size spans page-aligned gaps and PROT_NONE guard pages that are
    // not readable. Enumerate the actually-readable ranges belonging to this
    // module and scan each one independently instead.
    const modStart = mod.base;
    const modEnd   = mod.base.add(mod.size);

    const readable = Process.enumerateRanges('r--').filter(function (r) {
        return r.base.compare(modStart) >= 0 && r.base.compare(modEnd) < 0;
    });

    if (readable.length === 0) {
        log('no readable ranges inside module - cannot scan');
        return [];
    }

    let hits = [];
    let scanned = 0;
    readable.forEach(function (r) {
        // clamp the range so we never read past the module's end
        const end  = r.base.add(r.size).compare(modEnd) > 0 ? modEnd : r.base.add(r.size);
        const size = end.sub(r.base).toInt32();
        if (size <= 0) return;
        try {
            hits = hits.concat(Memory.scanSync(r.base, size, pattern));
            scanned++;
        } catch (e) {
            // a range can still vanish mid-scan; skip it rather than abort
        }
    });

    log('scanned ' + scanned + '/' + readable.length + ' readable ranges, ' + hits.length + ' hit(s)');
    return hits.map((h) => h.address);
}

// ---------------------------------------------------------------------------
// Decode an arm64 ADRP+ADD pair to the absolute address it materialises.
// ADRP: 1 immlo(2) 10000 immhi(19) Rd(5)
// ADD (immediate, 64-bit): 1001000100 imm12 Rn Rd
// ---------------------------------------------------------------------------
// The ADD/LDR that completes an ADRP pair is frequently NOT the next
// instruction - the compiler schedules unrelated work in between. So decode the
// ADRP, then look ahead up to LOOKAHEAD instructions for the first ADD (imm) or
// LDR (unsigned offset) whose base register is the ADRP's destination.
// Returns { addr, at } or null.
const LOOKAHEAD = 12;

function decodeAdrpRef(pc) {
    const adrp = pc.readU32();
    if ((adrp & 0x9f000000) !== 0x90000000) return null;       // not ADRP
    const immlo = (adrp >>> 29) & 0x3;
    const immhi = (adrp >>> 5) & 0x7ffff;
    let imm = (immhi << 2) | immlo;
    if (imm & 0x100000) imm -= 0x200000;                        // sign-extend 21 bits
    const rdAdrp = adrp & 0x1f;

    const page = pc.and(ptr(0xfff).not()).add(imm * 4096);

    for (let k = 1; k <= LOOKAHEAD; k++) {
        let ins;
        try { ins = pc.add(k * 4).readU32(); } catch (e) { return null; }

        // ADD Xd, Xn, #imm12  (64-bit, shift=0)
        if ((ins & 0xffc00000) === 0x91000000) {
            const rn = (ins >>> 5) & 0x1f;
            if (rn === rdAdrp) {
                const imm12 = (ins >>> 10) & 0xfff;
                return { addr: page.add(imm12), at: pc.add(k * 4) };
            }
        }

        // LDR Xt, [Xn, #imm12*8]  (64-bit unsigned offset) - string referenced
        // via a pointer slot rather than materialised directly
        if ((ins & 0xffc00000) === 0xf9400000) {
            const rn = (ins >>> 5) & 0x1f;
            if (rn === rdAdrp) {
                const imm12 = (ins >>> 10) & 0xfff;
                return { addr: page.add(imm12 * 8), at: pc.add(k * 4), indirect: true };
            }
        }

        // if the ADRP destination is overwritten by another ADRP, stop tracking
        if ((ins & 0x9f000000) === 0x90000000 && (ins & 0x1f) === rdAdrp) return null;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Walk backwards from an address to the enclosing function prologue.
// Heuristic: look for STP x29,x30,[sp,#-N]! (0xa9?? 7bfd pattern family)
// ---------------------------------------------------------------------------
function findFunctionStart(addr, maxBack) {
    for (let i = 0; i < maxBack; i += 4) {
        const p = addr.sub(i);
        let ins;
        try { ins = p.readU32(); } catch (e) { return null; }
        // STP x29, x30, [sp, #imm]!  -> 0xA9BX7BFD
        if ((ins & 0xffc07fff) === 0xa98003fd || (ins & 0xffc07fff) === 0xa9807bfd) return p;
        if ((ins & 0x7fc07fff) === 0x29807bfd) return p;
        // SUB sp, sp, #imm  as an alternative prologue opener
        if ((ins & 0xffc003ff) === 0xd10003ff && i > 0) return p;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Main: find ssl_client xref -> enclosing function -> hook it to return 1.
// In BoringSSL, ssl_crypto_x509_session_verify_cert_chain returns int
// (1 = chain OK). Forcing 1 accepts any presented certificate.
// ---------------------------------------------------------------------------
function installHook(mod) {
    log('libflutter.so @ ' + hex(mod.base) + ' size=' + mod.size);

    const strAddrs = findStringAddrs(mod, 'ssl_client');
    if (strAddrs.length === 0) {
        log('ERROR: "ssl_client" string not found - Flutter version may differ.');
        log('Fall back to reFlutter (see runtime/README.md).');
        return false;
    }
    log('found "ssl_client" at ' + strAddrs.map(hex).join(', '));

    // Scan .text for ADRP/ADD pairs that resolve to any of those addresses.
    const targets = new Set(strAddrs.map((a) => a.toString()));
    const candidates = [];

    const ranges = Process.enumerateRanges({ protection: 'r-x', coalesce: false })
        .filter((r) => r.base.compare(mod.base) >= 0
                    && r.base.compare(mod.base.add(mod.size)) < 0);

    ranges.forEach(function (r) {
        for (let off = 0; off + 8 <= r.size; off += 4) {
            const pc = r.base.add(off);
            let ref;
            try { ref = decodeAdrpRef(pc); } catch (e) { continue; }
            if (!ref) continue;
            if (targets.has(ref.addr.toString())) {
                candidates.push(pc);
                continue;
            }
            // indirect: the slot may hold a pointer to the string
            if (ref.indirect) {
                try {
                    const deref = ref.addr.readPointer();
                    if (targets.has(deref.toString())) candidates.push(pc);
                } catch (e) { /* slot not readable */ }
            }
        }
    });

    if (candidates.length === 0) {
        log('ERROR: no ADRP/ADD xref to "ssl_client" found.');
        return false;
    }
    log('xref sites: ' + candidates.map(hex).join(', '));

    let hooked = 0;
    candidates.forEach(function (site) {
        const fn = findFunctionStart(site, 0x600);
        if (!fn) { log('could not resolve function start for ' + hex(site)); return; }

        try {
            Interceptor.attach(fn, {
                onLeave: function (retval) {
                    if (retval.toInt32() !== 1) {
                        log('cert chain verify -> forcing OK (was ' + retval.toInt32() + ')');
                        retval.replace(ptr(1));
                    }
                }
            });
            log('hooked verify candidate @ ' + hex(fn));
            hooked++;
        } catch (e) {
            log('hook failed @ ' + hex(fn) + ': ' + e);
        }
    });

    return hooked > 0;
}

// ---------------------------------------------------------------------------
// Also surface Approov's Dart-layer pinning decisions so you can see, in the
// log, that transport verification passed but Approov pinning still rejected.
// That distinction is the whole point when triaging a failed intercept.
// ---------------------------------------------------------------------------
function watchApproov() {
    const dlopen = resolveExport(null, 'android_dlopen_ext');
    if (!dlopen) return;
    Interceptor.attach(dlopen, {
        onEnter: function (args) {
            try { this.lib = args[0].readCString(); } catch (e) { this.lib = null; }
        },
        onLeave: function () {
            if (this.lib && /approov/i.test(this.lib)) {
                log('NOTE: libapproov.so loaded - Approov pinning is ABOVE this hook.');
                log('      A clean TLS hook will still fail Approov pin comparison.');
            }
        }
    });
}

watchApproov();

const mod = findFlutter();
if (mod) {
    installHook(mod);
} else {
    log('libflutter.so not yet loaded - waiting for dlopen...');
    const dlopen = resolveExport(null, 'android_dlopen_ext');
    Interceptor.attach(dlopen, {
        onEnter: function (args) {
            try { this.lib = args[0].readCString(); } catch (e) { this.lib = null; }
        },
        onLeave: function () {
            if (this.lib && this.lib.indexOf('libflutter.so') !== -1) {
                const m = findFlutter();
                if (m) { installHook(m); }
            }
        }
    });
}

})();
