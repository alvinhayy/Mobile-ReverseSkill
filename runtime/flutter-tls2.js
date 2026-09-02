/*
 * flutter-tls2.js — locate and neutralise BoringSSL's ssl_verify_peer_cert
 * inside a stripped libflutter.so (arm64).
 * Authorized engagement use only.
 *
 * The stock NVISO technique (ADRP+ADD adjacency to the "ssl_client" string)
 * returned no xref on this build, so this widens the search:
 *   - scans every executable range of the module, not just .text guesses
 *   - accepts ADRP + {ADD imm | LDR uimm} with a 32-instruction lookahead
 *   - also accepts 64-bit literal pointers to the string (literal pools)
 * then walks backwards to the function prologue and replaces it with
 * `mov w0, #1; ret` (BoringSSL: 1 == ssl_verify_ok).
 */

const T = (m) => send('[tls2] ' + m);

function execRanges(mod) {
    const lo = mod.base, hi = mod.base.add(mod.size);
    return Process.enumerateRanges('r-x').filter(r =>
        r.base.compare(lo) >= 0 && r.base.compare(hi) < 0);
}

function findString(mod, str) {
    const pat = Array.from(str, c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ') + ' 00';
    const lo = mod.base, hi = mod.base.add(mod.size);
    let hits = [];
    Process.enumerateRanges('r--')
        .filter(r => r.base.compare(lo) >= 0 && r.base.compare(hi) < 0)
        .forEach(r => {
            const end = r.base.add(r.size).compare(hi) > 0 ? hi : r.base.add(r.size);
            const sz = end.sub(r.base).toInt32();
            if (sz > 0) { try { hits = hits.concat(Memory.scanSync(r.base, sz, pat)); } catch (e) {} }
        });
    return hits.map(h => h.address);
}

const LOOKAHEAD = 32;

function xrefsTo(mod, target) {
    const out = [];
    execRanges(mod).forEach(function (r) {
        let buf;
        try { buf = r.base.readByteArray(r.size); } catch (e) { return; }
        const u32 = new Uint32Array(buf);
        for (let i = 0; i < u32.length; i++) {
            const ins = u32[i];
            if ((ins & 0x9f000000) !== 0x90000000) continue;      // ADRP
            const immlo = (ins >>> 29) & 3, immhi = (ins >>> 5) & 0x7ffff;
            let imm = (immhi << 2) | immlo;
            if (imm & 0x100000) imm -= 0x200000;
            const rd = ins & 0x1f;
            const pc = r.base.add(i * 4);
            const page = pc.and(ptr(0xfff).not()).add(imm * 4096);
            for (let k = 1; k <= LOOKAHEAD && i + k < u32.length; k++) {
                const n = u32[i + k];
                // ADD Xd, Xn, #imm12
                if ((n & 0xffc00000) === 0x91000000 && ((n >>> 5) & 0x1f) === rd) {
                    if (page.add((n >>> 10) & 0xfff).equals(target)) { out.push(pc); }
                    break;
                }
                // LDR Xt, [Xn, #uimm12]
                if ((n & 0xffc00000) === 0xf9400000 && ((n >>> 5) & 0x1f) === rd) {
                    if (page.add((((n >>> 10) & 0xfff) * 8)).equals(target)) { out.push(pc); }
                    break;
                }
                // register clobbered by another ADRP -> stop
                if ((n & 0x9f000000) === 0x90000000 && (n & 0x1f) === rd) break;
            }
        }
    });
    return out;
}

// Walk back to a plausible function start: STP x29,x30,[sp,#-N]! or SUB sp,sp,#N
function findPrologue(addr, maxBack) {
    for (let i = 0; i < maxBack; i++) {
        const p = addr.sub(i * 4);
        let ins;
        try { ins = p.readU32(); } catch (e) { return null; }
        if ((ins & 0xffc003e0) === 0xa98003e0) return p;           // STP ..,[sp,#-imm]!
        if ((ins & 0xffc003ff) === 0xd10003ff) return p;           // SUB sp, sp, #imm
        if ((ins & 0xfffffc1f) === 0xd503201f && i > 4) { /* nop padding */ }
    }
    return null;
}

function run() {
    const mod = Process.findModuleByName('libflutter.so');
    if (!mod) return false;
    T('libflutter.so @ ' + mod.base + ' size=' + mod.size);

    let targets = [];
    ['ssl_client', 'ssl_server'].forEach(function (s) {
        const addrs = findString(mod, s);
        T('"' + s + '" -> ' + addrs.length + ' hit(s): ' + addrs.join(', '));
        addrs.forEach(a => {
            const x = xrefsTo(mod, a);
            T('  xrefs to ' + a + ': ' + x.length + (x.length ? ' -> ' + x.slice(0, 6).join(', ') : ''));
            x.forEach(p => targets.push(p));
        });
    });

    if (!targets.length) { T('NO XREFS FOUND — cannot locate ssl_verify_peer_cert'); return true; }

    const fns = {};
    targets.forEach(function (p) {
        const f = findPrologue(p, 600);
        if (f) fns[f.toString()] = f;
    });
    const list = Object.keys(fns).map(k => fns[k]);
    T('candidate functions (' + list.length + '): ' + list.join(', '));

    list.forEach(function (f) {
        try {
            Interceptor.replace(f, new NativeCallback(function () {
                return 1;                      // ssl_verify_ok
            }, 'int', ['pointer', 'pointer']));
            T('PATCHED ' + f + ' -> return 1 (ssl_verify_ok)');
        } catch (e) { T('patch failed at ' + f + ': ' + e); }
    });
    return true;
}

let done = false;
const poll = setInterval(function () {
    if (done) { clearInterval(poll); return; }
    try { if (run()) { done = true; clearInterval(poll); } } catch (e) { T('run error: ' + e); }
}, 300);
