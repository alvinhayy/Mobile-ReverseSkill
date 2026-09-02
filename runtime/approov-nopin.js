/*
 * approov-nopin.js — paksa Approov memakai jalur "pinning bypassed" miliknya sendiri.
 * Authorized engagement use only.
 *
 * LATAR
 * -----
 * Patch BoringSSL ([`flutter-tls3.js`](flutter-tls3.js)) mematikan verifikasi rantai
 * sertifikat, tapi Approov memasang pinning SENDIRI di lapisan Dart di atasnya.
 * Akibatnya trafik API the target tetap menolak sertifikat Burp dan tidak pernah muncul
 * di Proxy history — hanya telemetri IronSky (klien Java) yang tercegat.
 *
 * TEMUAN
 * ------
 * `_createPinnedHttpClient` (libapp.so +0x15ded14) sudah punya jalur sah untuk
 * berjalan TANPA pinning — dipakai ketika Approov belum terinisialisasi:
 *
 *   0x15ded54  bl   _requireInitialized()
 *   0x15ded60  bl   Await()
 *   0x15ded68  tbz  w0, #4, #0x15dee74     <-- cabang penentu
 *   0x15ded6c  ...                          <-- FALL-THROUGH: jalur tanpa pinning
 *   0x15ded74  bl   HttpClient()                 buat client biasa
 *              bl   _copyClientState()
 *   0x15dee4c  r16 = ", pinning bypassed"        catat di log
 *   0x15dee68  bl   Logger::d()
 *   0x15dee70  b    ReturnAsyncNotFuture()       kembalikan client polos
 *
 *   0x15dee74  ...                          <-- CABANG DIAMBIL: setup pinning
 *              (Stopwatch, fetch pin dari layanan Approov, dst)
 *
 * Jadi cukup meng-NOP satu cabang: fall-through selalu terjadi, Approov selalu
 * mengembalikan HttpClient polos. Ini memakai jalur yang memang disediakan SDK,
 * bukan menambal callback verifikasi — jauh lebih kecil risikonya merusak state.
 *
 * Encoding diverifikasi statis dengan radare2:
 *   0x015ded68  60082036   tbz w0, 4, 0x15dee74     -> little-endian 0x36200860
 */

(function () {

const BRANCH_OFF = 0x15ded68;
const EXPECT = 0x36200860;      // tbz w0, #4, #0x15dee74
const NOP = 0xd503201f;

const A = (m) => send('[nopin] ' + m);

function patch() {
    const m = Process.findModuleByName('libapp.so');
    if (!m) return false;

    const p = m.base.add(BRANCH_OFF);
    let cur;
    try { cur = p.readU32(); } catch (e) { A('tidak bisa membaca ' + p + ': ' + e); return true; }

    if (cur === NOP) { A('sudah ter-patch'); return true; }
    if (cur !== EXPECT) {
        A('SIGNATURE MISMATCH di ' + p + ' — dapat 0x' + cur.toString(16) +
          ', diharapkan 0x' + EXPECT.toString(16) + ' — TIDAK di-patch');
        return true;
    }

    try {
        Memory.patchCode(p, 4, function (w) { w.writeU32(NOP); });
        A('PATCHED tbz@0x' + BRANCH_OFF.toString(16) + ' -> NOP  (Approov selalu "pinning bypassed")');
    } catch (e) { A('patch gagal: ' + e); }
    return true;
}

let done = false;
const poll = setInterval(function () {
    if (done) { clearInterval(poll); return; }
    try { if (patch()) { done = true; clearInterval(poll); } } catch (e) { A('err ' + e); }
}, 200);

})();
