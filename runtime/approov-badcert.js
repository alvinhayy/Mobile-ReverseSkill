/*
 * approov-badcert.js — buat Approov MENERIMA sertifikat Burp.
 * Authorized engagement use only.
 *
 * TEMUAN
 * ------
 * blutter menunjukkan tanda tangan berikut di libapp.so:
 *
 *   [closure] bool _pinningFailureCallback(dynamic, X509Certificate, String, int)
 *
 * Itu persis bentuk `badCertificateCallback` milik dart:io. Approov
 * mendaftarkannya sebagai handler sertifikat-buruk; ketika verifikasi gagal,
 * Dart memanggilnya dan nilai balik `false` membuat koneksi ditutup — inilah
 * yang memunculkan alert TLS `certificate_unknown` dari sisi klien, dan
 * sebabnya patch di lapisan BoringSSL saja tidak pernah cukup.
 *
 * Ekor fungsi (libapp.so +0x15e3c88, size 0xf8):
 *
 *   0x15e3d68  add x0, x22, #0x30    ; x22 = NULL  -> mengembalikan false
 *   0x15e3d6c  mov x15, x29
 *   0x15e3d70  ldp x29, x30, [x15], #0x10
 *   0x15e3d74  ret
 *
 * Konstanta Dart dipetakan dari output blutter sendiri:
 *   true  = NULL + 0x20      false = NULL + 0x30
 *
 * Jadi cukup mengubah immediate-nya 0x30 -> 0x20, sehingga callback
 * mengembalikan `true` = terima sertifikat.
 *
 *   0x9100c2c0  add x0, x22, #0x30   (false)
 *   0x910082c0  add x0, x22, #0x20   (true)
 *
 * Hanya satu immediate yang berubah — struktur frame dan epilog tetap utuh,
 * jadi jauh lebih aman daripada mengganti seluruh fungsi.
 */

(function () {

const RET_OFF = 0x15e3d68;
const EXPECT = 0x9100c2c0;      // add x0, x22, #0x30  -> false
const PATCH  = 0x910082c0;      // add x0, x22, #0x20  -> true

const B = (m) => send('[badcert] ' + m);

function patch() {
    const m = Process.findModuleByName('libapp.so');
    if (!m) return false;

    const p = m.base.add(RET_OFF);
    let cur;
    try { cur = p.readU32(); } catch (e) { B('tidak bisa membaca ' + p + ': ' + e); return true; }

    if (cur === PATCH) { B('sudah ter-patch'); return true; }
    if (cur !== EXPECT) {
        B('SIGNATURE MISMATCH di ' + p + ' — dapat 0x' + cur.toString(16) +
          ', diharapkan 0x' + EXPECT.toString(16) + ' — TIDAK di-patch');
        return true;
    }

    try {
        Memory.patchCode(p, 4, function (w) { w.writeU32(PATCH); });
        B('PATCHED _pinningFailureCallback ret @+0x' + RET_OFF.toString(16) +
          ': false -> true (sertifikat diterima)');
    } catch (e) { B('patch gagal: ' + e); }
    return true;
}

let done = false;
const poll = setInterval(function () {
    if (done) { clearInterval(poll); return; }
    try { if (patch()) { done = true; clearInterval(poll); } } catch (e) { B('err ' + e); }
}, 200);

})();
