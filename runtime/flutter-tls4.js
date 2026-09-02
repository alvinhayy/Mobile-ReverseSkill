/*
 * flutter-tls4.js — matikan verifikasi sertifikat pada level ssl_verify_peer_cert.
 * Authorized engagement use only.
 *
 * MENGAPA flutter-tls3.js TIDAK CUKUP
 * -----------------------------------
 * `ssl_crypto_x509_session_verify_cert_chain` (0x716c3c) memang dipanggil dan
 * sudah dipaksa mengembalikan 1 (terbukti: 8 panggilan, rv asli 0x0). Tapi klien
 * TETAP menolak sertifikat Burp — Event log Burp:
 *
 *   The client failed to negotiate a TLS connection to host.example.internal:8080:
 *   (certificate_unknown) Received fatal alert: certificate_unknown
 *
 * Alert datang dari KLIEN, jadi ada gate verifikasi di atas fungsi tadi.
 *
 * TARGET
 * ------
 * Pemanggilnya tidak bisa ditemukan lewat pemindaian BL — BoringSSL memanggil
 * chain-verifier lewat vtable `ssl_x509_method`. Alamatnya diambil saat runtime
 * dari `this.returnAddress`:
 *
 *   retaddr libflutter+0x706c48  ->  fungsi mulai di +0x7069cc   (ssl_verify_peer_cert)
 *   dipanggil dari libflutter+0x707ed8 (fungsi +0x707644, handshake)
 *
 * `ssl_verify_peer_cert` mengembalikan `enum ssl_verify_result_t`:
 *     ssl_verify_ok = 0, ssl_verify_invalid = 1, ssl_verify_retry = 2
 * jadi patch-nya adalah `return 0` — BUKAN 1 seperti pada chain-verifier yang
 * mengembalikan bool.
 *
 * Signature diverifikasi sebelum patch:
 *   0x7069cc  ffc301d1  sub sp, sp, #0x70      -> 0xd101c3ff
 *   0x7069d0  fe6703a9  stp x30, x25, [sp,#0x30] -> 0xa90367fe
 */

(function () {

const VERIFY_PEER_OFF = 0x7069cc;
const EXPECT = [0xd101c3ff, 0xa90367fe];

const T = (m) => send('[tls4] ' + m);

function patch() {
    const m = Process.findModuleByName('libflutter.so');
    if (!m) return false;

    const fn = m.base.add(VERIFY_PEER_OFF);
    let w0, w1;
    try { w0 = fn.readU32(); w1 = fn.add(4).readU32(); }
    catch (e) { T('tidak bisa membaca ' + fn + ': ' + e); return true; }

    if (w0 !== EXPECT[0] || w1 !== EXPECT[1]) {
        T('SIGNATURE MISMATCH di ' + fn + ' — dapat 0x' + w0.toString(16) + ',0x' + w1.toString(16) +
          ' diharapkan 0x' + EXPECT[0].toString(16) + ',0x' + EXPECT[1].toString(16) + ' — TIDAK di-patch');
        return true;
    }

    try {
        Interceptor.replace(fn, new NativeCallback(function (hs) {
            return 0;                     // ssl_verify_ok
        }, 'int', ['pointer']));
        T('PATCHED ssl_verify_peer_cert @ ' + fn + ' -> return 0 (ssl_verify_ok)');
    } catch (e) { T('patch gagal: ' + e); }
    return true;
}

let done = false;
const poll = setInterval(function () {
    if (done) { clearInterval(poll); return; }
    try { if (patch()) { done = true; clearInterval(poll); } } catch (e) { T('err ' + e); }
}, 200);

})();
