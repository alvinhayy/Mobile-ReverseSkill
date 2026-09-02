/*
 * flutter-tls3.js — disable Flutter/BoringSSL certificate chain verification.
 * Authorized engagement use only.
 *
 * Target resolved statically (runtime ADRP scanning mishandled the negative
 * page offsets — both xrefs to "ssl_client" are backward references):
 *
 *   libflutter.so vaddr 0x716c3c
 *     bool ssl_crypto_x509_session_verify_cert_chain(SSL_SESSION*, SSL_HANDSHAKE*,
 *                                                    uint8_t *out_alert)
 *
 *   Identified by: 3 args, opens with `*out_alert = 0x50` (SSL_AD_INTERNAL_ERROR),
 *   and references both "ssl_client" and "ssl_server" (X509_STORE_CTX_set_default).
 *   Returns bool -> replace with `return true`.
 *
 *   The other "ssl_client" xref (0x6fe3a0) is only a strcmp dispatcher over
 *   X509 purpose names and must NOT be patched.
 *
 * Byte signature is verified before patching so this fails loudly rather than
 * silently corrupting a different function if libflutter.so ever changes.
 */

const VERIFY_CHAIN_VADDR = 0x716c3c;
const EXPECT = [0xd101c3ff, 0xa9017bfd];   // sub sp,sp,#0x70 ; stp x29,x30,[sp,#0x10]

const T = (m) => send('[tls3] ' + m);

function patch() {
    const mod = Process.findModuleByName('libflutter.so');
    if (!mod) return false;

    const fn = mod.base.add(VERIFY_CHAIN_VADDR);
    let w0, w1;
    try { w0 = fn.readU32(); w1 = fn.add(4).readU32(); }
    catch (e) { T('cannot read ' + fn + ': ' + e); return true; }

    if (w0 !== EXPECT[0] || w1 !== EXPECT[1]) {
        T('SIGNATURE MISMATCH at ' + fn +
          ' got 0x' + w0.toString(16) + ',0x' + w1.toString(16) +
          ' expected 0x' + EXPECT[0].toString(16) + ',0x' + EXPECT[1].toString(16) +
          ' — refusing to patch');
        return true;
    }

    try {
        Interceptor.replace(fn, new NativeCallback(function (session, hs, outAlert) {
            return 1;                       // chain verified
        }, 'int', ['pointer', 'pointer', 'pointer']));
        T('PATCHED ssl_crypto_x509_session_verify_cert_chain @ ' + fn + ' -> return true');
    } catch (e) { T('patch failed: ' + e); }
    return true;
}

let done = false;
const poll = setInterval(function () {
    if (done) { clearInterval(poll); return; }
    try { if (patch()) { done = true; clearInterval(poll); } } catch (e) { T('err ' + e); }
}, 200);
