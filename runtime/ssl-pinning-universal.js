/* ssl-pinning-universal.js — Android 5-layer SSL-pinning bypass.
 * frida -U -f <pkg> -l runtime/ssl-pinning-universal.js */
Java.perform(function () {
  // L2: OkHttp CertificatePinner
  try {
    var CP = Java.use("okhttp3.CertificatePinner");
    CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {};
    console.log("[+] OkHttp CertificatePinner disabled");
  } catch (e) {}
  // L1: Conscrypt TrustManagerImpl
  try {
    var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    if (TMI.verifyChain) TMI.verifyChain.implementation = function () { return Java.use("java.util.ArrayList").$new(); };
    if (TMI.checkTrustedRecursive) TMI.checkTrustedRecursive.implementation = function () { return Java.use("java.util.ArrayList").$new(); };
    console.log("[+] TrustManagerImpl neutralised");
  } catch (e) {}
  // L3: WebView SslErrorHandler
  try { Java.use("android.webkit.SslErrorHandler").proceed.implementation = function () { return this.proceed(); }; } catch (e) {}
  console.log("[+] ssl-pinning-universal (java) loaded");
});
// L5: native BoringSSL/OpenSSL SSL_get_verify_result → X509_V_OK (0)
try {
  var g = Module.findExportByName(null, "SSL_get_verify_result");
  if (g) Interceptor.replace(g, new NativeCallback(function () { return 0; }, 'long', ['pointer']));
} catch (e) {}
