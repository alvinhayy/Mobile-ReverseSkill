/* crypto-dump.js — dump app-layer crypto (the wall after you unpin TLS).
 * frida -U -f <pkg> -l runtime/crypto-dump.js
 * Logs keys/IVs and Cipher/Mac/Digest in+out so you can decrypt payloads that are encrypted
 * ABOVE TLS. Combine with a Burp helper that decrypts "msg" fields and re-encrypts in Repeater. */
Java.perform(function () {
  function b64(bytes){ try { return Java.use("android.util.Base64").encodeToString(bytes, 2); } catch (e) { return "<"+ (bytes?bytes.length:0) +" bytes>"; } }
  function hex(bytes){ try { var s=""; for (var i=0;i<Math.min(bytes.length,64);i++){ var h=(bytes[i]&0xff).toString(16); s+=(h.length<2?"0":"")+h; } return s+(bytes.length>64?"…":""); } catch(e){ return ""; } }

  try {
    var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
    SKS.$init.overload('[B','java.lang.String').implementation = function (key, alg) {
      console.log("[crypto][key] alg=" + alg + " key(b64)=" + b64(key) + " hex=" + hex(key));
      return this.$init(key, alg);
    };
  } catch (e) {}
  try {
    var IV = Java.use("javax.crypto.spec.IvParameterSpec");
    IV.$init.overload('[B').implementation = function (iv) { console.log("[crypto][iv] " + b64(iv)); return this.$init(iv); };
  } catch (e) {}
  try {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload('[B').implementation = function (input) {
      var out = this.doFinal(input);
      console.log("[crypto][cipher] " + this.getAlgorithm() + "  in=" + b64(input) + "  out=" + b64(out));
      return out;
    };
  } catch (e) {}
  try {
    var Mac = Java.use("javax.crypto.Mac");
    Mac.doFinal.overload('[B').implementation = function (input) {
      var out = this.doFinal(input); console.log("[crypto][mac] " + this.getAlgorithm() + " out=" + b64(out)); return out;
    };
  } catch (e) {}
  try {
    var MD = Java.use("java.security.MessageDigest");
    MD.digest.overload('[B').implementation = function (input) {
      var out = this.digest(input); console.log("[crypto][digest] " + this.getAlgorithm() + " out=" + hex(out)); return out;
    };
  } catch (e) {}
  console.log("[+] crypto-dump loaded");
});
