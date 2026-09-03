/* ios-bypass.js — iOS jailbreak-detection + anti-debug + SSL-pinning bypass.
 * frida -U -f <bundle-id> -l runtime/ios-bypass.js   (authorized targets only) */
// --- jailbreak: filesystem checks ---
try {
  var fm = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
  Interceptor.attach(fm.implementation, {
    onEnter: function (a) { this.p = new ObjC.Object(a[2]).toString(); },
    onLeave: function (r) {
      if (this.p && /Cydia|\/var\/lib\/apt|sshd|\/bin\/bash|MobileSubstrate|\/etc\/apt/.test(this.p)) r.replace(0);
    }
  });
} catch (e) {}
// --- fork blocked in sandbox → return -1 ---
try { Interceptor.replace(Module.findExportByName(null,"fork"), new NativeCallback(function(){ return -1; },'int',[])); } catch (e) {}
// --- dyld image count clamp ---
try {
  var dc = Module.findExportByName(null, "_dyld_get_image_count");
  Interceptor.attach(dc, { onLeave: function (r) { if (r.toInt32() > 200) r.replace(200); } });
} catch (e) {}
// --- anti-debug: PT_DENY_ATTACH (ptrace request 31) ---
try {
  var pt = Module.findExportByName(null, "ptrace");
  Interceptor.replace(pt, new NativeCallback(function (req, pid, addr, data) {
    if (req === 31) return 0;
    return 0;
  }, 'int', ['int','int','pointer','pointer']));
} catch (e) {}
// --- SSL pinning: SecTrustEvaluate → proceed ---
try {
  var se = Module.findExportByName("Security", "SecTrustEvaluate");
  if (se) Interceptor.replace(se, new NativeCallback(function (trust, result) {
    Memory.writeU32(result, 1); // kSecTrustResultProceed
    return 0;                   // errSecSuccess
  }, 'int', ['pointer','pointer']));
} catch (e) {}
console.log("[+] ios-bypass loaded (jailbreak + anti-debug + SSL)");
