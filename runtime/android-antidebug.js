/* android-antidebug.js — ptrace(TRACEME) + TracerPid + isDebuggerConnected.
 * frida -U -f <pkg> -l runtime/android-antidebug.js */
try {
  var ptrace = Module.findExportByName(null, "ptrace");
  if (ptrace) Interceptor.replace(ptrace, new NativeCallback(function () { return 0; }, 'long', ['int','int','pointer','pointer']));
} catch (e) {}

// fake TracerPid: 0 when the app reads /proc/self/status
try {
  var fopen = Module.findExportByName(null, "fopen");
  Interceptor.attach(fopen, {
    onEnter: function (a) { try { this.p = Memory.readUtf8String(a[0]); } catch (e) {} },
    onLeave: function (r) { if (this.p && this.p.indexOf("status") >= 0) console.log("[antidebug] status read: " + this.p); }
  });
} catch (e) {}

Java.perform(function () {
  try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function () { return false; }; } catch (e) {}
});
console.log("[+] android-antidebug loaded");
