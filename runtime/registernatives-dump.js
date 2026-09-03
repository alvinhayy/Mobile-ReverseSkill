/* registernatives-dump.js — log every JNI RegisterNatives call (name, signature, native address).
 * frida -U -f <pkg> -l runtime/registernatives-dump.js
 * Reveals where Java bridges bind into native detection libs (e.g. Appdome's libloader.so),
 * so you can open the exact offset in Ghidra and patch/hook the detection routine.
 * (technique: farimarwat / Appdome analysis)  */
function hookRN() {
  var libart = Process.findModuleByName("libart.so"); if (!libart) return false;
  var cand = libart.enumerateSymbols().filter(function (s) {
    return s.name.indexOf("RegisterNatives") >= 0 && s.name.indexOf("CheckJNI") < 0 && s.name.indexOf("Runtime") < 0;
  });
  if (!cand.length) cand = libart.enumerateExports().filter(function (s) { return s.name.indexOf("RegisterNatives") >= 0; });
  if (!cand.length) return false;
  var PS = Process.pointerSize;
  cand.forEach(function (sym) {
    try {
      Interceptor.attach(sym.address, {
        onEnter: function (args) {
          var methods = args[2], count = args[3].toInt32();
          for (var i = 0; i < count; i++) {
            var m = methods.add(i * PS * 3);
            var name = m.readPointer().readCString();
            var sig = m.add(PS).readPointer().readCString();
            var fn = m.add(PS * 2).readPointer();
            var mod = Process.findModuleByAddress(fn);
            var where = mod ? (mod.name + "+0x" + fn.sub(mod.base).toString(16)) : fn.toString();
            console.log("[RegisterNatives] " + name + " " + sig + "  ->  " + where);
          }
        }
      });
      console.log("[+] hooked " + sym.name);
    } catch (e) {}
  });
  return true;
}
if (!hookRN()) { var t = setInterval(function(){ if (hookRN()) clearInterval(t); }, 300); }
