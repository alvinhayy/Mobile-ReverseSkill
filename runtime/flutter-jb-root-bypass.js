/* flutter-jb-root-bypass.js — defeat the flutter_jailbreak_detection plugin.
 * The plugin delegates to RootBeer (Android) / IOSSecuritySuite (iOS) over a MethodChannel and
 * returns booleans (jailbroken, developerMode). Force those to false at the channel/native gap.
 *   frida -U -f <pkg> -l runtime/flutter-jb-root-bypass.js  (Android; add android-root-bypass.js too)
 * (technique: rayhanhanaputra / CyberCX)  */
Java.perform(function () {
  // A) neutralise RootBeer (the plugin's Android backend)
  try {
    var RB = Java.use("com.scottyab.rootbeer.RootBeer");
    RB.class.getDeclaredMethods().forEach(function (m) {
      var n = m.getName();
      try { RB[n].overloads.forEach(function (ov) {
        if (ov.returnType && ov.returnType.className === 'boolean') ov.implementation = function () { return false; };
      }); } catch (e) {}
    });
    console.log("[flutter-jb] RootBeer neutralised");
  } catch (e) {}

  // B) force the plugin's MethodChannel results to false (jailbroken/developerMode)
  ["com.example.flutter_jailbreak_detection.FlutterJailbreakDetectionPlugin",
   "com.flutterjailbreakdetection.FlutterJailbreakDetectionPlugin"].forEach(function (cls) {
    try {
      var P = Java.use(cls);
      P.onMethodCall.implementation = function (call, result) {
        try { console.log("[flutter-jb] " + call.method.value + " -> false"); } catch (e) {}
        result.success(false); return;
      };
      console.log("[flutter-jb] hooked " + cls + ".onMethodCall");
    } catch (e) {}
  });
  console.log("[+] flutter-jb-root-bypass loaded");
});
