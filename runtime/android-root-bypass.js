/* android-root-bypass.js — neutralise RootBeer + Build.TAGS + package-hide + isDebuggerConnected.
 * frida -U -f <pkg> -l runtime/android-root-bypass.js   (authorized targets only)
 * Hooks every RootBeer boolean check -> false, retrying until the class is loaded (it is often
 * loaded after spawn), so it works even when attached at process start. */
Java.perform(function () {
  var METHODS = [
    "isRooted","isRootedWithBusyBox","isRootedWithEmulatorCheck",
    "detectRootManagementApps","detectPotentiallyDangerousApps","detectRootCloakingApps",
    "detectTestKeys","checkForBusyBoxBinary","checkForSuBinary","checkSuExists",
    "checkForRWPaths","checkForDangerousProps","checkForRootNative","checkForMagiskBinary",
    "checkForBinary","isSelinuxFlagInEnabled"
  ];
  function hookRootBeer() {
    var RB;
    try { RB = Java.use("com.scottyab.rootbeer.RootBeer"); } catch (e) { return false; }
    var n = 0;
    METHODS.forEach(function (m) {
      if (!RB[m]) return;
      try {
        RB[m].overloads.forEach(function (ov) {
          ov.implementation = function () { return false; };
        });
        n++;
      } catch (e) {}
    });
    console.log("[+] RootBeer neutralised (" + n + " methods)");
    return true;
  }
  if (!hookRootBeer()) {                       // class not loaded yet at spawn → retry
    var tries = 0;
    var t = setInterval(function () {
      if (hookRootBeer() || ++tries > 100) clearInterval(t);
    }, 200);
  }

  try { Java.use("android.os.Build").TAGS.value = "release-keys"; } catch (e) {}
  try {
    var PM = Java.use("android.content.pm.PackageManager");
    var NNF = Java.use("android.content.pm.PackageManager$NameNotFoundException");
    PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
      if (pkg && (pkg.indexOf("magisk") >= 0 || pkg.indexOf("frida") >= 0 ||
                  pkg === "de.robv.android.xposed.installer")) throw NNF.$new();
      return this.getPackageInfo(pkg, flags);
    };
  } catch (e) {}
  try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function () { return false; }; } catch (e) {}
  console.log("[+] android-root-bypass loaded");
});
