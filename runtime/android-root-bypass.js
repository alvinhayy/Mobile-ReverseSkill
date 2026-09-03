/* android-root-bypass.js — RootBeer + Build.TAGS + package-hide + isDebuggerConnected.
 * frida -U -f <pkg> -l runtime/android-root-bypass.js   (authorized targets only) */
Java.perform(function () {
  // RootBeer — force every check to false
  try {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    ["isRooted","isRootedWithBusyBox","checkSuExists","detectRootManagementApps",
     "detectPotentiallyDangerousApps","detectTestKeys","checkForDangerousProps",
     "checkForRWPaths"].forEach(function (m) {
      if (RootBeer[m]) RootBeer[m].implementation = function () { return false; };
    });
    console.log("[+] RootBeer neutralised");
  } catch (e) {}

  // Build.TAGS → release-keys
  try { Java.use("android.os.Build").TAGS.value = "release-keys"; } catch (e) {}

  // hide magisk / frida / xposed from PackageManager
  try {
    var PM = Java.use("android.content.pm.PackageManager");
    var NNF = Java.use("android.content.pm.PackageManager$NameNotFoundException");
    PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
      if (pkg && (pkg.indexOf("magisk") >= 0 || pkg.indexOf("frida") >= 0 ||
                  pkg === "de.robv.android.xposed.installer")) throw NNF.$new();
      return this.getPackageInfo(pkg, flags);
    };
  } catch (e) {}

  // Debug.isDebuggerConnected → false
  try { Java.use("android.os.Debug").isDebuggerConnected.implementation = function () { return false; }; } catch (e) {}
  console.log("[+] android-root-bypass loaded");
});
