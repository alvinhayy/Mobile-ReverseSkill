# Frida + Objection — deep usage

For **authorized** dynamic analysis only. Ready-made bypass scripts: [`../runtime/`](../runtime/).

## Frida core API

### Java runtime (Android)
```javascript
Java.perform(function () {
  // hook a static method
  var System = Java.use("java.lang.System");
  System.getProperty.overload('java.lang.String').implementation = function (key) {
    console.log("System.getProperty: " + key);
    return this.getProperty(key);
  };

  // hook a constructor
  var File = Java.use("java.io.File");
  File.$init.overload('java.lang.String').implementation = function (path) {
    console.log("File opened: " + path);
    return this.$init(path);
  };

  // enumerate loaded classes
  Java.enumerateLoadedClasses({ onMatch: function (n) { console.log(n); }, onComplete: function () {} });

  // change a return value
  var RootDetector = Java.use("com.app.security.RootDetector");
  RootDetector.isDeviceRooted.implementation = function () { return false; };
});
```

### Native layer (Android + iOS)
```javascript
// hook an exported function
Interceptor.attach(Module.findExportByName(null, "open"), {
  onEnter: function (args) { this.path = Memory.readUtf8String(args[0]); },
  onLeave: function (retval) { console.log("open(" + this.path + ") = " + retval); }
});

// hook an arbitrary address (by offset)
var base = Module.findBaseAddress("libnative.so");
Interceptor.attach(base.add(0x12345), {
  onEnter: function () {
    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
  }
});

// force strcmp to match
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
  onLeave: function (retval) { if (retval.toInt32() !== 0) retval.replace(0); }
});
```

### ObjC runtime (iOS)
```javascript
Interceptor.attach(ObjC.classes.ViewController["- viewDidLoad"].implementation, {
  onEnter: function () { console.log("viewDidLoad called"); }
});
ObjC.enumerateLoadedClasses({ onMatch: function (n) { console.log(n); }, onComplete: function () {} });
var NSString = ObjC.classes.NSString;
var str = NSString.stringWithString_("Hello from Frida");
```

## Objection command quick reference

### Common
```bash
objection -g "com.app" explore            # start
objection -g "com.app" explore -q         # quiet (inject only)
objection patchapk --source app.apk       # auto-inject Frida Gadget
objection signapk --source app.apk        # sign only
env                                        # app data dir
ls ; file download /path ; file upload local.txt /remote
sqlite connect /path/db.sqlite ; .tables ; select * from users;
```

### Android-specific
```bash
android root disable
android sslpinning disable
android hooking list classes
android hooking list class_methods com.app.Main
android hooking watch class com.app.Main
android intent launch_activity com.app.MainActivity
android heap search instances com.app.User
android keystore list
```

### iOS-specific
```bash
ios jailbreak disable
ios sslpinning disable
ios keychain dump
ios nsuserdefaults get
ios nsurlcache dump
ios cookies get
ios pasteboard monitor
ios ui dump
ios plist cat Info.plist
```

## Root-free / jailbreak-free deployment (Frida Gadget)

### Android
```bash
apktool d app.apk -o app_unpacked
cp frida-gadget-<ver>-android-arm64.so app_unpacked/lib/arm64-v8a/libfrida-gadget.so
# inject System.loadLibrary("frida-gadget") into the main Activity onCreate/attachBaseContext (smali)
apktool b app_unpacked -o app_patched.apk && uber-apk-signer -a app_patched.apk
# or automated:
objection patchapk --source app.apk --skip-resources
```

### iOS
```bash
python3 frida-ios-dump.py -u -p com.app.target          # decrypt App Store IPA
# add @executable_path/FridaGadget.dylib to the Mach-O load commands
codesign -f -s "Apple Development" Payload/App.app        # re-sign
# install via Xcode sideload or AltStore
```

## SSL-Pinning bypass (advanced snippets)

### Android
```javascript
Java.use("okhttp3.CertificatePinner").check.overload('java.lang.String','java.util.List').implementation = function(){};
Java.use("com.android.org.conscrypt.TrustManagerImpl").verifyChain.implementation = function(){ return []; };
Java.use("android.webkit.SslErrorHandler").proceed.implementation = function(){ return this.proceed(); };
// Network Security Config: patch AndroidManifest → networkSecurityConfig → trust user certs
```

### iOS
```javascript
var f = Module.findExportByName("Security", "SecTrustEvaluate");
Interceptor.replace(f, new NativeCallback(function (trust, result) {
  Memory.writeU32(result, 1); // kSecTrustResultProceed
  return 0;                    // errSecSuccess
}, 'int', ['pointer','pointer']));
// Alamofire: hook ServerTrustManager.evaluate → always success
```

_Source: Frida docs, objection wiki, OWASP MASTG._

## RMS — Runtime Mobile Security (Frida GUI)
A web GUI over Frida for fast triage: dump/enumerate loaded classes, **mass-hook every method of a
filtered class**, live API monitor, and prebuilt bypasses (`system_exit_bypass`, root/SSL).
```bash
pip install rms-runtime-mobile-security   # or: git clone Merabtene/RMS-Runtime-Mobile-Security
rms   # opens http://127.0.0.1:5000 ; select the app, then Hook/monitor
```
Great for discovering which classes/methods to target before writing a focused Frida script.
Codeshare quick-bypasses: `frida --codeshare dzonerzy/fridantiroot`,
`frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida`.

## Frida / Objection "version hell" (most common attach failure)
- **frida-server on device MUST match host `frida` exactly** (major.minor.patch). Check
  `frida --version` vs the server (or the KSU module's `module.prop`); align with
  `pip install "frida==<server-version>"`.
- If a KSU/Magisk **module already runs a server** (e.g. `cekidot`), use it — match the client to
  it instead of fighting it.
- Objection failing on new Android/ART = its bundled `frida-java-bridge` is stale →
  `cd $(objection ...)/node_modules && npm i frida-java-bridge@latest` (see sensepost/objection#800),
  or use plain Frida scripts.
- `pkill -f frida` also kills the MCP/agent node process (argv contains "frida"); target the binary
  (`pkill -x frida-server`).
