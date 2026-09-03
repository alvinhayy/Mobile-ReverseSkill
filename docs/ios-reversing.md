# iOS reverse engineering

Complements the `reverse-engineer` skill's iOS pipeline (`scripts/analyze-ios.sh`).
Authorized targets only.

## IPA acquisition & decryption
```bash
# App Store
ipatool search "Target App"
ipatool purchase -b com.target.app
ipatool download -b com.target.app -o app.ipa

# extract an installed app (jailbroken device)
scp root@device:/private/var/containers/Bundle/Application/*/Target.app .

# decrypt (App Store binaries are encrypted FAT)
python3 dump.py com.target.app -o decrypted.ipa     # frida-ios-dump (recommended)
Clutch -i ; Clutch -d 1                              # Clutch
DYLD_INSERT_LIBRARIES=dumpdecrypted.dylib /path/to/App   # dumpdecrypted
```

## Mach-O analysis
```bash
otool -l  Target | grep crypt     # encryption status (cryptid)
otool -L  Target                  # dynamic library dependencies
otool -hv Target                  # header info
jtool2 --pages Target             # memory page info

lipo -info Target                 # thin a fat binary
lipo Target -thin arm64 -output Target_arm64

nm -g Target                      # exported symbols
nm -a Target                      # all symbols
swift-demangle <mangled>          # Swift symbol demangling
class-dump -H Target -o headers/  # ObjC class/method declarations
```

## Objective-C runtime analysis
```
Message dispatch:  objc_msgSend(id self, SEL op, ...)  → dynamic method dispatch
Runtime lookup order:
  1. class method cache
  2. class method list
  3. walk up the superclass chain
  4. +resolveInstanceMethod / +resolveClassMethod
  5. forwardingTargetForSelector
  6. methodSignatureForSelector + forwardInvocation
```
```javascript
// hook an instance method (args[0]=self, args[1]=selector, args[2+]=args)
Interceptor.attach(ObjC.classes.ClassName["- instanceMethod:"].implementation, {
  onEnter: function (args) { console.log(new ObjC.Object(args[0]), args[2].toInt32()); }
});
```

## Swift reversing — name mangling
```
$s10ModuleName5ClassC6method3argSi_tF
  │ │          │     │ │     │  │  └ argument types
  │ │          │     │ │     │  └── return type
  │ │          │     │ │     └───── argument name
  │ │          │     │ └─────────── method name
  │ │          │     └───────────── class name (len + name)
  │ │          └─────────────────── module name
  │ └────────────────────────────── identifier marker
  └──────────────────────────────── global marker
Tools: swift-demangle, Hopper (auto).
```

## Jailbreak-detection categories & bypass
1. **Filesystem** (`/Applications/Cydia.app`, `/var/lib/apt/`, `/bin/bash`, `/usr/sbin/sshd`)
   → hook `NSFileManager -fileExistsAtPath:`.
2. **Sandbox-escape** (`fork()` succeeds, `system()`) → hook `fork` → return -1.
3. **dyld injection** (`_dyld_get_image_count` > threshold) → clamp the return value.
4. **URL scheme** (`cydia://`) → hook `UIApplication -canOpenURL:`.
5. **sysctl** (`KERN_PROC` → `kinfo_proc`) → clear `P_TRACED` in `p_flag`.

Unified script: [`../runtime/ios-bypass.js`](../runtime/ios-bypass.js).

## Key protection-bypass checklist
| Protection | iOS bypass |
|---|---|
| App Store encryption | frida-ios-dump / Clutch |
| SSL Pinning | objection `ios sslpinning disable` / SSL Kill Switch 2 |
| Jailbreak detection | objection `ios jailbreak disable` / custom Frida hook |
| Anti-debug (PT_DENY_ATTACH) | inject Frida after launch / debugserver |
| Integrity check | hook the MAC/code-signature verification |
| Anti-injection | strip the `__RESTRICT` segment from the Mach-O |
| Swift obfuscation | swift-demangle + LLM-assisted semantic recovery |
| Screenshot protection | hook `UIScreen.mainScreen snapshotViewAfterScreenUpdates:` |

_Source: OWASP MASTG, frida-ios-dump, The iPhone Wiki._
