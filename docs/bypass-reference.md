# Root / Jailbreak / Anti-debug / SSL-Pinning bypass reference

Defensive-research reference for **authorized** mobile assessments. Ready-to-use Frida scripts
derived from this doc live in [`../runtime/`](../runtime/) (see that folder's README).

## Detection layer model

```
Layer 1: Static detection (install-time / startup)
  ├─ package-manager checks (Cydia, apt, Magisk)
  ├─ file checks (su, busybox, frida-server)
  └─ property checks (ro.debuggable, ro.secure)

Layer 2: Runtime detection (continuous)
  ├─ process checks (frida-server, magiskd)
  ├─ port checks (27042 = frida default)
  ├─ memory checks (injection traces in /proc/self/maps)
  └─ backtrace checks (Frida call frames)

Layer 3: Environment detection (on-demand)
  ├─ ptrace check (TracerPid)
  ├─ /proc/self/status check
  ├─ build.prop check (test-keys)
  └─ direct syscall check (bypassing libc)
```

## Android root-detection bypass

| Detection lib | Method | Bypass |
|---|---|---|
| RootBeer | 8 combined checks | hook every check method → return false |
| SafetyNet | Google Play Services remote attestation | Magisk Hide / Shamiko / Play Integrity Fix |
| Google Play Integrity | replaces SafetyNet | Trickystore + PIF |
| custom native check | syscall reads /proc/self/status | hook the syscall or remount /proc |

Combined Frida bypass → [`../runtime/android-root-bypass.js`](../runtime/android-root-bypass.js)
(RootBeer methods, `Build.TAGS`→`release-keys`, hide magisk/frida/xposed packages).

## iOS jailbreak-detection bypass

Multi-layer hooks (see [`../runtime/ios-bypass.js`](../runtime/ios-bypass.js)):
1. **Filesystem** — hook `NSFileManager -fileExistsAtPath:` → NO for `/Applications/Cydia.app`,
   `/var/lib/apt`, `/bin/bash`, `/usr/sbin/sshd`, `/etc/apt`, `/Library/MobileSubstrate`.
2. **fork** (blocked in the sandbox) — `Interceptor.replace(fork)` → return -1.
3. **URL scheme** — hook `LSApplicationWorkspace`/`UIApplication -canOpenURL:` → NO for `cydia://`.
4. **Signature** — `MISValidateSignature` → `onLeave` replace retval with 0.
5. **dyld** — clamp `_dyld_get_image_count` to a sane value.
6. **sysctl** — clear `P_TRACED` in the returned `kinfo_proc.p_flag`.

## Anti-debugging bypass

### Android
- **ptrace(PTRACE_TRACEME)** self-trace → hook `ptrace` → return 0.
- **TracerPid** in `/proc/self/status` → hook `fopen`, fake the `status` content (TracerPid: 0).
- **`Debug.isDebuggerConnected`** (Java) → return false.
See [`../runtime/android-antidebug.js`](../runtime/android-antidebug.js).

### iOS
- **PT_DENY_ATTACH** (`ptrace(31,…)`) → `Interceptor.replace(ptrace)`, ignore request 31.
- **sysctl** → clear `P_TRACED` in `kinfo_proc.p_flag`.
- **getppid** (debugger ⇒ ppid != 1 launchd) → hook to return 1.

## SSL-Pinning bypass

### Android — five layers ([`../runtime/ssl-pinning-universal.js`](../runtime/ssl-pinning-universal.js))
```
Layer 1 — TrustManager: accept all certificates
Layer 2 — OkHttp CertificatePinner: hook → empty the pin list
Layer 3 — WebView SslErrorHandler: ignore certificate errors
Layer 4 — Network Security Config: patch xml → trust user certs
Layer 5 — Native SSL (OpenSSL/BoringSSL): hook SSL_get_verify_result → X509_V_OK
```

### iOS — four layers
```
Layer 1 — NSURLSession: hook SecTrustEvaluate → kSecTrustResultProceed
Layer 2 — Alamofire: hook ServerTrustManager
Layer 3 — AFNetworking: hook AFSecurityPolicy
Layer 4 — libcurl: LD_PRELOAD replace the SSL verify callback
```

### Objection one-liners
```bash
# Android — hooks all 5 layers automatically
objection -g "com.app" explore
android sslpinning disable

# iOS — hooks all 4 layers automatically
objection -g "com.app" explore
ios sslpinning disable
```

_Source: OWASP MASTG (formerly MSTG), Frida CodeShare, objection wiki._
