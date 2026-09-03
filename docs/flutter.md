# Flutter — reverse engineering & traffic interception

Authorized targets only. Detect with `scripts/detect-stack.sh` (`libflutter.so` + `libapp.so`).

## Static
`scripts/analyze-flutter.sh <apk|xapk> out/` → **blutter** decompiles the Dart AOT snapshot
(`libapp.so`) into `blutter_out/` (pseudo-source, class/function names, `blutter_frida.js` for the
exact snapshot). blutter matches the target's Dart runtime version. `reFlutter` is the repackage
companion. Needs the **arm64** `libapp.so` (pass the arm64 split / .xapk).

## TLS interception (three tiers)
Flutter uses its own BoringSSL and **ignores the system proxy**, so browser-style proxying fails.

1. **Standard unpin** — [`../runtime/flutter-tls.js`](../runtime/flutter-tls.js) patches
   `ssl_verify_peer_cert` (NVISO-style pattern scan). Works for many builds.
2. **Proxy redirect (when unpin isn't enough)** —
   [`../runtime/flutter-tls-connect-redirect.js`](../runtime/flutter-tls-connect-redirect.js) hooks
   `connect()`/`send()` to redirect outbound TCP to your proxy and inject an HTTP `CONNECT` so
   mitmproxy (run in **regular mode**) learns the real host. Set `PROXY_HOST`/`PROXY_PORT`.
3. **Binary-patch fallback (when Frida pattern scans fail)** — load `libflutter.so` in Ghidra,
   string-search `ssl_client`, follow XREFs to `ssl_crypto_x509_session_verify_cert_chain`, compute
   the file offset and patch it to return success (or NOP the branch). Then, for ARM targets,
   `reFlutter` repackages the patched `libflutter.so` and re-signs the APK (offline, no runtime Frida).

**⚠ Gotcha:** on an **x86_64 emulator** the arm64 `libflutter.so` runs under
`libndk_translation.so` and is **invisible to Frida** → use a **physical ARM64 device** (or an
arm64 emulator image) for the Frida tiers.

## Root / jailbreak detection
The `flutter_jailbreak_detection` plugin delegates to **RootBeer** (Android) /
**IOSSecuritySuite** (iOS) over a MethodChannel returning `jailbroken`/`developerMode`. Bypass:
- [`../runtime/flutter-jb-root-bypass.js`](../runtime/flutter-jb-root-bypass.js) — neutralise
  RootBeer + force the plugin's `onMethodCall` results to false. (Also load `android-root-bypass.js`.)
- Static: a ~12-line smali patch of the plugin's boolean return, then `scripts/patch-apk.sh build`.

_Sources: HITB blutter (Worawit), randywestergren, m4kr0, appsecwarrior, nikkoenggaliano, rayhanhanaputra._
