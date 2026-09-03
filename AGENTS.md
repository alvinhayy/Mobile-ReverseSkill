# Mobile-ReverseSkill — agent guide (opencode)

Reusable toolkit for **authorized** mobile reverse engineering, dynamic analysis, and fuzzing
(Android + iOS). This file orients the agent; deep docs are in `docs/`, skills in `skills/`,
backlog/roadmap in `docs/ROADMAP.md`.

## Golden rule
Authorized targets only (apps you own / contracted / CTF / OSS). Keep target identity, real
domains, and secrets out of any commit. Dynamic traffic hits your own/local backend, never
third-party production. Fuzzing runs offline (local libs / emulator).

## Static analysis (`skills/reverse-engineer/`, `scripts/`)
- `scripts/detect-stack.sh <apk|ipa|xapk>` → flutter | react-native | unity | xamarin | cordova | native
- `scripts/analyze-android.sh` (jadx/apktool/baksmali/dex2jar/dexdump/strings/apkleaks) → `<tool>_out/`
- `scripts/analyze-flutter.sh` (blutter, reFlutter) · `scripts/analyze-rn.sh` (Hermes/JSC) · `scripts/analyze-ios.sh`
- `scripts/attack-surface.sh <apk>` → exported components, deep links, providers, risky flags (+ `am start` line)
- `scripts/install-tools.sh --stack <android|flutter|rn|ios|cross> --check`

## APK handling (`scripts/`)
- `scripts/merge-apks.sh <dir|xapk|apks|apkm>` → one signed APK (APKEditor) — do this before patching split apps
- `scripts/patch-apk.sh decompile|build|sign|depin|find-root|install` → static patch & re-sign (Frida-independent)

## Dynamic — Frida (`runtime/`) — set your own target package
- SSL/pinning: `ssl-pinning-universal.js` (Android 5-layer), `ios-bypass.js` (iOS), `flutter-tls*.js`,
  **`flutter-tls-connect-redirect.js`** (Dart proxy redirect + CONNECT inject)
- Root/JB/anti-debug: `android-root-bypass.js` (RootBeer), `android-antidebug.js`, `ios-bypass.js`,
  **`flutter-jb-root-bypass.js`**, `emu-bypass.js`, `*-spoof.js`
- Recon/dump: **`rn-frida-hook.js`** (RN network/bridge/AsyncStorage/bundle), **`crypto-dump.js`**
  (keys/IV + Cipher/Mac I/O), **`registernatives-dump.js`** (JNI → native offsets, e.g. Appdome `libloader.so`)
- Device UI automation via the `uiautomator2` MCP (`docs/MCP-SETUP.md`); camoufox MCP for stealth web.

## Fuzzing (`skills/afl-fuzzing/`, `scripts/`)
- `afl-fuzzing` — on-device AFL++ for Android native libs (**always validate the harness reaches the
  target via a poison-pointer control before trusting "0 crashes"**).
- `/fuzz-source` — host libFuzzer/AFL++ for open-source C/C++ libs.

## Interactive/long-running steps → new tab (monitorable)
`scripts/run-in-tab.sh <label> "<command>"` opens it in a new terminal tab (frida REPL, emulator
boot, frida-server, AFL TUI) and mirrors to `~/.mre-runs/<label>-*.log` for the agent to tail.

## Commands (`.opencode/command/`)
`/re-static`, `/merge-apks`, `/patch-apk`, `/frida-run`,
`/observe-runtime`, `/fuzz-build`, `/fuzz-validate`, `/fuzz-run`, `/fuzz-source`, `/spawn`, `/setup`, `/root-avd`.

## Method
detect stack → static (endpoints/secrets/flow + `attack-surface.sh`) → lab (`/spawn`,`/setup`) →
dynamic/observe (`/observe-runtime`, Frida) → fuzz parsers of untrusted input. Follow the MASTG
checklist in `docs/WORKFLOW.md`.

## Reference docs
`docs/`: TOOLING, bypass-reference, frida-objection, ios-reversing, ios-nojailbreak, react-native,
flutter, attack-surface, commercial-protectors, MCP-SETUP, WORKFLOW, ROADMAP.
