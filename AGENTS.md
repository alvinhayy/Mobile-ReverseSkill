# Mobile-ReverseSkill — agent guide (opencode)

Reusable toolkit for **authorized** mobile reverse engineering, dynamic analysis, and fuzzing
(Android + iOS). This file orients the agent; deep docs are in `docs/` and `skills/`.

## Golden rule
Authorized targets only (apps you own / contracted / CTF / OSS). Keep target identity, real
domains, and secrets out of any commit. Dynamic traffic hits your own/local backend, never
third-party production. Fuzzing runs offline (local libs / emulator).

## Capabilities & where they live
- **Static analysis** (`skills/reverse-engineer/`): detect the framework, then run the pipeline.
  - `scripts/detect-stack.sh <apk|ipa|xapk>` → flutter | react-native | unity | xamarin | cordova | native
  - `scripts/analyze-android.sh <apk> [out]` → jadx/apktool/baksmali/dex2jar/dexdump/strings → `<tool>_out/`
  - `scripts/analyze-flutter.sh <apk> [out]` → blutter (Dart AOT) → `blutter_out/`
  - `scripts/analyze-rn.sh <apk> [out]` → Hermes (hermes-dec/hbctool) or JSC → `hermes_out/` / `rndecompiler_out/`
  - `scripts/analyze-ios.sh <ipa> [out]` → plist/entitlements/otool/nm/class-dump/swift-demangle
  - `scripts/install-tools.sh --stack <android|flutter|rn|ios|cross> --check`
- **Dynamic** (`runtime/`): Frida bypass/observe templates (set your own package). Universal:
  `android-root-bypass.js`, `android-antidebug.js`, `ssl-pinning-universal.js`, `ios-bypass.js`.
  Device UI automation via the `uiautomator2` MCP (see `docs/MCP-SETUP.md`).
- **Fuzzing** (`skills/afl-fuzzing/`): on-device AFL++ for Android native libs; host libFuzzer/AFL++
  for open-source libs. **Always validate the harness reaches the target (poison-pointer control)
  before trusting a "0 crashes" result.**
- **Long-running/interactive steps** open in a new terminal tab and mirror to a log you can tail:
  `scripts/run-in-tab.sh <label> "<command>"`.

## Commands (`.opencode/command/`)
`/re-static`, `/detect` (via scripts), `/fuzz-build`, `/fuzz-validate`, `/fuzz-run`,
`/fuzz-source`, `/frida-run`, `/observe-runtime`, `/spawn`, `/setup`, `/root-avd`.

## Method
Detect stack → static (endpoints/secrets/flow, separate real vs honeypot) → set up lab
(`/spawn`, `/setup`) → dynamic/observe (`/observe-runtime`) → fuzz where a parser takes
untrusted input. Reference: `docs/bypass-reference.md`, `docs/frida-objection.md`, `docs/ios-reversing.md`.
