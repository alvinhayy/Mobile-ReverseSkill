# Tooling matrix

Static-analysis + decompiler toolchain per stack. Install with
`scripts/install-tools.sh --stack <name>` (or `--check` to audit). Build order:
**Android → Flutter → RN → iOS** (+ cross disassemblers).

## Output convention — `<tool>_out/`

Every tool that produces output writes to a folder named after it, suffix `_out`:

```
out/
  apktool_out/    jadx_out/    dex2jar_out/    baksmali_out/    dexdump_out/
  strings_out/    apkleaks_out/    detect.txt    MANIFEST.txt
```

`*_out/` holds **decompiled target code** — it is git-ignored and must never be committed.

## Status

| Stack | Status | Pipeline |
|---|---|---|
| Android | done (stage 1) | `scripts/analyze-android.sh` |
| Flutter | done (stage 2) | `scripts/analyze-flutter.sh` |
| React Native | done (stage 3) | `scripts/analyze-rn.sh` |
| iOS | done (stage 4) | `scripts/analyze-ios.sh` |

---

## Android (stage 1)

| Tool | Install (macOS) | Role | `_out` |
|---|---|---|---|
| **jadx** | `brew install jadx` | DEX -> Java sources | `jadx_out/` |
| **apktool** | `brew install apktool` | smali + resources + `AndroidManifest.xml` | `apktool_out/` |
| **baksmali** | `brew install smali` | DEX -> smali (per dex) | `baksmali_out/` |
| **dex2jar** | `brew install dex2jar` | DEX -> JAR (`d2j-dex2jar`) | `dex2jar_out/` |
| **dexdump** | Android build-tools | method/proto dump | `dexdump_out/` |
| **apkleaks** | `pip install apkleaks` (opt) | secrets/endpoints regex | `apkleaks_out/` |
| `strings` | bundled | URLs from dex + `.so` | `strings_out/` |

Run:
```bash
scripts/install-tools.sh --stack android --check     # audit
scripts/analyze-android.sh app.apk out/app           # -> out/app/<tool>_out/
```

Notes:
- Flutter apps keep logic in `libapp.so` (Dart AOT); most classes are absent from
  `classes.dex` -- jadx/smali output is thin, routing to the Flutter pipeline (stage 2).
- `dexdump` ships with Android build-tools: `sdkmanager 'build-tools;<ver>'`.

## Flutter (stage 2)

Flutter logic is a **Dart AOT snapshot** in `libapp.so` (paired with `libflutter.so`),
usually in the **arm64 split** / `.xapk`, not the base APK.

| Tool | Install (macOS) | Role | `_out` |
|---|---|---|---|
| **blutter** | `git clone worawit/blutter` + `brew install cmake ninja` | Dart AOT snapshot -> pseudo-source, class defs, `blutter_frida.js` | `blutter_out/` |
| **reFlutter** | `pip install reflutter` | patch/repack APK for traffic interception + snapshot dump (dynamic) | `reflutter_out/` (manual) |
| `unzip` | bundled | pull `assets/flutter_assets/` (pubspec, fonts) | `assets_out/` |

Run:
```bash
scripts/install-tools.sh --stack flutter --check     # audit (blutter, reflutter, cmake, ninja)
export BLUTTER_HOME="$HOME/tools/blutter"            # where blutter.py lives
scripts/analyze-flutter.sh app.xapk out/app          # -> out/app/blutter_out/, assets_out/
```

Notes:
- `blutter_out/` contains `asm/` (per-library Dart pseudo-source), `objs.txt`, `pp.txt`, and
  `blutter_frida.js` (a ready hook script for the exact snapshot).
- **First run builds blutter's Dart VM** for the target's snapshot version (needs `cmake`+`ninja`);
  subsequent runs on the same version are fast.
- blutter works on **arm64** `libapp.so`; pass the arm64 split or the `.xapk`.
- reFlutter is the *dynamic* companion (repackage + resign + install) — run it manually.

## React Native (stage 3)

The app logic is a JS bundle at `assets/index.android.bundle`. Two engines:
**Hermes** (compiled bytecode — `libhermes.so` present, magic `c6 1f bc 03`) or
**JSC** (minified JS text).

| Tool | Install (macOS) | Role | `_out` |
|---|---|---|---|
| **hermes-dec** | `pip install hermes-dec` | Hermes bytecode -> disasm (`hbc-disassembler`) + pseudo-JS (`hbc-decompiler`) | `hermes_out/` |
| **hbctool** | `pip install hbctool` | Hermes disasm/asm for patching (**version-locked** to the HBC version) | `hbctool_out/` |
| **react-native-decompiler** | `npm i -g react-native-decompiler` | JSC/plain bundle -> recovered modules | `rndecompiler_out/` |
| **js-beautify** | `npm i -g js-beautify` | prettify a minified JSC bundle | `jsbeautify_out/` |

Run:
```bash
scripts/install-tools.sh --stack rn --check
scripts/analyze-rn.sh app.apk out/app     # auto-detects Hermes vs JSC and routes
```

Notes:
- **Hermes** is now the RN default. `hbctool` is picky: its disassembler is pinned to specific
  Hermes bytecode versions — if it errors, install the `hbctool` build matching the target's HBC
  version; `hermes-dec` is more version-tolerant.
- **JSC** bundles are just (minified) JS — `react-native-decompiler` un-webpacks modules;
  `js-beautify` is the quick fallback.

## iOS (stage 4)

Unpack the `.ipa` (`Payload/<App>.app`), read `Info.plist` + entitlements, and analyze the
Mach-O. **App Store binaries are FairPlay-encrypted** (`cryptid=1`) — `class-dump`/`nm` return
garbage until you decrypt on a jailbroken device (`frida-ios-dump` / `bagbak`).

| Tool | Install (macOS) | Role | `_out` |
|---|---|---|---|
| **class-dump** | `brew install class-dump` | ObjC interface headers from Mach-O | `classdump_out/` |
| **otool** | Xcode CLT (`xcode-select --install`) | arch, linked libs, load commands, encryption check | `otool_out/` |
| **nm** | Xcode CLT | symbol table | `nm_out/` |
| **swift-demangle** | Xcode (`xcrun swift-demangle`) | demangle Swift symbols from `nm` | `swiftdemangle_out/` |
| **plutil** | bundled | `Info.plist` -> JSON (URL schemes, ATS) | `plist_out/` |
| **codesign** | Xcode CLT | entitlements + signing info | `codesign_out/` |

Run:
```bash
scripts/install-tools.sh --stack ios --check
scripts/analyze-ios.sh app.ipa out/app
```

Notes:
- The script prints `cryptid=` from `LC_ENCRYPTION_INFO`; if non-zero, decrypt first.
- **class-dump** covers ObjC only; for Swift use `swift-demangle` over `nm` output, or a
  decompiler (Ghidra / Hopper / IDA — see cross table).

## iOS lab & device tooling (non-jailbreak)

| Tool | Install | Use |
|---|---|---|
| **libimobiledevice** | `brew install libimobiledevice` | `idevice*` — device info, syslog, pair |
| **ideviceinstaller** | `brew install ideviceinstaller` | install/list/uninstall apps over USB |
| **ios-deploy** | `brew install ios-deploy` | install + debug an app bundle |
| **ipatool** | `brew install ipatool` | download IPAs from the App Store |
| **ios-app-signer** | GUI (github.com/DanTheMan827/ios-app-signer) | re-sign IPA; **uncheck "No get-task-allow"** for Frida attach |
| **Sideloadly / AltStore** | sideloadly.io / altstore.io | sideload re-signed IPA with a free Apple cert (AltStore auto-refreshes) |
| **frida-ios-dump** | pip / repo | decrypt an installed App Store binary (needs a JB device once) |
| **ioscpy** | github.com/lautarovculic/ioscpy | scrcpy-for-iOS — mirror/control a **jailbroken** iPhone (the iOS analog to the Android uiautomator2 MCP) |

See [`ios-nojailbreak.md`](ios-nojailbreak.md) for the full re-sign + sideload workflow.

## Cross disassemblers (any stack)

| Tool | Install | Use |
|---|---|---|
| **Ghidra** | `brew install --cask ghidra` | decompile `.so` / Mach-O / `.dylib`; headless-scriptable |
| **radare2** | `brew install radare2` | CLI disasm + `r2frida` |
| **rizin** | `brew install rizin` | radare2 fork (optional) |
| **IDA** | commercial | premium disasm (optional) |
| **Hopper** | `brew install --cask hopper-disassembler` | macOS/iOS disasm (iOS work) |
