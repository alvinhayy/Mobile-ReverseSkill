# Roadmap / backlog

Gap analysis from a 2-agent deep research pass (2026-09-03) over ~40 mobile-RE sources
(OWASP MASTG-adjacent blogs, cheatsheets, HITB talks, Frida/Objection/Flutter/iOS write-ups),
checked against the live repo. Legend: ☐ todo · ◐ in progress · ☑ done.

## Priority additions (P1 highest value)

| P | Item | Artifact(s) | Why | Status |
|---|---|---|---|---|
| 1 | **React Native dynamic instrumentation** | `runtime/rn-frida-hook.js` + `docs/react-native.md` | Biggest hole — repo had RN *static* only. Hooks RN network (OkHttp), JS↔native bridge, AsyncStorage, bundle load; + remote-debug/dev-mode workflow. | ☑ |
| 2 | **Merge split APKs (XAPK/APKS → 1 APK)** | `scripts/merge-apks.sh` (APKEditor) + `/merge-apks` | Prerequisite for patching / reFlutter / apk-mitm. The repo's own targets are split; without a merge you hit "App not installed". | ☑ |
| 3 | **Static patch-and-resign** | `scripts/patch-apk.sh` + `/patch-apk` | Repo was 100% dynamic. Fallback when RASP kills Frida: smali `isRooted→false` / null pinning → `apktool b` → `apksigner` → install. Also `depin` (apk-mitm), RN dev-mode flip. | ☑ |
| 4 | **Non-jailbroken iOS pipeline** | `docs/ios-nojailbreak.md` | decrypt → **ios-app-signer (keep get-task-allow)** / FridaGadget embed → Sideloadly/AltStore/`ideviceinstaller` → `objection explore` on stock device; static-patch alt. | ☑ |
| 5 | **Advanced Flutter TLS (when standard scripts fail)** | `runtime/flutter-tls-connect-redirect.js` + `docs/flutter.md` | connect()/send() redirect + CONNECT inject; Ghidra `ssl_..._verify_cert_chain` patch; physical-ARM64 gotcha. Serves the repo's Flutter targets. | ☑ |
| 6 | **App-layer crypto hooking** | `runtime/crypto-dump.js` | Hooks `SecretKeySpec`/`IvParameterSpec`/`Cipher`/`Mac`/`MessageDigest` → dumps keys/IVs + in/out to recover payload plaintext behind TLS. | ☑ |
| 7 | **Commercial-protector bypass (Appdome, …)** | `docs/commercial-protectors.md` + `runtime/registernatives-dump.js` | RegisterNatives enumeration → Ghidra offsets → hook/patch; Appdome threat-check map + StrongR-Frida note. | ☑ |
| 8 | **Attack-surface / IPC testing** | `scripts/attack-surface.sh` + `docs/attack-surface.md` | Enumerate exported components / deep links / providers + risky flags (tested on AndroGoat); drozer + `am`/`content` probing + loot checklist. | ☑ |
| 9 | **iOS toolchain + device automation** | `docs/TOOLING.md` (iOS lab section) | Added libimobiledevice/ideviceinstaller/ios-deploy/ipatool/ios-app-signer/Sideloadly/AltStore + **ioscpy** (iOS analog to uiautomator2). | ☑ |
| 10 | **Flutter root/JB-detection bypass** | `runtime/flutter-jb-root-bypass.js` | `flutter_jailbreak_detection` delegates to RootBeer / IOSSecuritySuite over a **MethodChannel** — neutralise RootBeer + force onMethodCall false, or smali patch. | ☑ |

## Quick wins (docs / high ROI)

| Item | Where | Status |
|---|---|---|
| `apk-mitm` wrapper (one-command auto de-pin) | command/doc | ☐ |
| **RMS (Runtime Mobile Security)** — Frida GUI for mass-hook/enumerate | note in `docs/frida-objection.md` | ☐ |
| Frida/Objection **version-hell** troubleshooting (frida-server↔frida-tools match, rebuild `frida-java-bridge`) | box in `docs/frida-objection.md` | ☐ |
| Burp CA via **Magisk conscrypt-APEX module** (rootAVD/x86_64 users) | `docs/MCP-SETUP.md` | ☐ |
| **RN remote-debug / dev-mode** (`__DEV__`, `getUseDeveloperSupport`, Metro + Chrome DevTools, live reload) | `docs/react-native.md` | ☐ |
| iOS **static binary-patch + re-sign** (Hopper/Ghidra NOP-return → export → re-sign) | `docs/ios-nojailbreak.md` | ☑ |
| **MASTG** methodology checklist | `docs/WORKFLOW.md` | ☐ |
| Flutter **manual-offset unpin fallback** (Ghidra locate `ssl_..._verify_cert_chain`) | `docs/flutter.md` (tier 3) | ☑ |

## Deliberately skipped (low value for mobile RE)
odin.io (OSINT/recon, not IPA/device analysis) · Zebra KB 000029517 (login portal / niche enterprise) ·
HITB B(l)utter talks (already covered by `analyze-flutter`) · BeDefended (beyond the MASTG checklist) ·
noise links (a Google search, a YouTube video, a Notion page, a Google-Drive file, a personal agent URL).

## Sources (representative)
tanprathan & nobox910 cheatsheets, payatu attack-surface, securitycafe RMS, suryadina crypto,
pilfer/laripping/bedefended RN, isec.pl/devilslane/nowsecure/dghostninja root+SSL, AntiSplit-M,
0xn3va & litesec (iOS no-JB), ioscpy, randywestergren & m4kr0 & appsecwarrior (Flutter TLS),
farimarwat (Appdome), HITB blutter/Flutter-vuln, apk-mitm, fox-it conscrypt module, sensepost/objection#800.
