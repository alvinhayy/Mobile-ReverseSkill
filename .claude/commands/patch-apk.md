---
description: Statically patch, rebuild, re-sign, and install an APK (Frida-independent bypass fallback)
argument-hint: "<apk>  (or a subcommand: decompile|build|sign|depin|find-root|install)"
allowed-tools: Bash(apktool:*), Bash(*apksigner*), Bash(*zipalign*), Bash(adb:*), Bash(npx:*)
---

Statically patch an APK when RASP defeats Frida. Target: `$ARGUMENTS`. Use `scripts/patch-apk.sh`.

Typical flow:
1. `scripts/patch-apk.sh decompile <apk>` → smali in `<apk>-src/`.
2. `scripts/patch-apk.sh find-root <apk>-src` → find `isRooted`/`CertificatePinner`/JB checks.
3. Edit smali: force boolean checks false (`const/4 v0, 0x0` then `return v0`), null the OkHttp
   `CertificatePinner`, or add an all-trusting TrustManager; for RN dev-mode flip
   `getUseDeveloperSupport()` → `0x1`.
4. `scripts/patch-apk.sh build <apk>-src out.apk` → apktool b + zipalign + sign (debug keystore).
5. `scripts/patch-apk.sh install out.apk`.

Fast path: `scripts/patch-apk.sh depin <apk>` (apk-mitm auto de-pin + resign). If the input is a
split/XAPK, run `scripts/merge-apks.sh` first. Authorized targets only.
