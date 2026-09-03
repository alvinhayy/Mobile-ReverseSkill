---
description: Merge split APKs / XAPK / APKS / APKM into one installable, signed APK (APKEditor)
argument-hint: "<dir|xapk|apks|apkm> [out.apk]"
allowed-tools: Bash(java:*), Bash(*apksigner*), Bash(adb:*), Bash(curl:*)
---

Merge a split app into a single installable APK so patching / reFlutter / apk-mitm work:
```bash
scripts/merge-apks.sh $ARGUMENTS      # downloads APKEditor on first run, merges + signs
```
Then `scripts/patch-apk.sh install <out.apk>`. Needed because most tooling can't operate on
split/XAPK bundles ("App not installed"). Authorized targets only.
