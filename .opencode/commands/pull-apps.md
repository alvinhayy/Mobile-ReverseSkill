---
description: Pull an app (base APK + all splits) from a connected device/AVD via adb — resolves pm path, handles work profiles, merges split apps into one signed APK
argument-hint: <package-name>
---

Pull the app from the attached device/AVD into `targets/`: `$ARGUMENTS`

Steps:
1. Resolve every APK path (base + splits):
   `adb shell pm path $ARGUMENTS` → lines like `package:/data/app/.../base.apk`,
   `.../split_config.arm64_v8a.apk`, …
   Not found? It may live in a work profile / secondary user — `adb shell pm list users`,
   then retry `adb shell pm path --user 10 $ARGUMENTS` and add `--user 10` to the pull.
   Unsure of the exact package name: `adb shell pm list packages -3 | grep <keyword>`.
2. Pull each path (strip the `package:` prefix): `adb pull <path> targets/$ARGUMENTS/`.
3. Multiple splits → merge into one installable signed APK:
   `scripts/merge-apks.sh targets/$ARGUMENTS` (APKEditor) → `targets/$ARGUMENTS/merged-signed.apk`.
   Single `base.apk` → use it directly.
4. Triage what was pulled: `scripts/detect-stack.sh targets/$ARGUMENTS/*.apk` (flutter | rn | native →
   picks the right analysis pipeline).
5. Suggest next steps: `/re-static` (endpoints/secrets/deception), `/vuln-hunt` (vuln classes),
   `/patch-apk` (decompile → patch → re-sign).

Authorized targets only — pull apps you own or are contracted to test. Pulled APKs stay under
`targets/` (git-ignored); never commit them.
