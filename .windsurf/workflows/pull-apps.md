---
description: Acquire an Android app (base APK + splits) or an iOS IPA from an authorized connected device
argument-hint: <package-name|bundle-id> [output.ipa]
---

Acquire the authorized app identified by `$ARGUMENTS` into `targets/`.

First determine the platform without guessing:

1. Parse the first argument as the Android package name or iOS bundle ID. An optional second
   argument is the iOS output filename.
2. Check connected Android devices with `adb devices` and test the identifier with
   `adb shell pm path <identifier>`.
3. On macOS, check the iOS path with `command -v ios-ipa-extractor` and a trusted, unlocked
   USB-connected iPhone/iPad. If both platforms match or neither can be established, ask which
   platform to use before acquiring anything.

## Android — pull installed APKs

1. Resolve every APK path (base + splits):
   `adb shell pm path <package>` → lines like `package:/data/app/.../base.apk`,
   `.../split_config.arm64_v8a.apk`, …
   Not found? It may live in a work profile / secondary user — `adb shell pm list users`,
   then retry `adb shell pm path --user 10 <package>` and use that user consistently.
   Unsure of the exact package name: `adb shell pm list packages -3 | rg <keyword>`.
2. Create `targets/<package>/`, strip each `package:` prefix, and `adb pull` every resolved path
   into that directory.
3. Multiple splits → merge into one installable signed APK:
   `scripts/merge-apks.sh targets/<package>` (APKEditor) →
   `targets/<package>/merged-signed.apk`. Single `base.apk` → use it directly.
4. Validate and triage the result with `unzip -tqq <apk>` and
   `scripts/detect-stack.sh <apk>`.

## iOS — resolve on device, download from Apple

Use [`ios-ipa-extractor`](https://github.com/iw00tr00t/ios-ipa-extractor) for a non-jailbroken
iOS device. It uses Frida to enumerate installed apps and obtain the bundle ID, then uses
`ipatool` with the authorized Apple ID to download the authentic IPA from Apple's CDN. It does
**not** copy or decrypt the installed executable from the device.

1. Check the installation:
   `command -v ios-ipa-extractor ipatool`.
   If missing, run `scripts/install-tools.sh --stack ios` and retry.
2. Unlock the iPhone/iPad, connect it over USB, and accept **Trust This Computer**.
3. If no bundle ID was supplied, run `ios-ipa-extractor` interactively to list third-party apps
   and select one. Otherwise create `targets/<bundle-id>/` and run:
   ```bash
   ios-ipa-extractor -b <bundle-id> -o targets/<bundle-id>/<output-or-bundle-id>.ipa
   ```
   Let `ipatool` prompt interactively for authentication. Never put Apple ID passwords or 2FA
   codes in command arguments, logs, reports, or committed files; do not use the upstream `-p`
   or `-c` flags.
   If `ipatool` reports `platform version lookup returned no app`, do not assume the bundle ID is
   invalid. Confirm the exact bundle ID and numeric app ID with
   `ipatool --format json search --platform iphone <bundle-id>`, then resolve the current offer's
   `externalId` from Apple's public platform lookup using the account storefront and retry the
   download directly with all values pinned:
   ```bash
   ipatool download --app-id <numeric-id> --bundle-identifier <bundle-id> \
     --external-version-id <external-id> --platform iphone \
     --output targets/<bundle-id>/<app>.ipa --purchase
   ```
   This works around storefronts where ipatool's `enterprisestore` version lookup is empty even
   though the normal iOS catalog contains the app. Verify that the resolved bundle ID and visible
   version match before downloading. The upstream extractor currently rejects `--verbose` even
   though its failure text suggests it; use `ipatool ... --verbose` directly only when necessary,
   and redact diagnostic output because it may contain account/session metadata.
4. Validate the result:
   ```bash
   unzip -tqq targets/<bundle-id>/<app>.ipa
   unzip -l targets/<bundle-id>/<app>.ipa | rg 'Payload/.*\.app/' | head
   shasum -a 256 targets/<bundle-id>/<app>.ipa
   ```
5. State clearly that the App Store executable remains FairPlay-encrypted. Check `cryptid` before
   static binary analysis; `/re-static` can still inspect plist/resources, but meaningful
   class-dump/disassembly requires an authorized decrypted IPA (for example, via
   `frida-ios-dump` or `bagbak` on a compatible jailbroken research device).

Finally, report the exact local artifact path and suggest `/re-static` (endpoints, secrets,
deception), `/vuln-hunt` (vulnerability classes), and `/patch-apk` for Android patching.

Authorized targets only — use apps you own, are contracted to test, or that are explicitly in
scope. Artifacts stay under `targets/` (git-ignored); never commit IPAs, APKs, identifiers,
credentials, or device data.
