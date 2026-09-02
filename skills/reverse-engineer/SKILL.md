---
name: reverse-engineer
description: Static analysis of Android APKs, iOS IPAs, and bundled web apps — extract endpoints, secrets, permissions, code flow, and separate real endpoints from planted honeypots, then report as JSON + Markdown.
category: mobile-security
author: alvinhayy
license: MIT
tags: [android, ios, apk, ipa, static-analysis, secrets, endpoints, reverse-engineering]
---

# reverse-engineer — mobile & web static analysis

Structured methodology for pulling security-relevant data out of a mobile app or web bundle
you are **authorized** to assess: API endpoints, hardcoded secrets/keys, permissions, code
flow, and deception (honeypot endpoints, anti-analysis checks).

> **Authorized use only.** Analyse artifacts you own or are contracted/permitted to test.
> Keep target identity and raw findings in the private engagement report, never in a shared repo.

## When to use

- You have an `.apk` / `.xapk` / `.aab`, an `.ipa`, or a minified web/JS bundle and need a
  fast, repeatable first pass before deeper dynamic work.

## Tool environment (local first, Docker fallback)

`apktool`, `jadx`, `dex2jar`, `baksmali`, `dexdump`, `strings`, `unzip`; `trufflehog`,
`gitleaks` for secrets; `class-dump`, `otool`, `codesign`, `plutil` for iOS; `js-beautify`,
`prettier` for web. Fallback: Docker `cryptax/android-re`.

## Pipelines

### APK
1. **Manifest** — `apktool d app.apk`; parse package, version, `minSdk`/`targetSdk`,
   permissions, exported components, `networkSecurityConfig`.
2. **Decompile** — `jadx` for Java/Kotlin; note when a Flutter app keeps its logic in
   `libapp.so` (Dart AOT) and most classes are **absent from `classes.dex`**.
3. **Strings/URLs** — carve endpoints from `libapp.so` and dex (`strings`, targeted greps).
4. **Secrets** — `trufflehog`/`gitleaks` over the unpacked tree.
5. **Certificates / pinning** — inspect the signing cert and any pinning config.

### IPA
`Info.plist` (`plutil`), entitlements (`codesign -d --entitlements`), the Mach-O binary
(`otool`, `class-dump`, `strings`).

### Web / JS bundle
Beautify minified code (`js-beautify`/`prettier`), extract routes and tokens, map the
API surface.

## Deception & honeypot analysis (do this explicitly)

Real apps plant fake endpoints and anti-analysis checks. For each candidate endpoint:
- Trace **runtime URL construction** (concatenation, base + path) rather than trusting a
  literal string.
- Decode encodings (Base64/XOR/AES) around URLs and keys.
- Note emulator/debugger/root checks that gate behaviour.
- Classify with a truth table: `CONFIRMED_REAL` vs `PLANTED_FAKE`, with the evidence.

## Reporting

Emit machine-readable + human-readable outputs:
- `endpoints.json`, `secrets.json`, `metadata.json`, `flow-analysis.json`,
  `deception-analysis.json`
- A Markdown `report.md` with a Mermaid flow diagram.

Keep client-identifying data (real domains, package, brand, secrets) out of any shared copy —
redact to placeholders before publishing.

## Credits

Methodology adapted from the community "reverse-engineer" skill
(gist `binsarjr/adbd5110cd78bbd09a1d9afc0f23c944`). Original wording MIT.
