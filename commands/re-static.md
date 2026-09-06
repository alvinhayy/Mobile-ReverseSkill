---
description: Static-analyze an APK/IPA/web bundle (endpoints, secrets, permissions, deception)
argument-hint: <path-to-apk|ipa|bundle>
---

Invoke the **reverse-engineer** skill and run a full static-analysis pass on: `$ARGUMENTS`

Steps:
1. Load the `reverse-engineer` skill.
2. Detect artifact type (APK/XAPK/AAB, IPA, or web/JS bundle) and run the matching pipeline:
   manifest/Info.plist → decompile (`jadx`/`apktool`; note Flutter `libapp.so`) → strings/URL
   carve → secrets (`trufflehog`/`gitleaks`) → certificate/pinning.
3. Do the **deception & honeypot** pass: trace runtime URL construction, decode obfuscation,
   classify each endpoint `CONFIRMED_REAL` vs `PLANTED_FAKE`.
4. Emit `endpoints.json`, `secrets.json`, `metadata.json`, `flow-analysis.json`,
   `deception-analysis.json`, and a Markdown `report.md` with a Mermaid flow diagram, into a
   `findings/<slug>-<YYYY-MM-DD>/` directory.

Authorized targets only. Keep real identity/domains/secrets in the local report — never commit them.
