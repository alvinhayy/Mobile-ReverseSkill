---
description: Hunt vulnerability classes (IPC, WebView, providers, TLS, storage, crypto) over a decompiled app — rg signatures + optional semgrep taint, triage, per-class PoC
argument-hint: <path-to-apk|ipa|jadx_out|analysis-out>
---

Invoke the **mobile-vuln-hunt** skill and run a vulnerability-class hunt on: `$ARGUMENTS`

Steps:
1. Load the `mobile-vuln-hunt` skill.
2. If the input is an APK/IPA (not yet decompiled), run the matching pipeline first
   (`scripts/analyze-android.sh` / `scripts/analyze-ios.sh`); for Android also
   `scripts/attack-surface.sh` for the exported-component inventory.
3. Tier 1 — run the skill's ripgrep signature block over `jadx_out/` + `apktool_out/`
   (Android) or the decrypted binary + `classdump_out/` (iOS; check `cryptid` first).
4. Tier 2 — if `semgrep` is installed, run
   `skills/mobile-vuln-hunt/semgrep/android-taint.yaml` for the dataflow classes
   (intent redirection, WebView URL injection, file write, stream URI read).
5. Triage each hit (exported reachability, attacker-APK discipline, debug-guard checks) and pick
   the matching dynamic PoC from `docs/vuln-classes-android.md` / `docs/vuln-classes-ios.md`
   (full depth: `docs/research/mobile-pentesting/`).
6. Emit `findings/<slug>-<YYYY-MM-DD>/vuln-classes.json` + `report.md` grouped by family
   (IPC / WebView / Provider / File / Network / Crypto / Storage / Anti-analysis), with chain
   narratives for linked findings.

Authorized targets only. Keep target identity/domains/secrets in the local report — never commit them.
