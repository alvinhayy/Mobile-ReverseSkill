---
description: Autonomous runtime observation — read the static RE results (protections + flow), attach the right frida bypasses, drive the app via uiautomator2-mcp, and correlate behavior
argument-hint: "<package> [re-out-dir]  (re-out-dir = a /re-static output, default ./out)"
allowed-tools: Bash(adb:*), Bash(frida:*), Bash(frida-ps:*), Bash(grep:*), Bash(rg:*), Bash(cat:*)
---

Autonomously observe `$ARGUMENTS` at runtime by building on the static analysis, then driving the
app on-device via **uiautomator2-mcp** while frida is attached. Package = first token; RE output
dir = second token (default `./out`, i.e. the folder `/re-static` / analyze-*.sh wrote).

Work through this end-to-end, deciding actions from what you read (this command is meant to run
with minimal hand-holding):

### 1. Ingest the static picture
Read the RE artifacts for this app (do not re-run RE if already present):
- stack (`detect.txt`), endpoints/URLs (`strings_out/urls.txt`), and the decompiled logic
  (`hermes_out/decompiled.js` | `blutter_out/asm/**` | `jadx_out/**`), plus any `FINDINGS.md`.
- the manifest (`apktool_out/AndroidManifest.xml` or `aapt2 dump badging`) → **launch activity**,
  exported components, permissions, `usesCleartextTraffic`, `networkSecurityConfig`.
Summarize: package, entry screen, the primary user flow, and the key endpoints to watch.

### 2. Fingerprint protections (decide the bypass set)
Grep the decompiled code + `lib/*/*.so` names for defenses, and map each to a `runtime/` script:
| Signal in the app | Bypass to attach |
|---|---|
| BoringSSL/OkHttp pinning, `CertificatePinner`, `libflutter.so` | `flutter-tls*.js` (Flutter) / OkHttp unpin |
| root checks (`su`, `magisk`, `which`, `RootBeer`) | `runtime/proc-spoof.js`, `runtime/prop-find-fix.js` |
| emulator checks (`goldfish`, `ro.kernel.qemu`, `generic`) | `runtime/emu-bypass.js`, `runtime/ua-spoof.js` |
| frida/debugger/RASP (`frida`, `ptrace`, IronSky, `libappsec`) | `runtime/rasp-bypass.js` / `rasp-neutralise.js` |
| attestation (`Approov`, `libapproov`, Play Integrity, SafetyNet) | `runtime/approov-*.js` (note: server-side attestation may be undefeatable — say so) |
Pick only the scripts the evidence supports; list what you chose and why.

### 3. Ensure the lab is ready
`adb devices` (else `/spawn`). frida-server running & client matched (else `/setup`, incl. a
module server like `cekidot`). uiautomator2-mcp available & `connect_device` OK (else `/setup`
step 3). Confirm the target package is installed (`adb shell pm path <package>`; else `adb install`).

### 4. Attach frida (bypasses + observation) in a live tab
Launch in a tab so it is watchable and mirrored to a log you tail:
```bash
LOG=$(scripts/run-in-tab.sh observe "frida -U -f <package> \
  $(for s in <chosen bypass scripts>; do printf -- '-l runtime/%s ' "$s"; done) -l runtime/<obs>.js")
```
For observation, prefer an existing hook (or write a tiny one to scratch): hook the app's HTTP
client / `fetch` / OkHttp / `SSL_write` to log method+URL+body, and any auth/crypto functions the
static step flagged. Read `$LOG` as you go.

### 5. Drive the flow via uiautomator2-mcp (this is the "auto observation")
Use the MCP tools: `connect_device` → `app_start <package>` → then loop:
`dump_hierarchy_summary` / `screenshot` to see the screen, `click_element` / `input_text` /
`swipe` to advance through the flow you mapped in step 1 (e.g. register/login → dashboard →
the sensitive actions: transfer, profile-picture-URL upload, admin/hidden paths). Take a
screenshot at each state. Prefer selecting elements by text/resource-id from the hierarchy, not
fixed coordinates.

### 6. Observe & correlate
While driving, watch three streams and tie them to the static hypotheses:
- **frida log** (`$LOG`) — hooked requests, bypass hits, blocked/allowed.
- **network** — Burp (if `/setup burp` done) or `adb logcat` for URLs/tokens.
- **UI state** — screenshots / hierarchy.
Confirm or refute each finding from `FINDINGS.md` (e.g. does `/upload_profile_picture_url` fetch
an attacker URL → SSRF; is a hidden/admin path reachable; IDOR on numeric ids; tokens in logs).

### 7. Report
A runtime-observation summary: protections seen + whether bypassed; the flow walked (with
screenshots); endpoints actually called; and each static hypothesis marked
observed / not-observed / needs-follow-up. Save to `<re-out-dir>/RUNTIME.md`.

Authorized targets only. Dynamic requests should hit your own/local backend, not third-party prod.
