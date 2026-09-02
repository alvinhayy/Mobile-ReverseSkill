---
description: Spawn the app with a runtime bypass script attached (TLS/emulator/RASP/attestation)
argument-hint: <package> [script.js ...]
---

Attach the `runtime/` Frida helpers to a target you are authorized to test: `$ARGUMENTS`

Steps:
1. Parse `$ARGUMENTS` → first token = package (default placeholder `com.example.targetapp`),
   the rest = script names from `runtime/` (default: `rasp-bypass.js flutter-tls.js`).
2. Confirm a device/emulator is up (`adb devices`) and `frida-server`/gadget is available.
3. Spawn with the scripts layered:
   `frida -U -f <package> $(for s in <scripts>; do echo -l runtime/$s; done)`
   — run via `-l` files, not an interactive stdin session (it exits on EOF and can look like a
   RASP block).
4. If it dies at launch, attach `runtime/kill-trace.js` / `probe-emu.js` to find what terminates
   it, then add the matching bypass (`emu-bypass.js`, `proc-spoof.js`, `ua-spoof.js`, …).
5. Pair with **uiautomator2-mcp** (see `docs/MCP-SETUP.md`) to drive the UI to the screen you
   want to observe.

Authorized targets only.
