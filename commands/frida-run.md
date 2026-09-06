---
description: Spawn the app with a runtime bypass script attached (TLS/emulator/RASP/attestation)
argument-hint: <package> [script.js ...]
---

Attach the `runtime/` Frida helpers to a target you are authorized to test: `$ARGUMENTS`

Steps:
1. Parse `$ARGUMENTS` → first token = package (default placeholder `com.example.targetapp`),
   the rest = script names from `runtime/` (default: `rasp-bypass.js flutter-tls.js`).
2. Confirm a device/emulator is up (`adb devices`) and `frida-server`/gadget is available.
3. **Launch in a NEW terminal tab so the user can watch/interact, while you keep monitoring
   the mirrored log.** Build the frida command, then hand it to `scripts/run-in-tab.sh`:
   ```bash
   LOG=$(scripts/run-in-tab.sh frida "frida -U -f <package> $(for s in <scripts>; do printf -- '-l runtime/%s ' "$s"; done)")
   ```
   The interactive frida REPL opens in its own tab (iTerm2/Terminal); if Automation isn't
   permitted it falls back to background — either way the session is mirrored to `$LOG`.
4. **Monitor** the process from here by reading `$LOG` (`tail -n 40 "$LOG"`, re-read as needed).
   Report boot progress, hook output, and any crash/kill from the log.
5. If it dies at launch, launch a diagnostic in another tab
   (`scripts/run-in-tab.sh kil: "frida -U -f <package> -l runtime/kill-trace.js"` or
   `probe-emu.js`), read its log, then add the matching bypass
   (`emu-bypass.js`, `proc-spoof.js`, `ua-spoof.js`, …).
6. Pair with **uiautomator2-mcp** (see `docs/MCP-SETUP.md`) to drive the UI to the screen you
   want to observe.

Note: run frida via `-l` script files, not an interactive stdin pipe that exits on EOF (that
looks like a RASP block). Authorized targets only.
