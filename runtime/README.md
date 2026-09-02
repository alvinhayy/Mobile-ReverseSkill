# Frida runtime helpers

Generalized Frida templates for **authorized** dynamic analysis. The target package is a
placeholder `com.example.targetapp` — replace it with the app you are permitted to test.

```bash
frida -U -f com.example.targetapp -l flutter-tls.js
# spawn with several layered scripts:
frida -U -f com.example.targetapp -l rasp-bypass.js -l flutter-tls.js
```

| Script | Purpose |
|---|---|
| `flutter-tls.js` / `flutter-tls2..4.js` | Flutter/BoringSSL TLS certificate-verification unpinning (variants for different builds) |
| `emu-bypass.js` | Bypass emulator-detection checks so the app runs on an AVD |
| `approov-nopin.js` / `approov-badcert.js` | Probe/relax attestation + pinning behaviour |
| `rasp-bypass.js` / `rasp-neutralise.js` | RASP neutralisation patterns |
| `proc-spoof.js` / `ua-spoof.js` / `prop-find-fix.js` / `maps-spoof.js` | Device identity / property spoofing helpers |
| `probe-emu.js` / `probe-remaining.js` | Diagnostics: what the app inspects / what still blocks it |
| `verdict-hook.js` / `find-verdict.js` / `ironsky-log.js` / `kill-trace.js` | Tracing helpers for locating a protection's decision point |

> Gotcha: run agents via a file/port, not an interactive `frida` CLI that exits on stdin EOF —
> that exit can look like a RASP block when it is not. Use `-l script.js` and keep the session
> attached (or use `frida-inject` / a gadget).

**Authorized use only.** Do not point these at apps or infrastructure you don't own or aren't
contracted to test.

## Driving the app (MCP)

Pair these Frida scripts with **[uiautomator2-mcp](https://github.com/fdciabdul/uiautomator2-mcp)**
so the agent can launch the app, dump the UI, and tap through to the screen you want to observe.
Setup: [`../docs/MCP-SETUP.md`](../docs/MCP-SETUP.md).
