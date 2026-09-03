# React Native — static + dynamic analysis

Authorized targets only. Detect with `scripts/detect-stack.sh` (Hermes = `libhermes.so`;
JSC = `index.android.bundle` text).

## Static (recap)
`scripts/analyze-rn.sh <apk> out/` →
- **Hermes** → `hermes_out/` (`hbc-disassembler` + `hbc-decompiler`), or `hbctool` for patch/rebuild.
- **JSC** → `rndecompiler_out/` (`react-native-decompiler`) + `jsbeautify_out/pretty.js`.
- Grep the decompiled bundle for endpoints, `Bearer`, admin/internal paths, hardcoded secrets.
- Hermes deep tools: `hermes_rs`, `hasmer`, "Bytecode Studio".

## Dynamic — Frida ([`../runtime/rn-frida-hook.js`](../runtime/rn-frida-hook.js))
```bash
frida -U -f <pkg> -l runtime/rn-frida-hook.js -l runtime/ssl-pinning-universal.js
```
Logs, version-tolerant (Java side): **network** (OkHttp `RealCall` req/resp — RN's fetch/XHR go
through OkHttp), the **JS→native bridge** (`CatalystInstanceImpl.callFunction` — which native
modules JS invokes), **AsyncStorage** multiGet/multiSet (plaintext local storage), and the **JS
bundle** load path (`loadScriptFromAssets`/`loadScriptFromFile` — also the JS-injection point).
Attach `ssl-pinning-universal.js` so HTTPS bodies are visible.

JS-runtime hooks (advanced): inject JS ahead of the app bundle by wrapping `loadScriptFromAssets`,
then hook `XMLHttpRequest.prototype.open` / `XMLHttpRequest._interceptor` / `JSON.parse` in the
Hermes/JSC global.

## Remote debug / dev-mode (zero-Frida, powerful)
Flip the app into JS debug mode and set breakpoints in Chrome DevTools:
1. Patch the bundle/flags: in `index.android.bundle` set `__DEV__ = false → true`; in smali flip
   `ReactNativeHost.getUseDeveloperSupport()` return `0x0 → 0x1` (then rebuild/resign — see
   `scripts/patch-apk.sh`).
2. Serve the JS from Metro (`npx react-native start`, port 8081) — or use RN's dev menu
   ("Debug JS Remotely").
3. Open `http://localhost:8081/debugger-ui` in Chrome → breakpoints, watch, step through the JS.
4. **Edit-Shake-Reload**: replace the served bundle and reload to run modified JS live.

## Tips
- Reach the bundle: `adb shell run-as <pkg> cat ...` or pull `assets/index.android.bundle`.
- Loot: `shared_prefs/`, AsyncStorage `databases/`, `cache/http-cache` (cached responses + tokens).
- Deep links / exported components: see [`attack-surface.md`](attack-surface.md).

_Sources: bedefended (RN + Frida), pilfer.github.io, laripping (RN remote debug)._
