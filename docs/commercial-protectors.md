# Commercial protectors (Appdome, DexProtector, Promon, …)

Authorized targets only. Commercial shields fuse many detections into a native lib and bind them
to Java via `RegisterNatives`, so the fastest way in is to enumerate those bindings, then
analyze/patch the specific routines.

## Generic methodology
1. **Enumerate native bindings** — [`../runtime/registernatives-dump.js`](../runtime/registernatives-dump.js)
   logs every `RegisterNatives` (name, signature, native address+offset). For Appdome the logic
   compiles into **`libloader.so`**; each detection routine's offset shows up here.
2. **Analyze in Ghidra** — open the lib, jump to the offsets, read the checks (root/frida/emulator/
   debugger/proxy/integrity), then either **Frida-hook** the return or **binary-patch** it.
3. **Neutralise return values** — hook each native at its offset (`base.add(0x...)`) and force the
   boolean/int result; or patch the branch (`mov w0,#0; ret`) and repackage (`scripts/patch-apk.sh`).

## Appdome threat model (names to grep/hook)
`RootedDevice, FridaDetected, MagiskManagerDetected, EmulatorFound, CodeInjectionDetected,
ActiveDebuggerThreatDetected, AppIsDebuggable, DeveloperOptionsEnabled, NetworkProxyConfigured,
AppIntegrityError` + SSL/pinning checks. Appdome specifically hunts standard `frida-server` on
27042 and injected gadgets — use a **renamed/ported Frida** (e.g. StrongR-Frida) or a non-default
port, spawn early, and pair with `android-antidebug.js` + `android-root-bypass.js`.

## Notes
- These shields also do **integrity/anti-repackage** checks → prefer runtime Frida over static
  patching, or defeat the integrity routine (found via step 1) before patching.
- Combine with `ssl-pinning-universal.js` (native `SSL_get_verify_result`) since the pinning is
  often also inside the protector's lib.

_Source: farimarwat (Appdome 2026), general RASP methodology._
