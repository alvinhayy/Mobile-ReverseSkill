# iOS pentesting without a jailbreak

Authorized targets only. Instrument a stock iPhone by **re-signing a decrypted IPA with
`get-task-allow` enabled** (or embedding FridaGadget), then sideloading it.

## Prerequisites (add to your toolbox)
`ipatool` (App Store download), a **jailbroken device or a friend's** for the one-time decrypt
(`frida-ios-dump` / Iridium + AppSync), **ios-app-signer**, a **free Apple Developer** cert,
**Sideloadly** or **AltStore** (or `ideviceinstaller`), and **libimobiledevice**
(`brew install libimobiledevice ideviceinstaller ios-deploy`). See `docs/TOOLING.md`.

## Workflow A — re-sign with get-task-allow (Frida/Objection attach)
1. **Get a decrypted IPA.** App Store binaries are FairPlay-encrypted; decrypt once on a JB device
   (`frida-ios-dump.py -u -p <bundle>` → `decrypted.ipa`), or pull with Apple Configurator.
2. **Re-sign** in **ios-app-signer** with your free Development cert and **UNCHECK "No
   get-task-allow"** (this leaves the `get-task-allow` entitlement on, which lets a debugger/Frida
   attach to *that* app's sandbox on a non-JB device).
3. **Install:** `ideviceinstaller -i resigned.ipa -w` (or Sideloadly / AltStore).
4. **Attach:** `frida-ps -Uai` then `objection -g <bundle_id> explore` →
   `ios sslpinning disable`, `ios jailbreak disable`, `ios keychain dump`, etc.

## Workflow B — embed FridaGadget (no debugger entitlement)
Repackage the app with **`FridaGadget.dylib`**: either add it via **Xcode Build Phases → Embed &
Sign** and re-sign, or CLI-inject a load command (`optool`/`insert_dylib`/`ldid`) then re-sign.
The gadget loads at launch → instrument with a Frida script/`config` file. Works alongside
Sideloadly's auto-sign.

## Static patch instead of runtime (JB-detection)
Load the (decrypted) Mach-O in Hopper/Ghidra, find the JB-detection routine (strings
`/Applications/Cydia.app`, `cydia://`, `canOpenURL`), patch it (`mov w0,#0; ret` / NOP the branch),
export the executable, re-sign the app bundle, sideload. Frida-independent. See `docs/ios-reversing.md`.

## Limits
Free Apple certs expire in **7 days** (re-sign/re-install weekly; AltStore auto-refreshes).
Some hardened apps also check the provisioning profile / team-id — combine with `ios-bypass.js`.

_Sources: litesec (modern iOS no-JB), 0xn3va (source patching), 0x9ec/objection docs._
