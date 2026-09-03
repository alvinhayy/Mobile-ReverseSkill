---
description: Prep a rooted device for dynamic analysis — install the proxy (Burp) CA + start frida-server
argument-hint: "[burp|httptoolkit|all]  proxy for the CA (default: auto)"
allowed-tools: Bash(adb:*), Bash(frida:*), Bash(frida-ps:*), Bash(openssl:*), Bash(curl:*)
---

Prepare a rooted AVD/device for dynamic analysis: (1) trust the intercepting proxy's CA,
(2) get `frida-server` running. Proxy target: `${ARGUMENTS:-auto}` (`burp` | `httptoolkit` | `all`).

**Pre-flight:** `adb devices` — if none, run `/spawn` first. Confirm root: `adb shell su 0 id`.

### 1. Burp CA + proxy route
Start Burp first (Proxy listener on `:8080`). Then, from `tools/Mobile-Pentest-Setup/`:
```bash
./mount-ca.sh --proxy ${ARGUMENTS:-auto} --user --persist   # CA into APEX trust store, survives reboot
./proxy.sh   --connect ${ARGUMENTS:-auto}                    # route device traffic (host 10.0.2.2)
./mount-ca.sh --status                                       # expect OK (2/2)
```
Manual fallback (no toolkit / plain Burp CA export as DER):
```bash
openssl x509 -inform DER -in cacert.der -out /tmp/ca.pem
H=$(openssl x509 -inform PEM -subject_hash_old -in /tmp/ca.pem | head -1)
adb push /tmp/ca.pem /data/local/tmp/$H.0
adb shell su 0 sh -c "mount -o rw,remount /system 2>/dev/null; cp /data/local/tmp/$H.0 /system/etc/security/cacerts/ && chmod 644 /system/etc/security/cacerts/$H.0"
```

### 2. frida-server (version MUST match host frida)
```bash
source .venv-frida/bin/activate 2>/dev/null || pip install -U frida-tools
FV=$(frida --version); ABI=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')   # emulator = arm64-v8a
# download github.com/frida/frida/releases/download/$FV/frida-server-$FV-android-$ABI.xz, then unxz
adb push frida-server /data/local/tmp/frida-server
adb shell su 0 chmod 755 /data/local/tmp/frida-server
adb shell "su 0 /data/local/tmp/frida-server &"
frida-ps -U | head        # sanity: process list over USB/emulator
```

### 3. Report
Proxy (host:port, connected?), `mount-ca.sh --status`, frida host version, `frida-ps -U` sanity.

Gotcha: run agents via `-l script.js` (see `runtime/`), not an interactive stdin session that
exits on EOF (that looks like a RASP block). Authorized targets only.
