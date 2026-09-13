---
description: Prep a rooted device for dynamic analysis — proxy (Burp) CA + frida-server + uiautomator2-mcp
argument-hint: "[burp|httptoolkit|all]  proxy for the CA (default: auto)"
allowed-tools: Bash(adb:*), Bash(frida:*), Bash(frida-ps:*), Bash(openssl:*), Bash(curl:*), Bash(claude mcp:*)
---

Prepare a rooted AVD/device for dynamic analysis: (1) trust the intercepting proxy's CA,
(2) get `frida-server` running, (3) wire up the **uiautomator2-mcp** device-automation server.
Proxy target: `${ARGUMENTS:-auto}` (`burp` | `httptoolkit` | `all`).

**Pre-flight:** `adb devices` — if none, run `/spawn` first. Confirm root: `adb shell su -c id`
(KernelSU uses `su -c`, not Magisk's `su 0`).

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

### 2. frida-server (client and server versions MUST match)
First check if a KernelSU/Magisk module already runs one (e.g. the **`cekidot`** module) — if so,
**use it**, don't fight it (it rebinds `27042` and auto-restarts). Just match the host client:
```bash
adb shell 'su -c "ls /data/adb/modules | grep -i cekidot"'      # module-provided frida-server?
adb shell 'su -c "ps -A -o ARGS | grep [f]rida"'                # already listening on 27042?
source .venv-frida/bin/activate 2>/dev/null || pip install -U frida-tools
# align the HOST client to the server's version (e.g. cekidot module.prop 'version'):
pip install "frida==<server-version>"; frida --version
frida-ps -U | head                                              # sanity over the running server
```
Only if nothing is running, deploy your own (version-matched to the host frida):
```bash
FV=$(frida --version); ABI=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')   # arm64-v8a
# download github.com/frida/frida/releases/download/$FV/frida-server-$FV-android-$ABI.xz, then unxz
adb push frida-server /data/local/tmp/frida-server; adb shell su -c 'chmod 755 /data/local/tmp/frida-server'
LOG=$(scripts/run-in-tab.sh frida-server "adb shell su -c /data/local/tmp/frida-server")   # in a tab
frida-ps -U | head
```

### 3. Device automation MCP (uiautomator2-mcp)
Wire up the MCP that drives the device UI (needed to walk flows to the screen under test). See
[`docs/MCP-SETUP.md`](../../docs/MCP-SETUP.md).
```bash
# install once if missing:
[ -d ~/tools/uiautomator2-mcp ] || git clone https://github.com/fdciabdul/uiautomator2-mcp ~/tools/uiautomator2-mcp
( cd ~/tools/uiautomator2-mcp && [ -d .venv ] || { python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt; } )
# register with the agent (idempotent — skip if already listed by `claude mcp list`):
claude mcp add --transport stdio uiautomator2 -- ~/tools/uiautomator2-mcp/.venv/bin/python ~/tools/uiautomator2-mcp/server.py
```
Then verify the MCP tools are available and call `connect_device` (uiautomator2 pushes its
on-device agent), then `dump_hierarchy_summary` on the current screen. If the tools are not yet
loaded in this session, tell the user to reload so the MCP server is picked up.

### 4. Report
Proxy (host:port, connected?), `mount-ca.sh --status`, frida version + `frida-ps -U` sanity,
and uiautomator2-mcp registered + `connect_device` OK.

Gotcha: run agents via `-l script.js` (see `runtime/`), not an interactive stdin session that
exits on EOF (that looks like a RASP block). Authorized targets only.
