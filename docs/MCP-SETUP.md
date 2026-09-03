# Runtime analysis MCP — uiautomator2-mcp

Dynamic/runtime analysis needs to **drive the app on a device**: launch it, dump the UI tree,
tap through flows, type input, and reach the screen that triggers the code you're testing (e.g.
open the QR scanner so a crafted image hits the native recognizer you're fuzzing, or walk an
auth flow while a Frida script is attached).

This repo's runtime workflow uses **[uiautomator2-mcp](https://github.com/fdciabdul/uiautomator2-mcp)**
by [@fdciabdul](https://github.com/fdciabdul) — an MCP server that exposes Android device
automation (via [openatx/uiautomator2](https://github.com/openatx/uiautomator2)) to Claude
Code, Cursor, and other MCP clients.

## What it gives the agent

| Category | Tools |
|---|---|
| Screen | `screenshot`, `screen_on/off`, `unlock`, `screen_rotation` |
| UI inspection | `dump_hierarchy`, `dump_hierarchy_summary`, `find_element(s)`, `xpath_query` |
| Interaction | `click`, `click_element`, `long_click`, `double_click`, `swipe`, `scroll_to`, `drag`, `pinch_*` |
| Text / keys | `input_text`, `clear_text`, `get/set_clipboard`, `press_key` |
| Apps | `app_start`, `app_stop`, `app_current`, `app_list` |
| Device | `connect_device`, `device_info`, `shell_command`, `open_notification`, `open_quick_settings` |
| Automation | `set_watcher`, `remove_watcher`, `wait_for_element`, `get_toast` |

## Prerequisites

- Python **3.10+**
- Android device or emulator with **USB/ADB debugging**; `adb devices` must list it
- ADB on `PATH`

## Install

```bash
git clone https://github.com/fdciabdul/uiautomator2-mcp.git
cd uiautomator2-mcp
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # mcp, uiautomator2, Pillow
```

## Register with your agent

**Claude Code:**
```bash
claude mcp add --transport stdio uiautomator2 -- \
  /path/to/uiautomator2-mcp/.venv/bin/python \
  /path/to/uiautomator2-mcp/server.py
```

**Generic MCP client (`mcpServers` config):**
```json
{
  "mcpServers": {
    "uiautomator2": {
      "command": "/path/to/uiautomator2-mcp/.venv/bin/python",
      "args": ["/path/to/uiautomator2-mcp/server.py"]
    }
  }
}
```

On first use, call `connect_device` (uiautomator2 pushes its on-device agent), then
`app_start <package>` and `dump_hierarchy_summary` to see the screen.

## How it fits the workflow here

- **`reverse-engineer`** → after static analysis, drive the app to confirm which endpoints/flows
  are live and reachable.
- **`runtime/` Frida scripts** → spawn the app with a TLS-unpinning / bypass script attached,
  then use the MCP to walk the UI and generate the traffic/behaviour you want to observe.
- **`afl-fuzzing`** → navigate to the feature that feeds the native parser (e.g. the QR/barcode
  scanner) to validate reachability of your fuzz target in the real app.

> **Authorized use only.** Automate only devices you own and apps you're permitted to test.

## Credit

MCP server: **[fdciabdul/uiautomator2-mcp](https://github.com/fdciabdul/uiautomator2-mcp)**
(built on [openatx/uiautomator2](https://github.com/openatx/uiautomator2)). Not vendored here —
install from upstream; it keeps its own license.

## Burp CA on Android 14+ (alternatives to KernelSU mount-ca)
The `/setup` flow trusts the proxy CA via `mount-ca.sh` (KernelSU, conscrypt/APEX). For
**Magisk / rootAVD (x86_64)** users, a Magisk module is easier:
- **BurpCA-AutoTrust** (github.com/Hrishikesh7665/BurpCA-AutoTrust) or **AlwaysTrustUserCerts /
  conscrypt-trust-user-certs** (fox-it) — bind-mount the user CA into the system/APEX trust store
  on every boot. Install the module, push the Burp CA to the user store, reboot.
- Manual (root): convert Burp DER→PEM, `subject_hash_old` rename, copy to
  `/system/etc/security/cacerts/<hash>.0` (chmod 644) via an overlay/remount.
