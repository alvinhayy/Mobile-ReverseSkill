---
description: Set up a rooted, anti-detection Android AVD (KernelSU on Apple Silicon, Magisk on x86_64)
argument-hint: "[api-level]  (default: 36)"
---

Set up a rooted test AVD for API `${ARGUMENTS:-36}`. Pick the path by host arch (`uname -m`):

**Apple Silicon / arm64 → KernelSU** via `alvinhayy/Mobile-Pentest-Setup`:
```bash
git clone https://github.com/alvinhayy/Mobile-Pentest-Setup && cd Mobile-Pentest-Setup
./create-avd.sh --name lab1 --api ${ARGUMENTS:-36} --full   # build→root→boot→grant→spoof→CA→proxy
```

**x86_64 → Magisk** via `newbit/rootAVD`:
```bash
git clone https://gitlab.com/newbit/rootAVD.git && cd rootAVD
./rootAVD.sh ListAllAVDs
./rootAVD.sh system-images/android-${ARGUMENTS:-36}/google_apis/x86_64/ramdisk.img
```

Then verify: `adb devices`, `adb shell su 0 id`, and (for anti-detection work) confirm the
spoofed device identity is internally consistent. Register `uiautomator2-mcp` afterwards
(see `docs/MCP-SETUP.md`) so the agent can drive the device.

For your own device or an AVD you own only.
