---
description: Spawn (boot) a rooted KernelSU AVD — auto-picks the only one, else /spawn <avd-name>
argument-hint: "[avd-name]  (required only if more than one AVD is installed)"
allowed-tools: Bash(adb:*), Bash(emulator:*), Bash(*emulator -list-avds*), Bash(*emulator -avd*)
---

Boot a rooted test AVD (KernelSU lab from `alvinhayy/Mobile-Pentest-Setup`). Target: `$ARGUMENTS`

Steps:
1. **Resolve the emulator binary**: prefer `"$ANDROID_HOME"/emulator/emulator`, else
   `"$ANDROID_SDK_ROOT"/emulator/emulator`, else `emulator` on PATH.
2. **List installed AVDs**: `<emulator> -list-avds`.
3. **Pick the AVD**:
   - If `$ARGUMENTS` is non-empty → use it as the AVD name (verify it's in the list; if not,
     show the list and stop).
   - Else if **exactly one** AVD is installed → use it.
   - Else (**zero** → tell the user to create one with
     `tools/Mobile-Pentest-Setup/create-avd.sh --name lab1 --api 36`; **more than one** →
     print the list and ask them to run `/spawn <avd-name>`). Do **not** guess when ambiguous.
4. **Check if already running**: `adb devices` — if an emulator is already up for that AVD, say so
   and skip re-spawning.
5. **Spawn in a NEW terminal tab** (so the user sees the emulator's boot output; you monitor the
   mirrored log):
   `LOG=$(scripts/run-in-tab.sh emu-<name> "<emulator> -avd <name> -no-snapshot-load")`
6. **Wait for boot**: `adb wait-for-device` then poll `adb shell getprop sys.boot_completed`
   until `1` (and read `$LOG` for boot progress / errors).
7. **Verify root (KernelSU)**: `adb shell su 0 id`. If not root, hint:
   `cd tools/Mobile-Pentest-Setup && ./root-avd.sh --grant-shell`.
8. **Report**: device serial (`adb devices`), model (`adb shell getprop ro.product.model`),
   API level, and root status.

For your own AVDs only.
