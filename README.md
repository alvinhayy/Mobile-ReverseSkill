<h1 align="center">Mobile-ReverseSkill</h1>

<p align="center">
  Reusable <b>Agent Skills</b> for mobile reverse engineering &amp; native fuzzing —
  installable into Claude Code, Cursor, Copilot and friends via <a href="https://skill.fish">skillfish</a>.
</p>

<p align="center">
  <a href="https://github.com/alvinhayy/Mobile-ReverseSkill/stargazers"><img src="https://img.shields.io/github/stars/alvinhayy/Mobile-ReverseSkill?style=flat&logo=github"></a>
  <img src="https://img.shields.io/badge/skills-2-blue">
  <img src="https://img.shields.io/badge/platform-Android%20%7C%20iOS%20%7C%20Web-green">
  <img src="https://img.shields.io/badge/install-skillfish-8A2BE2?logo=npm">
  <img src="https://img.shields.io/github/last-commit/alvinhayy/Mobile-ReverseSkill">
  <img src="https://img.shields.io/github/languages/code-size/alvinhayy/Mobile-ReverseSkill">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey">
</p>

---

## Skills

| Skill | What it does |
|---|---|
| [`afl-fuzzing`](skills/afl-fuzzing/) | Greybox-fuzz Android native `.so` libraries **on-device** with AFL++ — cross-compile the fuzzer for Android arm64, harness a JNI parser with a stub `JNIEnv`, detect bugs with ASan/`libdislocator`, and **validate the harness actually reaches the target** (poison-pointer control). Includes a complete worked harness + scripts. |
| [`reverse-engineer`](skills/reverse-engineer/) | Static analysis of Android APKs, iOS IPAs, and web bundles — extract endpoints, secrets, permissions, code flow, and separate real endpoints from planted honeypots; report as JSON + Markdown. |

## Install

Add a skill to your agent with [skillfish](https://skill.fish):

```bash
npx skillfish add alvinhayy/Mobile-ReverseSkill afl-fuzzing
npx skillfish add alvinhayy/Mobile-ReverseSkill reverse-engineer
```

Or clone and point your agent's skills directory at `skills/`:

```bash
git clone https://github.com/alvinhayy/Mobile-ReverseSkill
```

## Slash commands

Ship with the repo as a project (`.claude/commands/`), or copy them to `~/.claude/commands/`
to use anywhere:

| Command | Does |
|---|---|
| `/re-static <apk\|ipa\|bundle>` | Static analysis via the `reverse-engineer` skill (endpoints, secrets, deception) |
| `/fuzz-build [lib.so]` | Build AFL++ for Android + harness, push to the emulator |
| `/fuzz-validate [lib.so]` | Prove the harness reaches the target (poison-pointer / under-alloc controls) |
| `/fuzz-run [seconds]` | Run the on-device campaign and triage crashes |
| `/frida-run <package> [script.js ...]` | Spawn the app with `runtime/` bypass scripts attached |
| `/root-avd [api]` | Rooted AVD (KernelSU on Apple Silicon, Magisk on x86_64) |

## Tooling & multi-stack (staged)

Static-analysis + decompiler toolchain, built stage by stage: **Android → Flutter → RN → iOS**
(+ cross disassemblers). Install and audit:

```bash
scripts/install-tools.sh --stack android --check   # audit availability
scripts/detect-stack.sh app.apk                    # flutter|react-native|unity|xamarin|native
scripts/analyze-android.sh app.apk out/app         # -> out/app/<tool>_out/
```

Each tool writes to its own `<tool>_out/` folder (git-ignored — holds decompiled target code).
Full matrix + status: [`docs/TOOLING.md`](docs/TOOLING.md).

## Repository layout

```
.claude/commands/       slash commands
scripts/                 install-tools.sh, detect-stack.sh, analyze-android.sh
.claude/commands/       slash commands (see below)
skills/
  afl-fuzzing/         SKILL.md + harness/ + scripts/ + README.md (full method writeup)
  reverse-engineer/    SKILL.md
runtime/               Frida helper scripts (TLS unpinning, emulator/RASP/attestation bypass,
                       device spoofing) — generalized templates; set your own target package
docs/
  WORKFLOW.md          end-to-end mobile-RE workflow guide (toolchain, rooting, fuzzing)
  MCP-SETUP.md         runtime device-automation MCP setup (uiautomator2-mcp)
```

## Frida runtime helpers (`runtime/`)

Generic Frida templates for dynamic analysis. The target package is a placeholder
`com.example.targetapp` — replace it with the app you are authorized to test:

```bash
frida -U -f com.example.targetapp -l runtime/flutter-tls.js
```

Highlights: `flutter-tls*.js` (Flutter/BoringSSL TLS unpinning), `emu-bypass.js`
(emulator-detection bypass), `approov-*.js` (attestation/pinning probes),
`rasp-*.js` (RASP neutralisation patterns), `*-spoof.js` (device identity spoofing).

## Runtime device automation (MCP)

Dynamic analysis drives the app on a device — launch it, dump the UI tree, tap through flows,
and reach the screen that triggers the code under test (open the QR scanner, walk an auth flow
while a Frida script is attached). This uses **[uiautomator2-mcp](https://github.com/fdciabdul/uiautomator2-mcp)**
by [@fdciabdul](https://github.com/fdciabdul):

```bash
git clone https://github.com/fdciabdul/uiautomator2-mcp.git
cd uiautomator2-mcp && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
claude mcp add --transport stdio uiautomator2 -- $PWD/.venv/bin/python $PWD/server.py
```

Full setup + config for other MCP clients: [`docs/MCP-SETUP.md`](docs/MCP-SETUP.md).

## Rooting a test AVD

- **macOS / Apple Silicon (arm64)** → KernelSU via
  [`alvinhayy/Mobile-Pentest-Setup`](https://github.com/alvinhayy/Mobile-Pentest-Setup):
  `./create-avd.sh --name lab1 --api 36 --full`
- **x86_64** → Magisk via [`newbit/rootAVD`](https://gitlab.com/newbit/rootAVD):
  `./rootAVD.sh system-images/android-<API>/<tag>/x86_64/ramdisk.img`

See [`docs/WORKFLOW.md`](docs/WORKFLOW.md) for the full toolchain and step-by-step flow.

## ⚠ Authorized use only

These skills are for **authorized** security research: apps you own, or engagements you are
contracted/permitted to run, or CTF/education. Keep the target's identity, real domains, and
raw findings in your private report — never commit them here. All fuzzing runs **offline on a
local emulator/device**; nothing targets third-party production infrastructure.

## Credits & license

- `afl-fuzzing` builds on [AFL++](https://github.com/AFLplusplus/AFLplusplus) (AGPL-3.0) and the
  Trail of Bits [`aflpp`](https://github.com/trailofbits/skills) skill.
- `reverse-engineer` methodology adapted from the community gist
  `binsarjr/adbd5110cd78bbd09a1d9afc0f23c944`.

Original content in this repository (harnesses, scripts, skill docs) is **MIT** — see
[`LICENSE`](LICENSE). Bundled/referenced upstream tools keep their own licenses.
