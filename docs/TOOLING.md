# Tooling matrix

Static-analysis + decompiler toolchain per stack. Install with
`scripts/install-tools.sh --stack <name>` (or `--check` to audit). Build order:
**Android → Flutter → RN → iOS** (+ cross disassemblers).

## Output convention — `<tool>_out/`

Every tool that produces output writes to a folder named after it, suffix `_out`:

```
out/
  apktool_out/    jadx_out/    dex2jar_out/    baksmali_out/    dexdump_out/
  strings_out/    apkleaks_out/    detect.txt    MANIFEST.txt
```

`*_out/` holds **decompiled target code** — it is git-ignored and must never be committed.

## Status

| Stack | Status | Pipeline |
|---|---|---|
| Android | done (stage 1) | `scripts/analyze-android.sh` |
| Flutter | stage 2 | blutter, reFlutter |
| React Native | stage 3 | hermes-dec, hbctool, react-native-decompiler |
| iOS | stage 4 | class-dump, otool/nm, swift-demangle |

---

## Android (stage 1)

| Tool | Install (macOS) | Role | `_out` |
|---|---|---|---|
| **jadx** | `brew install jadx` | DEX -> Java sources | `jadx_out/` |
| **apktool** | `brew install apktool` | smali + resources + `AndroidManifest.xml` | `apktool_out/` |
| **baksmali** | `brew install smali` | DEX -> smali (per dex) | `baksmali_out/` |
| **dex2jar** | `brew install dex2jar` | DEX -> JAR (`d2j-dex2jar`) | `dex2jar_out/` |
| **dexdump** | Android build-tools | method/proto dump | `dexdump_out/` |
| **apkleaks** | `pip install apkleaks` (opt) | secrets/endpoints regex | `apkleaks_out/` |
| `strings` | bundled | URLs from dex + `.so` | `strings_out/` |

Run:
```bash
scripts/install-tools.sh --stack android --check     # audit
scripts/analyze-android.sh app.apk out/app           # -> out/app/<tool>_out/
```

Notes:
- Flutter apps keep logic in `libapp.so` (Dart AOT); most classes are absent from
  `classes.dex` -- jadx/smali output is thin, routing to the Flutter pipeline (stage 2).
- `dexdump` ships with Android build-tools: `sdkmanager 'build-tools;<ver>'`.

## Cross disassemblers (any stack)

| Tool | Install | Use |
|---|---|---|
| **Ghidra** | `brew install --cask ghidra` | decompile `.so` / Mach-O / `.dylib`; headless-scriptable |
| **radare2** | `brew install radare2` | CLI disasm + `r2frida` |
| **rizin** | `brew install rizin` | radare2 fork (optional) |
| **IDA** | commercial | premium disasm (optional) |
| **Hopper** | `brew install --cask hopper-disassembler` | macOS/iOS disasm (iOS work) |
