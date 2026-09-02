#!/usr/bin/env bash
# analyze-android.sh <app.apk> [OUTDIR=./out]
# Run the Android static-analysis tools; each tool writes to its own <tool>_out/ folder.
# Missing tools are skipped with a note (install: scripts/install-tools.sh --stack android).
#
# Produces under OUTDIR:
#   apktool_out/   jadx_out/   dex2jar_out/   baksmali_out/   dexdump_out/
#   strings_out/   apkleaks_out/   detect.txt   MANIFEST.txt
set -uo pipefail

APK="${1:-}"; OUT="${2:-./out}"
[ -n "$APK" ] && [ -f "$APK" ] || { echo "usage: $0 <app.apk> [OUTDIR]"; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
have(){ command -v "$1" >/dev/null 2>&1; }
step(){ printf '\n\033[36m==> %s\033[0m\n' "$*"; }
skip(){ printf '\033[33m--  skip %s (%s)\033[0m\n' "$1" "$2"; }

# 0. framework detection (informational)
step "detect stack"; sh "$HERE/detect-stack.sh" "$APK" | tee "$OUT/detect.txt" || true

# extract dex once for baksmali/dexdump
DEXTMP="$OUT/.dex"; rm -rf "$DEXTMP"; mkdir -p "$DEXTMP"
unzip -o -j "$APK" 'classes*.dex' -d "$DEXTMP" >/dev/null 2>&1 || true

# 1. apktool → apktool_out/  (smali + resources + AndroidManifest)
step "apktool"
if have apktool; then apktool d -f "$APK" -o "$OUT/apktool_out" >/dev/null && echo "  -> $OUT/apktool_out"; else skip apktool "brew install apktool"; fi

# 2. jadx → jadx_out/  (Java sources)
step "jadx"
if have jadx; then jadx -q -d "$OUT/jadx_out" "$APK" >/dev/null 2>&1 || true; echo "  -> $OUT/jadx_out"; else skip jadx "brew install jadx"; fi

# 3. dex2jar → dex2jar_out/app.jar
step "dex2jar"
if have d2j-dex2jar; then mkdir -p "$OUT/dex2jar_out"; d2j-dex2jar "$APK" -f -o "$OUT/dex2jar_out/app.jar" >/dev/null 2>&1 && echo "  -> $OUT/dex2jar_out/app.jar"; else skip dex2jar "brew install dex2jar"; fi

# 4. baksmali → baksmali_out/  (per-dex smali)
step "baksmali"
if have baksmali; then
  mkdir -p "$OUT/baksmali_out"
  for d in "$DEXTMP"/classes*.dex; do [ -f "$d" ] || continue; baksmali d "$d" -o "$OUT/baksmali_out/$(basename "$d" .dex)" >/dev/null 2>&1 || true; done
  echo "  -> $OUT/baksmali_out"
else skip baksmali "brew install smali"; fi

# 5. dexdump → dexdump_out/<dex>.txt
step "dexdump"
DEXDUMP="$(ls "$HOME"/Library/Android/sdk/build-tools/*/dexdump 2>/dev/null | tail -1)"
if [ -n "$DEXDUMP" ]; then
  mkdir -p "$OUT/dexdump_out"
  for d in "$DEXTMP"/classes*.dex; do [ -f "$d" ] || continue; "$DEXDUMP" -d "$d" > "$OUT/dexdump_out/$(basename "$d" .dex).txt" 2>/dev/null || true; done
  echo "  -> $OUT/dexdump_out"
else skip dexdump "Android build-tools"; fi

# 6. strings → strings_out/urls.txt  (URLs from dex + native libs)
step "strings (urls)"
mkdir -p "$OUT/strings_out"; TMPLIB="$OUT/.lib"; rm -rf "$TMPLIB"; mkdir -p "$TMPLIB"
unzip -o -j "$APK" 'lib/*/lib*.so' -d "$TMPLIB" >/dev/null 2>&1 || true
{ strings -a "$DEXTMP"/classes*.dex 2>/dev/null; strings -a "$TMPLIB"/*.so 2>/dev/null; } \
  | grep -aoiE 'https?://[a-z0-9._~:/?#@!$&()*+,;=%-]+' | sort -u > "$OUT/strings_out/urls.txt" || true
echo "  -> $OUT/strings_out/urls.txt ($(wc -l < "$OUT/strings_out/urls.txt" 2>/dev/null | tr -d ' ') urls)"

# 7. apkleaks → apkleaks_out/apkleaks.json  (optional secrets/endpoints)
step "apkleaks"
if have apkleaks; then mkdir -p "$OUT/apkleaks_out"; apkleaks -f "$APK" -o "$OUT/apkleaks_out/apkleaks.json" >/dev/null 2>&1 && echo "  -> $OUT/apkleaks_out/apkleaks.json"; else skip apkleaks "pip install apkleaks (optional)"; fi

rm -rf "$DEXTMP" "$TMPLIB"
# manifest of produced outputs
( cd "$OUT" && ls -d *_out 2>/dev/null ) > "$OUT/MANIFEST.txt" 2>/dev/null || true
step "done"; echo "outputs in: $OUT"; sed 's/^/  - /' "$OUT/MANIFEST.txt" 2>/dev/null || true
echo "NOTE: *_out/ holds decompiled target code — do not commit it (see .gitignore)."
