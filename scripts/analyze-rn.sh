#!/usr/bin/env bash
# analyze-rn.sh <app.apk|app.xapk> [OUTDIR=./out]
# Reverse a React Native app. Detects Hermes vs JSC and routes:
#   Hermes -> hermes-dec (hbc-decompiler/-disassembler) + hbctool  -> hermes_out/, hbctool_out/
#   JSC    -> react-native-decompiler + js-beautify                -> rndecompiler_out/, jsbeautify_out/
#   install: scripts/install-tools.sh --stack rn
set -uo pipefail

APK="${1:-}"; OUT="${2:-./out}"
[ -n "$APK" ] && [ -f "$APK" ] || { echo "usage: $0 <app.apk|xapk> [OUTDIR]"; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
have(){ command -v "$1" >/dev/null 2>&1; }
step(){ printf '\n\033[36m==> %s\033[0m\n' "$*"; }
skip(){ printf '\033[33m--  %s\033[0m\n' "$*"; }

step "detect stack"; sh "$HERE/detect-stack.sh" "$APK" | tee "$OUT/detect.txt" || true

# 1. extract the JS bundle(s)
step "extract JS bundle"
BUN="$OUT/.bundle"; rm -rf "$BUN"; mkdir -p "$BUN"
unzip -o -j "$APK" 'assets/index.android.bundle' 'assets/*.bundle' -d "$BUN" >/dev/null 2>&1 || true
# xapk / bundle: also look inside base split
if ! ls "$BUN"/*.bundle >/dev/null 2>&1; then
  TMPX="$OUT/.xapk"; rm -rf "$TMPX"; mkdir -p "$TMPX"
  unzip -o -j "$APK" '*base*.apk' '*.apk' -d "$TMPX" >/dev/null 2>&1 || true
  for a in "$TMPX"/*.apk; do [ -f "$a" ] && unzip -o -j "$a" 'assets/index.android.bundle' 'assets/*.bundle' -d "$BUN" >/dev/null 2>&1 || true; done
fi
BUNDLE="$(ls "$BUN"/index.android.bundle "$BUN"/*.bundle 2>/dev/null | head -1)"
[ -n "$BUNDLE" ] || { skip "no *.bundle found — pass the apk/xapk containing assets/index.android.bundle"; exit 1; }
echo "  bundle: $(basename "$BUNDLE") ($(du -h "$BUNDLE" | cut -f1))"

# 2. Hermes or JSC?  (libhermes.so, or Hermes magic bytes c6 1f bc 03)
IS_HERMES=0
unzip -l "$APK" 2>/dev/null | grep -qi 'libhermes\.so' && IS_HERMES=1
head -c 4 "$BUNDLE" | xxd 2>/dev/null | grep -qiE 'c61f bc03|c603 191f' && IS_HERMES=1

if [ "$IS_HERMES" = 1 ]; then
  echo "  engine: Hermes (bytecode)"
  # hermes-dec: hbc-decompiler / hbc-disassembler
  step "hermes-dec"
  if have hbc-decompiler || have hbc-disassembler; then
    mkdir -p "$OUT/hermes_out"
    have hbc-disassembler && hbc-disassembler "$BUNDLE" "$OUT/hermes_out/disasm.hasm" >/dev/null 2>&1 && echo "  -> hermes_out/disasm.hasm" || true
    have hbc-decompiler   && hbc-decompiler   "$BUNDLE" "$OUT/hermes_out/decompiled.js" >/dev/null 2>&1 && echo "  -> hermes_out/decompiled.js" || true
  else skip "hermes-dec not found (pip install hermes-dec)"; fi
  step "hbctool"
  if have hbctool; then mkdir -p "$OUT/hbctool_out"; hbctool disasm "$BUNDLE" "$OUT/hbctool_out" >/dev/null 2>&1 && echo "  -> hbctool_out/ (instruction.hasm + metadata)" || skip "hbctool disasm failed (Hermes bytecode version mismatch — pin hbctool to the target's version)"; else skip "hbctool not found (pip install hbctool)"; fi
else
  echo "  engine: JSC / plain (minified JS)"
  step "react-native-decompiler"
  if have react-native-decompiler; then mkdir -p "$OUT/rndecompiler_out"; react-native-decompiler -i "$BUNDLE" -o "$OUT/rndecompiler_out" >/dev/null 2>&1 && echo "  -> rndecompiler_out/ (recovered modules)" || skip "react-native-decompiler failed"; else skip "react-native-decompiler not found (npm i -g react-native-decompiler)"; fi
  step "js-beautify"
  if have js-beautify; then mkdir -p "$OUT/jsbeautify_out"; js-beautify "$BUNDLE" > "$OUT/jsbeautify_out/pretty.js" 2>/dev/null && echo "  -> jsbeautify_out/pretty.js" || true; else skip "js-beautify not found (npm i -g js-beautify)"; fi
fi

# 3. urls from the bundle
step "strings (urls)"
mkdir -p "$OUT/strings_out"
strings -a "$BUNDLE" 2>/dev/null | grep -aoiE 'https?://[a-z0-9._~:/?#@!$&()*+,;=%-]+' | sort -u > "$OUT/strings_out/urls.txt" || true
echo "  -> strings_out/urls.txt ($(wc -l < "$OUT/strings_out/urls.txt" 2>/dev/null | tr -d ' ') urls)"

rm -rf "$BUN" "$OUT/.xapk" 2>/dev/null
( cd "$OUT" && ls -d *_out 2>/dev/null ) > "$OUT/MANIFEST.txt" 2>/dev/null || true
step "done"; echo "outputs in: $OUT"; sed 's/^/  - /' "$OUT/MANIFEST.txt" 2>/dev/null || true
echo "NOTE: *_out/ holds reversed target code — do not commit it."
