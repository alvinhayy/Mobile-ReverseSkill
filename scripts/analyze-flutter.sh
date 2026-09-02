#!/usr/bin/env bash
# analyze-flutter.sh <app.apk|app.xapk> [OUTDIR=./out]
# Reverse a Flutter (Dart AOT) app: blutter -> blutter_out/ ; note reFlutter for dynamic.
# Needs the arm64 libapp.so + libflutter.so (usually in the arm64 split / xapk).
#   install: scripts/install-tools.sh --stack flutter   (blutter, reflutter)
set -uo pipefail

APK="${1:-}"; OUT="${2:-./out}"
[ -n "$APK" ] && [ -f "$APK" ] || { echo "usage: $0 <app.apk|xapk> [OUTDIR]"; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
have(){ command -v "$1" >/dev/null 2>&1; }
step(){ printf '\n\033[36m==> %s\033[0m\n' "$*"; }
skip(){ printf '\033[33m--  %s\033[0m\n' "$*"; }

# 0. confirm Flutter
step "detect stack"; sh "$HERE/detect-stack.sh" "$APK" | tee "$OUT/detect.txt" || true
grep -qi flutter "$OUT/detect.txt" || skip "not detected as Flutter — continuing anyway"

# 1. gather libapp.so + libflutter.so (arm64 preferred) from the apk/xapk (may nest split apks)
step "extract Dart AOT libs"
LIBDIR="$OUT/.flutterlibs"; rm -rf "$LIBDIR"; mkdir -p "$LIBDIR"
extract_libs(){ unzip -o -j "$1" 'lib/arm64-v8a/libapp.so' 'lib/arm64-v8a/libflutter.so' -d "$LIBDIR" >/dev/null 2>&1 || true; }
extract_libs "$APK"
if [ ! -f "$LIBDIR/libapp.so" ]; then
  # xapk / bundle: pull config.arm64_v8a.apk then extract from it
  TMPX="$OUT/.xapk"; rm -rf "$TMPX"; mkdir -p "$TMPX"
  unzip -o -j "$APK" '*config.arm64_v8a.apk' -d "$TMPX" >/dev/null 2>&1 || true
  for a in "$TMPX"/*.apk; do [ -f "$a" ] && extract_libs "$a"; done
fi
if [ ! -f "$LIBDIR/libapp.so" ]; then
  skip "libapp.so (arm64) not found — pass the arm64 split or the .xapk that contains lib/arm64-v8a/"
  exit 1
fi
echo "  libapp.so: $(du -h "$LIBDIR/libapp.so" | cut -f1)$( [ -f "$LIBDIR/libflutter.so" ] && echo ', libflutter.so ok' )"

# 2. blutter -> blutter_out/ (asm/, blutter_frida.js, objs.txt, pp.txt)
step "blutter"
BLUTTER=""
for d in "${BLUTTER_HOME:-}" "$HOME/blutter" "$HOME/tools/blutter" /opt/blutter ./blutter; do
  [ -n "$d" ] && [ -f "$d/blutter.py" ] && BLUTTER="$d/blutter.py" && break
done
if [ -n "$BLUTTER" ] && have python3; then
  echo "  using $BLUTTER (first run builds dartvm — may take a while)"
  python3 "$BLUTTER" "$LIBDIR" "$OUT/blutter_out" && echo "  -> $OUT/blutter_out (asm/, blutter_frida.js, objs.txt, pp.txt)"
else
  skip "blutter not found — clone/build it: scripts/install-tools.sh --stack flutter (sets \$BLUTTER_HOME)"
fi

# 3. flutter_assets (pubspec, fonts, images, kernel_blob if debug)
step "flutter_assets"
mkdir -p "$OUT/assets_out"
unzip -o "$APK" 'assets/flutter_assets/*' -d "$OUT/assets_out" >/dev/null 2>&1 || true
[ -d "$OUT/assets_out/assets/flutter_assets" ] && echo "  -> $OUT/assets_out" || skip "no flutter_assets in this apk (often in base apk)"

# 4. reFlutter (dynamic): repackage for traffic interception / snapshot dump — optional, interactive
step "reFlutter (dynamic, optional)"
if have reflutter; then echo "  run manually:  reflutter \"$APK\"   # patches APK; then resign & install"; else skip "pip install reflutter (optional)"; fi

rm -rf "$LIBDIR" "$OUT/.xapk" 2>/dev/null
( cd "$OUT" && ls -d *_out 2>/dev/null ) > "$OUT/MANIFEST.txt" 2>/dev/null || true
step "done"; echo "outputs in: $OUT"; sed 's/^/  - /' "$OUT/MANIFEST.txt" 2>/dev/null || true
echo "NOTE: *_out/ holds reversed target code — do not commit it."
