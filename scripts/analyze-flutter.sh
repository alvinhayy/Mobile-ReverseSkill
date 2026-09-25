#!/usr/bin/env bash
# analyze-flutter.sh <app.apk|app.xapk> [OUTDIR=./out]
# Reverse a Flutter (Dart AOT) app: r2flutter metadata + blutter pseudo-source.
# Needs the arm64 libapp.so + libflutter.so (usually in the arm64 split / xapk).
#   install: scripts/install-tools.sh --stack flutter   (r2flutter, blutter, reflutter)
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

# 2. r2flutter -> structured Dart AOT metadata (static; does not execute the app)
step "r2flutter"
R2FLUTTER=""
if have r2flutter; then
  R2FLUTTER="$(command -v r2flutter)"
else
  for d in "${R2FLUTTER_HOME:-}" "$HOME/tools/r2flutter"; do
    [ -n "$d" ] && [ -x "$d/bin/r2flutter" ] && R2FLUTTER="$d/bin/r2flutter" && break
  done
fi
if [ -n "$R2FLUTTER" ]; then
  R2F_OUT="$OUT/r2flutter_out"
  R2F_LOG="$R2F_OUT/run.log"
  mkdir -p "$R2F_OUT"
  : > "$R2F_LOG"
  echo "  using $R2FLUTTER ($("$R2FLUTTER" -V 2>/dev/null || echo 'version unknown'))"
  r2f_dump(){
    local name="$1"; shift
    printf '[%s] %s %s %s\n' "$(date -u +%FT%TZ)" "$R2FLUTTER" "$*" "$LIBDIR/libapp.so" >> "$R2F_LOG"
    if "$R2FLUTTER" "$@" "$LIBDIR/libapp.so" > "$R2F_OUT/$name.tmp" 2>> "$R2F_LOG"; then
      mv "$R2F_OUT/$name.tmp" "$R2F_OUT/$name"
      echo "  -> $R2F_OUT/$name"
    else
      rm -f "$R2F_OUT/$name.tmp"
      skip "r2flutter $* failed — see $R2F_LOG"
    fi
  }
  r2f_dump header.json -jH
  r2f_dump functions.json -jf
  r2f_dump classes.json -jc
  r2f_dump types.json -jT
  r2f_dump strings.json -jz
  r2f_dump xrefs.json -jx
  r2f_dump sbom.json -jS
else
  skip "r2flutter not found — install with scripts/install-tools.sh --stack flutter"
fi

# 3. blutter -> blutter_out/ (asm/, blutter_frida.js, objs.txt, pp.txt)
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

# 4. flutter_assets (pubspec, fonts, images, kernel_blob if debug)
step "flutter_assets"
mkdir -p "$OUT/assets_out"
unzip -o "$APK" 'assets/flutter_assets/*' -d "$OUT/assets_out" >/dev/null 2>&1 || true
[ -d "$OUT/assets_out/assets/flutter_assets" ] && echo "  -> $OUT/assets_out" || skip "no flutter_assets in this apk (often in base apk)"

# 5. reFlutter (dynamic): repackage for traffic interception / snapshot dump — optional, interactive
step "reFlutter (dynamic, optional)"
if have reflutter; then echo "  run manually:  reflutter \"$APK\"   # patches APK; then resign & install"; else skip "pip install reflutter (optional)"; fi

rm -rf "$LIBDIR" "$OUT/.xapk" 2>/dev/null
( cd "$OUT" && ls -d *_out 2>/dev/null ) > "$OUT/MANIFEST.txt" 2>/dev/null || true
step "done"; echo "outputs in: $OUT"; sed 's/^/  - /' "$OUT/MANIFEST.txt" 2>/dev/null || true
echo "NOTE: *_out/ holds reversed target code — do not commit it."
