#!/usr/bin/env bash
# analyze-ios.sh <app.ipa> [OUTDIR=./out]
# Static-analyze an iOS app: Info.plist, entitlements, Mach-O (otool/nm), ObjC headers
# (class-dump), Swift symbol demangling. Flags FairPlay-encrypted binaries (need on-device decrypt).
#   install: scripts/install-tools.sh --stack ios   (class-dump; otool/nm/codesign/plutil via Xcode CLT)
set -uo pipefail

IPA="${1:-}"; OUT="${2:-./out}"
[ -n "$IPA" ] && [ -f "$IPA" ] || { echo "usage: $0 <app.ipa> [OUTDIR]"; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
have(){ command -v "$1" >/dev/null 2>&1; }
step(){ printf '\n\033[36m==> %s\033[0m\n' "$*"; }
skip(){ printf '\033[33m--  %s\033[0m\n' "$*"; }

step "detect stack"; sh "$HERE/detect-stack.sh" "$IPA" | tee "$OUT/detect.txt" || true

# 1. unpack IPA, locate the .app and its Mach-O
step "unpack IPA"
APPROOT="$OUT/.ipa"; rm -rf "$APPROOT"; mkdir -p "$APPROOT"
unzip -oq "$IPA" -d "$APPROOT" || true
APP="$(ls -d "$APPROOT"/Payload/*.app 2>/dev/null | head -1)"
[ -n "$APP" ] || { skip "no Payload/*.app in IPA"; exit 1; }
INFO="$APP/Info.plist"
EXE="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$INFO" 2>/dev/null || plutil -extract CFBundleExecutable raw "$INFO" 2>/dev/null)"
BIN="$APP/$EXE"
echo "  app: $(basename "$APP")  exe: $EXE"

# 2. Info.plist -> plist_out/Info.json  (+ URL schemes, ATS)
step "Info.plist"
mkdir -p "$OUT/plist_out"
plutil -convert json -o "$OUT/plist_out/Info.json" "$INFO" 2>/dev/null && echo "  -> plist_out/Info.json" || cp "$INFO" "$OUT/plist_out/Info.plist"

# 3. entitlements + signing -> codesign_out/
step "codesign / entitlements"
mkdir -p "$OUT/codesign_out"
codesign -d --entitlements :- --xml "$BIN" > "$OUT/codesign_out/entitlements.plist" 2>/dev/null && echo "  -> codesign_out/entitlements.plist" || skip "codesign entitlements unavailable"
codesign -dvvv "$BIN" > "$OUT/codesign_out/signing.txt" 2>&1 || true

# 4. Mach-O: arch, linked libs, load commands -> otool_out/  ; encryption check
step "otool"
mkdir -p "$OUT/otool_out"
if have otool; then
  otool -hv  "$BIN" > "$OUT/otool_out/header.txt"   2>/dev/null || true
  otool -L   "$BIN" > "$OUT/otool_out/linked.txt"   2>/dev/null || true
  otool -l   "$BIN" > "$OUT/otool_out/loadcmds.txt" 2>/dev/null || true
  CRYPTID="$(grep -A4 LC_ENCRYPTION_INFO "$OUT/otool_out/loadcmds.txt" 2>/dev/null | awk '/cryptid/{print $2; exit}')"
  echo "  -> otool_out/  (cryptid=${CRYPTID:-0})"
  [ "${CRYPTID:-0}" != 0 ] && skip "BINARY IS FAIRPLAY-ENCRYPTED (cryptid=$CRYPTID) — class-dump/nm give garbage. Decrypt on a jailbroken device first (frida-ios-dump / bagbak)."
else skip "otool not found (xcode-select --install)"; fi

# 5. symbols (nm) + Swift demangle
step "nm / swift-demangle"
mkdir -p "$OUT/nm_out"
if have nm; then nm -m "$BIN" > "$OUT/nm_out/symbols.txt" 2>/dev/null && echo "  -> nm_out/symbols.txt"; else skip "nm not found"; fi
if have swift-demangle && [ -f "$OUT/nm_out/symbols.txt" ]; then
  mkdir -p "$OUT/swiftdemangle_out"; swift-demangle < "$OUT/nm_out/symbols.txt" > "$OUT/swiftdemangle_out/demangled.txt" 2>/dev/null && echo "  -> swiftdemangle_out/demangled.txt"
elif xcrun --find swift-demangle >/dev/null 2>&1 && [ -f "$OUT/nm_out/symbols.txt" ]; then
  mkdir -p "$OUT/swiftdemangle_out"; xcrun swift-demangle < "$OUT/nm_out/symbols.txt" > "$OUT/swiftdemangle_out/demangled.txt" 2>/dev/null && echo "  -> swiftdemangle_out/demangled.txt (xcrun)"
else skip "swift-demangle not found (Xcode)"; fi

# 6. ObjC headers (class-dump)
step "class-dump"
if have class-dump; then mkdir -p "$OUT/classdump_out"; class-dump -H -o "$OUT/classdump_out" "$BIN" >/dev/null 2>&1 && echo "  -> classdump_out/ (ObjC headers)" || skip "class-dump produced nothing (Swift-only or encrypted binary)"; else skip "class-dump not found (brew install class-dump)"; fi

# 7. urls
step "strings (urls)"
mkdir -p "$OUT/strings_out"
strings -a "$BIN" 2>/dev/null | grep -aoiE 'https?://[a-z0-9._~:/?#@!$&()*+,;=%-]+' | sort -u > "$OUT/strings_out/urls.txt" || true
echo "  -> strings_out/urls.txt ($(wc -l < "$OUT/strings_out/urls.txt" 2>/dev/null | tr -d ' ') urls)"

rm -rf "$APPROOT" 2>/dev/null
( cd "$OUT" && ls -d *_out 2>/dev/null ) > "$OUT/MANIFEST.txt" 2>/dev/null || true
step "done"; echo "outputs in: $OUT"; sed 's/^/  - /' "$OUT/MANIFEST.txt" 2>/dev/null || true
echo "NOTE: *_out/ holds reversed target data — do not commit it."
