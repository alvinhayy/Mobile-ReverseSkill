#!/usr/bin/env bash
# merge-apks.sh <input> [out.apk]
# Merge split APKs / .xapk / .apks / .apkm into ONE installable, signed APK (via REAndroid/APKEditor).
# Needed before patch-apk / reFlutter / apk-mitm on split targets ("App not installed" otherwise).
set -uo pipefail
IN="${1:?usage: merge-apks.sh <dir|xapk|apks|apkm|apk> [out.apk]}"
OUT="${2:-merged-signed.apk}"
HERE="$(cd "$(dirname "$0")" && pwd)"
command -v java >/dev/null 2>&1 || { echo "need java"; exit 1; }
JAR="${APKEDITOR_JAR:-$HOME/tools/APKEditor.jar}"
if [ ! -f "$JAR" ]; then
  mkdir -p "$(dirname "$JAR")"
  URL=$(curl -fsSL https://api.github.com/repos/REAndroid/APKEditor/releases/latest 2>/dev/null \
        | grep -oE 'https://[^"]*APKEditor-[0-9.]*\.jar' | head -1)
  [ -n "$URL" ] || { echo "could not resolve APKEditor download URL"; exit 1; }
  echo "[*] downloading APKEditor -> $JAR"; curl -fL "$URL" -o "$JAR"
fi
TMP=$(mktemp -d); MERGED="$TMP/merged.apk"
echo "[*] merging: $IN"
java -jar "$JAR" m -i "$IN" -o "$MERGED" -f || { echo "APKEditor merge failed"; rm -rf "$TMP"; exit 1; }
"$HERE/patch-apk.sh" sign "$MERGED" "$OUT"
rm -rf "$TMP"
echo "[+] merged + signed: $OUT   (adb install -r \"$OUT\")"
