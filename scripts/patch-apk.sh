#!/usr/bin/env bash
# patch-apk.sh <cmd> ...   static APK patch / rebuild / re-sign / install (Frida-independent).
#   decompile <apk> [dir]   apktool d  -> dir (edit smali by hand)
#   build <dir> [out.apk]    apktool b  + zipalign + sign  -> installable apk
#   sign <apk> [out.apk]     zipalign + apksigner (debug keystore, auto-created)
#   depin <apk>              apk-mitm: auto de-pin + netsec-config + resign (needs npx)
#   find-root <dir>          grep smali for root/pinning/JB patterns to patch
#   install <apk>            adb install -r
# Common smali patches: isRooted()/checkForSu()  -> `const/4 v0, 0x0` + `return v0`;
#   null the OkHttp CertificatePinner; RN dev-mode: getUseDeveloperSupport() -> return 0x1.
set -uo pipefail
BT=$(ls -d "$HOME"/Library/Android/sdk/build-tools/* 2>/dev/null | sort -V | tail -1)
APKSIGNER="$BT/apksigner"; ZIPALIGN="$BT/zipalign"
have(){ command -v "$1" >/dev/null 2>&1; }
ks(){ local KS="$HOME/.android/debug.keystore"; mkdir -p "$(dirname "$KS")"
  [ -f "$KS" ] || keytool -genkeypair -v -keystore "$KS" -storepass android -keypass android \
     -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
     -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1
  printf '%s' "$KS"; }
do_sign(){ local apk="$1" out="${2:-${1%.apk}-signed.apk}"; local KS; KS=$(ks); local A="$apk"
  [ -x "$ZIPALIGN" ] && "$ZIPALIGN" -f -p 4 "$apk" "${apk%.apk}-al.apk" >/dev/null 2>&1 && A="${apk%.apk}-al.apk"
  "$APKSIGNER" sign --ks "$KS" --ks-pass pass:android --ks-key-alias androiddebugkey \
     --key-pass pass:android --out "$out" "$A" && echo "[+] signed: $out"; }
cmd="${1:-}"; shift || true
case "$cmd" in
  decompile) have apktool || { echo "brew install apktool"; exit 1; }
             apktool d -f "${1:?apk}" -o "${2:-${1%.apk}-src}"; echo "edit smali in ${2:-${1%.apk}-src}";;
  build) apktool b "${1:?dir}" -o "${2:-rebuilt.apk}" && do_sign "${2:-rebuilt.apk}" "${2:-rebuilt.apk}";;
  sign)  do_sign "${1:?apk}" "${2:-}";;
  depin) have npx || { echo "need npx for apk-mitm"; exit 1; }; npx -y apk-mitm "${1:?apk}";;
  find-root) grep -rlE 'isRooted|RootBeer|CertificatePinner|checkForSu|Cydia|detectRoot|SafetyNet|getUseDeveloperSupport' "${1:?dir}" 2>/dev/null | head -40;;
  install) adb install -r "${1:?apk}";;
  *) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 2;;
esac
