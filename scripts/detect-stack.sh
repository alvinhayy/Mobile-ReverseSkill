#!/usr/bin/env bash
# detect-stack.sh <app.apk|app.xapk|app.aab|app.ipa>
# Identify the mobile app framework from package contents. Prints stack(s) + evidence.
set -uo pipefail
APP="${1:-}"
[ -n "$APP" ] && [ -f "$APP" ] || { echo "usage: $0 <apk|xapk|aab|ipa>"; exit 2; }

# portable listing: `unzip -l` names, one match per line
L="$(unzip -l "$APP" 2>/dev/null)"
[ -n "$L" ] || { echo "error: cannot list $APP (unzip failed)"; exit 1; }
hit(){ printf '%s\n' "$L" | grep -qiE "$1"; }
found=0
say(){ printf '  \033[32m▸\033[0m %-14s %s\n' "$1" "$2"; found=1; }

echo "stack detection: $APP"
case "$APP" in
  *.ipa)
    hit 'Flutter\.framework|App\.framework'            && say flutter      "Flutter.framework"
    hit 'hermes\.framework|main\.jsbundle'             && say react-native "hermes / jsbundle"
    hit 'UnityFramework\.framework'                    && say unity        "UnityFramework"
    hit '\.app/.*\.dll|libmonosgen'                    && say xamarin      ".NET assemblies"
    [ $found = 0 ] && say native "Swift/ObjC Mach-O (no cross-platform markers)"
    ;;
  *)  # apk / xapk / aab (zip of dex + lib)
    hit 'libflutter\.so|flutter_assets|libapp\.so'     && say flutter      "libflutter.so / flutter_assets"
    hit 'libhermes\.so'                                && say react-native "Hermes (libhermes.so)"
    hit 'index\.android\.bundle' && ! hit 'libhermes\.so' && say react-native "JSC bundle (index.android.bundle)"
    hit 'libil2cpp\.so|global-metadata\.dat'           && say unity        "IL2CPP (libil2cpp.so / global-metadata.dat)"
    hit 'bin/Data/Managed/.*\.dll'                     && say unity        "Unity Mono (.dll)"
    hit 'assemblies\.blob|assemblies/|libmonodroid\.so' && say xamarin     ".NET/Mono (assemblies)"
    hit 'assets/www/|assets/public/|capacitor\.config' && say cordova      "WebView (Cordova/Capacitor/Ionic)"
    hit 'libNativeScript\.so'                          && say nativescript "libNativeScript.so"
    [ $found = 0 ] && say native "Kotlin/Java (no cross-platform markers)"
    ;;
esac
