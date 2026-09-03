#!/usr/bin/env bash
# attack-surface.sh <app.apk> [out]
# Enumerate the Android IPC/attack surface from the DECODED manifest (apktool): exported
# activities/services/receivers/providers, deep-link schemes+hosts, risky flags. Complements
# analyze-android.sh. Reuses <out>/apktool_out/AndroidManifest.xml if present. -> attack-surface.txt
set -uo pipefail
APK="${1:?usage: attack-surface.sh <app.apk> [out]}"; OUT="${2:-./out}"; mkdir -p "$OUT"
MAN="$OUT/apktool_out/AndroidManifest.xml"
if [ ! -f "$MAN" ]; then
  command -v apktool >/dev/null 2>&1 || { echo "need apktool (brew install apktool)"; exit 1; }
  TMP="$OUT/.man"; rm -rf "$TMP"; apktool d -s -f "$APK" -o "$TMP" >/dev/null 2>&1 || true
  MAN="$TMP/AndroidManifest.xml"
fi
[ -f "$MAN" ] || { echo "no AndroidManifest.xml"; exit 1; }
REPORT="$OUT/attack-surface.txt"
python3 - "$APK" "$MAN" > "$REPORT" <<'PY'
import sys,xml.etree.ElementTree as ET
apk,man=sys.argv[1],sys.argv[2]
A='{http://schemas.android.com/apk/res/android}'
t=ET.parse(man); r=t.getroot()
def a(e,n): return e.get(A+n)
app=r.find('application')
print("# Attack surface —",apk)
print("\n## Risky flags")
if app is not None:
    for f in ('debuggable','allowBackup','usesCleartextTraffic','networkSecurityConfig'):
        v=a(app,f)
        if v is not None: print(f"  {f} = {v}")
for tag in ('activity','activity-alias','service','receiver','provider'):
    rows=[]
    for e in (app.iter(tag) if app is not None else []):
        exp=a(e,'exported'); name=a(e,'name'); perm=a(e,'permission')
        ifs=e.findall('intent-filter')
        schemes=sorted({a(d,'scheme') for f in ifs for d in f.findall('data') if a(d,'scheme')})
        hosts=sorted({a(d,'host') for f in ifs for d in f.findall('data') if a(d,'host')})
        actions=sorted({a(ac,'name') for f in ifs for ac in f.findall('action') if a(ac,'name')})
        # exported if explicitly true, or implicitly (has intent-filter and not exported=false)
        is_exp = exp=='true' or (exp is None and ifs)
        if is_exp: rows.append((name,exp,perm,schemes,hosts,actions))
    print(f"\n## Exported {tag} ({len(rows)})")
    for name,exp,perm,schemes,hosts,actions in rows:
        line=f"  {name}  exported={exp}"
        if perm: line+=f"  perm={perm}"
        if schemes: line+=f"  schemes={schemes}"
        if hosts: line+=f"  hosts={hosts}"
        print(line)
        if actions and any('VIEW' in x for x in actions) and schemes:
            print(f"      deeplink e.g.: adb shell am start -a android.intent.action.VIEW -d \"{schemes[0]}://{(hosts[0] if hosts else 'host')}/\"")
PY
echo "[+] attack surface -> $REPORT"; sed -n '1,45p' "$REPORT"
