# Android attack surface & IPC testing

Authorized targets only. Enumerate first, then probe exported components, deep links, and local
storage ("loot").

## Enumerate
```bash
scripts/attack-surface.sh <apk> out/     # -> out/attack-surface.txt
```
Lists exported activities/services/receivers/providers, deep-link schemes+hosts (with a ready
`am start` line), and risky flags (`debuggable`, `allowBackup`, `usesCleartextTraffic`,
`networkSecurityConfig`). Reuses `analyze-android.sh`'s `apktool_out/AndroidManifest.xml`.

## Probe exported components
```bash
# deep link (exported activity via VIEW intent)
adb shell am start -a android.intent.action.VIEW -d "scheme://host/path"
# start an exported activity directly / with extras
adb shell am start -n <pkg>/<activity> --es key value
# fire an exported receiver
adb shell am broadcast -n <pkg>/<receiver> -a <action> --es key value
# start an exported service
adb shell am startservice -n <pkg>/<service>
# read/query an exported content provider (IDOR / SQLi surface)
adb shell content query --uri content://<authority>/<path>
adb shell content query --uri content://<authority>/../  # path traversal test
```
**drozer** automates this end-to-end:
```
dz> run app.package.attacksurface <pkg>
dz> run app.activity.info -a <pkg>        # + app.service.info / app.broadcast.info / app.provider.info
dz> run app.provider.finduri <pkg>        # then scanner.provider.injection / .traversal
dz> run app.activity.start --component <pkg> <activity>
```

## Loot — local storage
```bash
adb shell run-as <pkg> ls -R /data/data/<pkg>          # (debuggable) or via root
# high-value: shared_prefs/*.xml, databases/*.db (+ RN AsyncStorage), files/, cache/http-cache
adb shell run-as <pkg> cat /data/data/<pkg>/shared_prefs/*.xml
```
`cache/http-cache` often holds cached GET request/response + OAuth tokens; SharedPrefs/SQLite hold
plaintext session data. Pull DBs and open with `sqlite3`.

_Sources: payatu (attack-surface static analysis), tanprathan/nobox910 cheatsheets, drozer wiki._
