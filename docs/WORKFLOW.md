# CLAUDE.md — Mobile-reverse

Panduan konteks untuk sesi Claude berikutnya di repo ini. Istilah teknis, path, dan perintah
apa adanya; prosa dalam bahasa Indonesia.

> **Catatan redaksi.** Identitas target (nama app/klien, package, versi, vendor proteksi) di
> **redact** di dokumen ini. Placeholder: `<TARGET>` = nama/entitas target, `<TARGET_PKG>` =
> package, `<target>/` = folder app di repo, `<TARGET>.apk` = base APK. Nama folder/berkas
> **fisik di disk mungkin masih memuat identitas** — cek dengan `ls`; ganti nama fisik hanya
> bila diminta. Jangan tulis identitas asli kembali ke file ini.

---

## 1. Apa ini & aturan main

Security assessment (reverse engineering + dynamic analysis) sebuah **aplikasi Flutter Android**
milik klien (identitas di-redact). **Authorized engagement** — catat entitas/kontrak/bounty
pemberi otorisasi di laporan (bukan di file ini) sebelum publikasi.

**Batas cakupan yang WAJIB dijaga (default):**
- Kerjakan **analisis biner offline** atas artefak yang sudah ada di repo + dynamic analysis
  di **emulator/device lokal**.
- **Jangan** kirim traffic serangan ke **server/infrastruktur produksi target** (API live,
  endpoint) tanpa konfirmasi otorisasi eksplisit dari user untuk sesi itu. Fuzzing/pengujian
  dilakukan pada komponen native lokal, bukan backend.
- Kalau ragu soal target yang menyentuh infrastruktur pihak ketiga, tanya dulu.

## 2. Target singkat

- **Flutter app**: logika utama di `libapp.so` (Dart AOT snapshot, ~24 MB) + `libflutter.so`.
  Kelas Java/Kotlin minim — banyak simbol TIDAK ada di `classes.dex`.
- Package `<TARGET_PKG>`, versi `[redacted]`, min SDK 26, target SDK 36.
- **Lapisan proteksi** (status di `runtime/README.md`):
  - Commercial **DEX packer + RASP** — packer defeated statically; RASP **tertembus
    2026-08-02** (blocker sebenarnya: `frida` CLI keluar saat stdin EOF, bukan agent-nya).
  - **Java2C VMP** (`libappsec.so`) — dikarakterisasi, tidak di-unwind (nilai rendah; payload
    asli = Dart snapshot yang sudah dump).
  - **Attestation + pinning SDK** (`libapproov.so`) — **tidak** defeatable sisi klien (temuan
    yang benar, bukan kegagalan).
  - TLS Flutter/BoringSSL — belum terverifikasi (`runtime/flutter-tls*.js`).
- **Native libs** ada di split arm64 `config.arm64_v8a.apk` (bukan di base apk). Menarik untuk
  memory-safety (library generik Google/AndroidX): `libbarhopper_v3.so` (ML Kit barcode/QR),
  `libnative-imagetranscoder.so` (JPEG/PNG/WebP Fresco), `libimage_processing_util_jni.so`
  (YUV CameraX), `libface_detector_v2_jni.so`.

## 3. Layout repo

| Path | Isi |
|---|---|
| `<TARGET>*.xapk` | XAPK asli |
| `*-flow-analysis.md` | Analisis alur app |
| `<target>/`, `splits/` | Split APK (base `<TARGET>.apk` + `config.*` per arch/lang). Native libs di `config.arm64_v8a.apk` |
| `runtime/` | Skrip **Frida** (RASP/TLS/emulator/attestation bypass) + `README.md` + `BYPASS-2026-08-02.md` |
| `fuzzing/` | Setup **AFL++** native fuzzing (lihat §5 + `fuzzing/README.md`) |
| `findings/` | Temuan bertanggal `findings/<slug>-<YYYY-MM-DD>/` |
| `tools/Mobile-Pentest-Setup/` | Script bikin AVD rooted anti-deteksi (KernelSU) — lihat §9 |
| `tools/uiautomator2-mcp/` | MCP untuk otomasi UI device |
| `.venv-frida/` | venv Python (frida CLI, python3.14) |
| `.mare-project.mareproj`, `.mare-out/` | Project MARE (mobile reverse) |

## 4. Environment & tooling

- Host: **macOS arm64** (Apple Silicon).
- Emulator: **arm64-v8a, API 36** (biasanya `emulator-5554`; user `shell` **tanpa root**, tapi
  `/data/local/tmp` bisa tulis+exec). **Sering tidak aktif** — nyalakan via §9.
- NDK: **r30-beta2** di `~/Library/Android/sdk/ndk/30.0.15729638` (prebuilt `darwin-x86_64`,
  jalan via Rosetta). Cross-compiler: `.../bin/aarch64-linux-android36-clang`.
- Terpasang: `docker`, `colima` (Linux container; **default mati** — `colima start` dulu),
  `apktool`, `baksmali`, `jadx`, `frida`, `adb`, `dexdump` (build-tools 36.0.0 di
  `~/Library/Android/sdk/build-tools/36.0.0/dexdump`).
- MCP aktif yang relevan: **uiautomator2** (otomasi device), **burp** (proxy/HTTP history),
  **claude-in-chrome**. (blender sering timeout — abaikan.)
- Scratchpad untuk file sementara: pakai direktori scratchpad sesi, bukan `/tmp`.

## 5. Native fuzzing (`fuzzing/`) — status & cara pakai

Sudah dibangun & tervalidasi sebagian. **Baca `fuzzing/README.md` sebelum lanjut.**

- **AFL++ 5.03a `afl-fuzz` di-cross-compile untuk Android arm64** → jalan di emulator
  (`/data/local/tmp/afl-fuzz`). `.so` = ELF bionic, jadi fuzzing **harus on-device**, bukan host.
- **Pipeline TERVALIDASI** lewat harness demo (bug tertanam) → AFL menemukan 4 crash (ASan).
  afl-fuzz + deteksi ASan/`libdislocator` on-device terbukti bekerja.
- **Harness barhopper BELUM valid — JANGAN percaya campaign "0 crash" sebelumnya.** Probe
  poison-pointer (`GetDirectBufferAddress`→`0x1`, tidak crash) membuktikan
  `recognizeBufferNative` **tidak pernah membaca buffer**: `createNative()` mengaktifkan
  **nol format barcode** → recognizer short-circuit. **Perbaikan wajib:**
  pakai `createNativeWithClientOptions(env, this, jbyteArray options)` dengan proto opsi yang
  mengaktifkan format, dan tambah ke stub `JNIEnv`: `GetByteArrayElements` (idx **184**,
  off `0x5c0`) + `GetArrayLength` (idx **171**, off `0x558`). Verifikasi ulang dengan probe
  poison-pointer: kalau sekarang **crash**, decoder baru benar-benar tereksekusi.
- **Coverage**: run saat ini **dumb mode** (`-n`, libs closed-source). Upgrade = **AFL++
  frida-mode**, yang **harus dibangun di kontainer Linux arm64** (Colima) — makefile-nya tak
  bisa cross-build dari macOS (memilih host `clang -target arm64-apple-macos`). Ref Quarkslab
  ada di README.

Perintah:
```bash
# rebuild semua artefak (afl-fuzz android, harness, libdislocator)
fuzzing/scripts/rebuild.sh
# jalankan campaign N detik (SETELAH harness diperbaiki)
adb push fuzzing/scripts/run_barhopper.sh /data/local/tmp/run_barhopper.sh
adb shell 'nohup sh /data/local/tmp/run_barhopper.sh 3600 >/data/local/tmp/bh/nohup.log 2>&1 &'
adb shell 'tail -1 /data/local/tmp/bh/out/plot_data'   # total_execs, saved_crashes
```

## 6. Runtime / Frida (`runtime/`)

Skrip bypass (`rasp-bypass.js`, `rasp-neutralise.js`, `flutter-tls*.js`, `approov-*.js`,
`emu-bypass.js`, `proc-spoof.js`, dll). Status terbaru & pelajaran di `runtime/README.md` dan
`runtime/BYPASS-2026-08-02.md`. **Gotcha penting:** jalankan agent lewat file/porta, jangan
`frida` CLI interaktif — CLI keluar saat stdin EOF dan itu yang dulu tampak seperti "RASP block".

## 7. Cara kerja yang diharapkan

- **Validasi temuan sebelum melaporkannya.** Untuk fuzzing: pakai positive control (mis. probe
  poison-pointer / under-alloc) untuk membuktikan harness benar-benar menjangkau kode target;
  hasil "0 crash" tak berarti apa-apa kalau parser tak pernah dijalankan. (Pelajaran 2026-08-27.)
- Untuk mengetahui signature fungsi native: **disassembly `.so`** (`llvm-objdump -d
  --disassemble-symbols=<sym>`) lebih andal daripada menebak — banyak kelas tak ada di dex.
  JNIEnv vtable: `index = offset/8` (mis. `0x730`→230 `GetDirectBufferAddress`).
- Simpan temuan ke `findings/<slug>-<YYYY-MM-DD>/` dan koreksi dokumen kalau ada hasil yang
  ternyata keliru (jangan biarkan klaim lama yang salah berdiri).
- **Jaga redaksi:** jangan tulis identitas asli target ke `CLAUDE.md`, laporan publik, atau
  memory. Detail identitas hanya di laporan engagement privat.
- Ada auto-memory di `~/.claude/projects/.../memory/`.

## 8. Skills yang dipakai

| Skill | Sumber | Untuk apa |
|---|---|---|
| **reverse-engineer** | gist `binsarjr/adbd5110cd78bbd09a1d9afc0f23c944` | Static analysis APK/IPA/web bundle → endpoints, secrets, permissions, flow, deception/honeypot. **Tersedia langsung** via tool Skill (`reverse-engineer`). Tools yang dirujuk: `apktool`, `jadx`, `dex2jar`, `strings`, `unzip`, Docker `cryptax/android-re`, `trufflehog`, `gitleaks`, `class-dump`, `otool`, `codesign`, `plutil`, `js-beautify`, `prettier`. |
| **afl-fuzzing** (`aflpp`) | `https://mcpmarket.com/tools/skills/afl-fuzzing` (juga `.../afl-security-fuzzing`) | Metodologi AFL++ greybox fuzzing. Halaman di balik Vercel JS-challenge (tak bisa di-fetch otomatis) — metodologinya **sudah diimplementasikan** di `fuzzing/` (lihat §5). |

**Install skill afl** (via [skillfish](https://www.npmjs.com/package/skillfish)):
```bash
npx skillfish add plurigrid/asi aflpp
```

## 9. Rooting AVD — pilih per arsitektur

**Mac (Apple Silicon / arm64) → KernelSU, repo `alvinhayy/Mobile-Pentest-Setup`** (ada lokal di
`tools/Mobile-Pentest-Setup/`). Bikin AVD rooted + spoof identitas + CA proxy sekali jalan.

```bash
cd tools/Mobile-Pentest-Setup
./create-avd.sh --name lab1 --api 36 --full            # build→root(KernelSU)→boot→grant→spoof→CA→proxy
#   --proxy burp|httptoolkit|all   (default: auto)
# atau bertahap:
./create-avd.sh --name lab1 --api 36
$ANDROID_HOME/emulator/emulator -avd lab1 -no-snapshot-load
./root-avd.sh --manager kernels/KernelSU-Next-manager.apk
./root-avd.sh --grant-shell         # grant root ke adb shell, otomatis (uiautomator, bukan tap koordinat)
./spoof-emu.sh                      # identitas device system-wide (system.prop KernelSU, post-fs-data)
./mount-ca.sh --user --persist      # CA proxy ke APEX trust store, bertahan reboot
./proxy.sh --connect                # arahkan traffic ke proxy (default host 10.0.2.2)
```
Tools wajib (mac): macOS Apple Silicon (script pakai BSD `sed -i ''`, `lsof`); Android SDK
(`platform-tools`, `emulator`, `cmdline-tools/latest`); system image
`system-images;android-36;google_apis_playstore;arm64-v8a` (auto-install); `python3`, `openssl`,
`curl`; KernelSU kernel + manager (bundled di `kernels/`, untuk API 36 — API lain butuh kernel
sesuai KMI image itu); Burp / HTTP Toolkit (opsional, hanya untuk intersepsi TLS).
Guardrail: nyalakan proxy **sebelum** pipeline (HTTP Toolkit hanya buka port saat app jalan).

**x86_64 → Magisk, repo `gitlab.com/newbit/rootAVD`** (patch ramdisk AVD dengan Magisk).

```bash
git clone https://gitlab.com/newbit/rootAVD.git && cd rootAVD
./rootAVD.sh ListAllAVDs                                              # daftar image + path ramdisk
./rootAVD.sh system-images/android-<API>/<tag>/x86_64/ramdisk.img    # patch → emulator reboot rooted
# lalu buka app Magisk untuk finalisasi; opsi lain: restore, FAKEBOOTIMG, GrantSU, InstallKernelModules
```
Tools wajib (x86_64): `bash`, `git`, Android SDK (`emulator`, `platform-tools`/adb) dengan
**system image x86_64 sudah ter-download** via `sdkmanager` dan AVD sudah dibuat; Magisk (di-handle
rootAVD). Mendukung image x86/x86_64/arm64-v8a.

## 10. Required tools (ringkas)

| Kategori | Tools |
|---|---|
| Android SDK | `adb`/platform-tools, `emulator`, `cmdline-tools/latest`, `sdkmanager`, `avdmanager`, `dexdump` (build-tools 36) |
| RE statis | `apktool`, `jadx`, `baksmali`, `dex2jar`, `strings`, `unzip`; (skill reverse-engineer) `trufflehog`, `gitleaks`, Docker `cryptax/android-re` |
| Native/fuzzing | NDK r30 (`aarch64-linux-android36-clang`, `llvm-objdump`, `llvm-nm`), AFL++ (di `fuzzing/AFLplusplus`), `cmake`, `make`, `clang` (host), `libdislocator` |
| Dynamic | `frida` (venv `.venv-frida`), `objection` (opsional), `uiautomator2` (MCP) |
| Rooting AVD | mac: `tools/Mobile-Pentest-Setup` (KernelSU); x86_64: `rootAVD` (Magisk) |
| Proxy/coverage | `docker` + `colima` (Linux container utk frida-mode build), Burp (MCP `burp`), HTTP Toolkit |
| Lain | `python3`, `openssl`, `curl`, `git` |

## 11. Dokumen rujukan

- `fuzzing/README.md` — laporan lengkap + koreksi validasi barhopper.
- `runtime/README.md`, `runtime/BYPASS-2026-08-02.md` — status lapisan proteksi.
- `*-flow-analysis.md` — alur app.
- `findings/*/SUMMARY.md`.
