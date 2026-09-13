# AFL++ Fuzzing — Target App (com.redacted.app)

Offline, coverage-oriented fuzzing of the app's **native components** (`.so`), run on a
local Android arm64 emulator. **No traffic is sent to TARGET infrastructure** — this analyses
binaries already present in the downloaded APK.

Host: macOS arm64 · Emulator: `emulator-5554` (arm64-v8a, API 36) · NDK r30-beta2 · AFL++ 5.03a

## What was built

| Artifact | Purpose |
|---|---|
| `AFLplusplus/afl-fuzz` | AFL++ fuzzer engine, **cross-compiled for Android arm64** (runs on the emulator) |
| `build/libdislocator.so` | AFL++ heap allocator that page-guards allocations, turning OOB into SIGSEGV (bug detector for closed-source libs with no ASan) |
| `harness/demo_parse.c` → `build/demo_parse` | Pipeline-validation harness with a *planted* stack overflow (ASan) |
| `harness/barhopper_harness.c` → `build/barhopper_harness` | Real harness for **`libbarhopper_v3.so`** (Google ML Kit barcode/QR recognizer) |
| `scripts/run_demo.sh`, `scripts/run_barhopper.sh` | On-device campaign launchers |

## Target selection (why barhopper)

The app is a Flutter app; native attack surface that processes **untrusted input** lives in
the arm64 split (`config.arm64_v8a.apk`):

- `libbarhopper_v3.so` — **ML Kit barcode/QR recognizer**. *Highest reachability*: a malicious
  QR/barcode scanned by the TARGET ticket scanner flows straight into `recognizeBufferNative`
  as a luminance buffer. **← primary target**
- `libnative-imagetranscoder.so` — Fresco JPEG/PNG/WebP decoder (functions registered
  dynamically; only `JNI_OnLoad` exported → needs offset-based harness).
- `libimage_processing_util_jni.so` — CameraX YUV→RGB (stride/integer-overflow surface).

## Harness technique (barhopper)

Reverse-engineered from disassembly of `libbarhopper_v3.so`:

- `createNative(JNIEnv*, jclass)` → allocates a 104-byte recognizer context. **No args, no
  ML model, no assets** — trivially constructible.
- `recognizeBufferNative(JNIEnv*, this, long ctx, int w, int h, ByteBuffer img, obj)` →
  reads the image via `JNIEnv->GetDirectBufferAddress` (vtable index **230**, offset `0x730`).

The harness calls the **real exported JNI functions** with a **stub `JNIEnv`** (a 400-entry
function-pointer table; index 230/231 return our fuzzed buffer + capacity, all other slots
return zeroed scratch so the rarely-reached result-delivery path doesn't NULL-deref).

**False-positive control:** width/height are **fixed** and the image buffer is allocated at
**exactly `W*H`** and guarded by `libdislocator`. With valid, self-consistent geometry, any
out-of-bounds access on a hostile image is a **real memory-safety bug**, not a harness artifact.

## Pipeline validation (proven)

`demo_parse` (ASan, planted stack-buffer-overflow) fuzzed on the emulator:
AFL found **4 crashing inputs** (`sig:06`, first at ~8 s / 1451 execs). See
`out/demo_crashes/` and `out/demo_asan_report.txt`. This confirms the full loop works
on-device: fork/exec, crash detection, corpus & crash saving.

## How to re-run

```bash
# (host) rebuild everything
./scripts/rebuild.sh

# (host) push + launch the barhopper campaign for N seconds
adb push scripts/run_barhopper.sh /data/local/tmp/run_barhopper.sh
adb shell 'nohup sh /data/local/tmp/run_barhopper.sh 3600 >/data/local/tmp/bh/nohup.log 2>&1 &'

# watch
adb shell 'cat /data/local/tmp/bh/out/fuzzer_stats | grep -E "execs|crash|run_time"'
adb shell 'ls /data/local/tmp/bh/out/crashes/'
```

## Limitations & recommended next steps

1. **Dumb mode (no coverage).** The on-device `afl-fuzz` runs blind (`-n`): `libbarhopper`
   is closed-source, so there is no compile-time instrumentation. Throughput is ~13 exec/s
   (each exec re-`dlopen`s barhopper and runs the recognizer). Barhopper is a hardened,
   billions-of-devices Google library — a short blind run is unlikely to find a crash.
2. **Add coverage → AFL++ frida-mode.** This is the correct upgrade for closed-source arm64
   libs. The `frida_mode` makefile targets a **Linux** build host, so cross-building it from
   macOS fails (`instrument.c` picks host `clang -target arm64-apple-macos`). Build it inside
   an **arm64 Linux container** (Colima is installed) using the Linux NDK, then push
   `afl-frida-trace.so` and run `afl-fuzz -O ...`. See:
   https://blog.quarkslab.com/android-greybox-fuzzing-with-afl-frida-mode.html
3. **Persistent mode** (100–1000× faster) needs an AFL-instrumented harness — pair with the
   frida-mode/Linux-container toolchain above.
4. **Better seeds:** feed real barcode/QR luminance frames as the starting corpus.
5. **Second target:** extend the same stub-JNIEnv technique to
   `libimage_processing_util_jni.so nativeConvertAndroid420ToABGR` (fix geometry, fuzz pixels).

## Campaign result — barhopper (this run)

| Metric | Value |
|---|---|
| Mode | dumb (`-n`), libdislocator preload |
| Duration | ~238 s |
| Total execs | **5,884** (~24.7 exec/s) |
| Queue cycles | 70 |
| **Crashes** | **0** |
| **Hangs** | **0** |

Interpretation: no memory-safety violation surfaced in `libbarhopper_v3.so` within this
short, coverage-less budget — the expected outcome for a hardened, widely-deployed Google
library. This run validates that the harness exercises the real `recognizeBufferNative`
code path on hostile images at valid geometry. A meaningful campaign needs frida-mode
coverage + persistent mode + hours of runtime (see "next steps" above).

## ⚠ Validation (correction) — the barhopper negative is NOT valid

A positive/negative control battery was run to check whether the harness actually reaches
the decoder. **It does not.**

| Probe | Setup | Expected if harness reaches decoder | Observed |
|---|---|---|---|
| Negative control | real harness, benign image | no crash | rc=0 ✓ |
| Under-alloc (256 B real buffer, claim 256×256) | OOB if lib reads the image | crash | **rc=0** ✗ |
| **Poison pointer** | `GetDirectBufferAddress` → `0x1` | instant SIGSEGV if lib reads the image | **rc=0** ✗ |

The poison-pointer probe is conclusive: `recognizeBufferNative` **never dereferences the image
buffer**, so it returns before scanning. Root cause: `createNative()` builds a recognizer with
**no barcode formats enabled**, so recognition short-circuits.

**Therefore the earlier "5,884 execs / 0 crashes" campaign exercised an early-return path, not
the decoder — it is not a meaningful negative result.**

### Fix required to get a valid harness
Create the context via `createNativeWithClientOptions(env, this, jbyteArray options)` with a
serialized options proto that enables barcode formats. That path calls, on the stub `JNIEnv`:
- `GetByteArrayElements` (vtable index **184**, off `0x5c0`) → return the proto bytes,
- `GetArrayLength` (index **171**, off `0x558`) → return the proto length.

Until the recognizer is created *with formats*, no barhopper campaign can find decoder bugs.
The pipeline itself (afl-fuzz on device, ASan/dislocator detection) remains validated by the
demo — only the barhopper harness needs this fix.
