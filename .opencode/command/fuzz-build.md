---
description: Build AFL++ for Android arm64 + the fuzzing harness, and push to the emulator
argument-hint: "[target-lib.so]  (default: libbarhopper_v3.so)"
---

Invoke the **afl-fuzzing** skill and stand up the on-device fuzzing toolchain for
`${ARGUMENTS:-libbarhopper_v3.so}`.

Steps:
1. Load the `afl-fuzzing` skill.
2. Confirm a device is up (`adb devices`); note its ABI/API (`adb shell getprop ro.product.cpu.abi`).
3. Cross-compile `afl-fuzz` for Android arm64 with the NDK clang, and build the harness +
   `libdislocator` (`skills/afl-fuzzing/scripts/rebuild.sh`).
4. Extract the target `.so` from `config.arm64_v8a.apk`; if the harness needs a JNI signature,
   disassemble it (`llvm-objdump -d --disassemble-symbols=<sym>`) and wire the stub `JNIEnv`
   (idx 230 `GetDirectBufferAddress`, 184 `GetByteArrayElements`, 171 `GetArrayLength`).
5. Push `afl-fuzz`, the harness, the target `.so`, and `libdislocator.so` to `/data/local/tmp`.
6. Sanity-run the harness on a benign seed (expect clean exit, no false crash).

Do NOT trust any campaign until `/fuzz-validate` passes.
