#!/bin/sh
set -e
HERE="$(cd "$(dirname "$0")/.." && pwd)"
NDKBIN="$HOME/Library/Android/sdk/ndk/30.0.15729638/toolchains/llvm/prebuilt/darwin-x86_64/bin"
CC="$NDKBIN/aarch64-linux-android36-clang"
cd "$HERE"
# afl-fuzz core (android arm64)
( cd AFLplusplus && make afl-fuzz CC="$CC" NO_PYTHON=1 )
# harnesses
"$CC" -O1 -g -fno-omit-frame-pointer harness/barhopper_harness.c -o build/barhopper_harness -ldl
"$CC" -O1 -g -fsanitize=address -fno-omit-frame-pointer harness/demo_parse.c -o build/demo_parse
# dislocator
"$CC" -O2 -fPIC -shared -I AFLplusplus/include AFLplusplus/utils/libdislocator/libdislocator.so.c -o build/libdislocator.so
echo "OK: build/ populated"
