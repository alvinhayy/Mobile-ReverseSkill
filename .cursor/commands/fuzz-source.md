---
description: Coverage-guided fuzz an OPEN-SOURCE C/C++ library on the host — AFL++ (source-instrumented) or libFuzzer, with a harness feeding the input to the target parser
argument-hint: "<git-url|path> <entry-function>   e.g. https://github.com/libwifi/libwifi libwifi_parse_frame"
allowed-tools: Bash(git:*), Bash(clang:*), Bash(cmake:*), Bash(make:*), Bash(afl-fuzz:*), Bash(afl-clang-fast:*), Bash(docker:*)
---

Fuzz an open-source native library with real coverage (source instrumentation) — the ideal AFL
case (unlike closed-source on-device). Target = first arg (git URL or local path); entry parser
= second arg. Authorized/OSS targets only.

### 1. Get the source & find the entry
```bash
git clone --depth 1 <url> src && cd src
```
Read the headers to confirm the parser signature (what buffer/len it takes). For libwifi that is
`libwifi_parse_frame(struct libwifi_frame *out, const unsigned char *buf, size_t buf_len, ...)`.

### 2. Pick the engine (host macOS)
- **libFuzzer (fast, native)** — homebrew LLVM clang: `/opt/homebrew/opt/llvm/bin/clang`
  supports `-fsanitize=fuzzer,address`. Best when no AFL on the host.
- **AFL++ (source-instrumented)** — via the `aflplusplus/aflplusplus` Docker image (Colima) or a
  host build; compile the lib+harness with `afl-clang-fast`, run `afl-fuzz -i seeds -o out`.

### 3. Write a harness
libFuzzer:
```c
#include <stddef.h>
#include <stdint.h>
#include "libwifi.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct libwifi_frame f = {0};
  if (libwifi_get_wifi_frame(&f, data, size, 0) == 0) libwifi_free_wifi_frame(&f);
  return 0;
}
```
AFL++ persistent: read `@@`/stdin into a buffer, call the same parser inside `__AFL_LOOP`.

### 4. Build (instrumented + ASan) & seed
```bash
# libFuzzer:
/opt/homebrew/opt/llvm/bin/clang -g -O1 -fsanitize=fuzzer,address -I<inc> harness.c <lib .a/.c> -o fuzz
# AFL++ (docker): afl-clang-fast -fsanitize=address ... ; seeds = a few valid frames/pcap payloads
```

### 5. Run in a live tab + monitor
```bash
LOG=$(scripts/run-in-tab.sh fuzz-lib "./fuzz -max_len=4096 corpus/")     # libFuzzer
# or: LOG=$(scripts/run-in-tab.sh fuzz-lib "afl-fuzz -i seeds -o out -- ./harness @@")
```
Watch `$LOG` (libFuzzer prints cov/exec/crashes; AFL shows its TUI). On a crash, libFuzzer writes
`crash-<hash>` (+ ASan report); AFL writes `out/default/crashes/`.

### 6. Triage & report
Reproduce each crash (`./fuzz crash-*`), read the ASan backtrace, classify (OOB/UAF/…), and note
the offending frame bytes. Save crashes + a summary; do not commit target source or crash corpora.
