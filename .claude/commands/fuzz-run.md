---
description: Run an on-device AFL++ campaign and report crashes/execs
argument-hint: "[seconds]  (default: 3600)"
---

Invoke the **afl-fuzzing** skill and run a campaign for `${ARGUMENTS:-3600}` seconds.

Preconditions: `/fuzz-build` done and **`/fuzz-validate` passed** (poison-pointer crashes).
If validation has not passed, stop and say so — do not run a meaningless campaign.

Steps:
1. Seed the corpus (prefer real inputs, e.g. actual QR/barcode luminance frames).
2. Launch in a NEW terminal tab for a live view (user watches; you monitor the mirrored log):
   `LOG=$(scripts/run-in-tab.sh fuzz "adb shell AFL_..._ /data/local/tmp/afl-fuzz -i ... -o ... -- ...")`
   (or, headless, `adb shell 'nohup sh /data/local/tmp/run_target.sh <seconds> >/data/local/tmp/nohup.log 2>&1 &'`).
3. Poll `plot_data` for `total_execs`, `execs_per_sec`, `saved_crashes`, `saved_hangs` (and read `$LOG`).
4. On any crash: pull it, reproduce, and **triage** — confirm it's a real memory-safety bug in
   the target (backtrace inside the lib, at valid geometry), not a harness artifact.
5. Report exec count, throughput, and crashes. If coverage is `0.00%` (dumb mode), note that
   greybox (frida-mode) coverage is the recommended upgrade.
