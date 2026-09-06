---
description: Run an on-device AFL++ campaign in a live tab (AFL TUI) and monitor crashes/execs
argument-hint: "[seconds]  (default: 3600)"
---

Invoke the **afl-fuzzing** skill and run a campaign for `${ARGUMENTS:-3600}` seconds.

Preconditions: `/fuzz-build` done and **`/fuzz-validate` passed** (poison-pointer crashes).
If validation has not passed, stop and say so — do not run a meaningless campaign.

Steps:
1. Seed the corpus (prefer real inputs, e.g. actual QR/barcode luminance frames).
2. **Launch AFL in a NEW terminal tab so the live AFL status screen is visible**, via
   `scripts/run-in-tab.sh` (TTY preserved → the TUI renders; the user watches it):
   ```bash
   LOG=$(scripts/run-in-tab.sh fuzz "adb shell 'cd /data/local/tmp/bh; \
     LD_LIBRARY_PATH=. AFL_PRELOAD=./libdislocator.so AFL_SKIP_BIN_CHECK=1 \
     AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
     timeout ${ARGUMENTS:-3600} ./afl-fuzz -n -m none -t 1500 -i seeds -o out -- ./harness @@'")
   ```
   (Adjust the on-device dir/harness to what `/fuzz-build` produced. Keep the AFL **TUI on** for
   the tab — do NOT set `AFL_NO_UI`. A headless alternative is
   `adb shell 'nohup sh /data/local/tmp/run_target.sh <seconds> >…/nohup.log 2>&1 &'`.)
3. **Monitor from here** — poll the clean, structured stats over adb (the tab's `$LOG` holds the
   ANSI TUI, so prefer these for parsing):
   ```bash
   adb shell 'tail -1 /data/local/tmp/bh/out/plot_data'      # total_execs, execs_per_sec, saved_crashes, saved_hangs
   adb shell 'cat /data/local/tmp/bh/out/fuzzer_stats' | grep -E 'execs|crashes|run_time'
   adb shell 'ls /data/local/tmp/bh/out/crashes/ 2>/dev/null'
   ```
   Report progress periodically while the tab shows the live dashboard.
4. On any crash: pull it, reproduce, and **triage** — confirm it's a real memory-safety bug in
   the target (backtrace inside the lib, at valid geometry), not a harness artifact.
5. Report exec count, throughput, and crashes. If coverage is `0.00%` (dumb mode), note that
   greybox (frida-mode) coverage is the recommended upgrade.
