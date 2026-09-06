---
description: Prove the fuzz harness actually reaches the target (poison-pointer + under-alloc controls)
argument-hint: "[target-lib.so]"
---

Invoke the **afl-fuzzing** skill and run the harness **positive controls** before trusting any
result for `${ARGUMENTS:-the current target}`.

A "0 crashes" campaign is meaningless if the harness never reaches the parser. Verify:
1. **Negative control** — real harness on a benign seed → must exit clean (no false crash).
2. **Poison-pointer** — rebuild with `-DPOISON_PTR` so `GetDirectBufferAddress` returns `0x1`.
   Run it: it MUST crash (SIGSEGV). If it exits cleanly, the target never reads the buffer →
   the harness is not exercising the decoder — fix it (e.g. create the context WITH options,
   correct arg order) before continuing.
3. **Under-alloc** — rebuild with a tiny `-DREALALLOC` while claiming full size; a real read
   past the buffer must fault under `libdislocator`.

Report each control's result explicitly. Only proceed to `/fuzz-run` once the poison-pointer
control crashes as expected.
