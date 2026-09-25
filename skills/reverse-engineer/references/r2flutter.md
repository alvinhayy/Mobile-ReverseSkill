# r2flutter for Flutter/Dart AOT

Read this reference when a Flutter target contains `libapp.so` and r2flutter is available or
can be installed. r2flutter is a static metadata and analysis aid, not a Dart source decompiler.
Use it alongside Blutter: r2flutter is strong at snapshot metadata, addresses, classes, strings,
ObjectPool references, and radare2 integration; Blutter provides broader pseudo-source and a
snapshot-specific Frida helper.

Upstream: <https://github.com/radareorg/r2flutter>

## Preconditions and input

- Use only an authorized artifact and do not execute the target application.
- Prefer the arm64/AArch64 `libapp.so`; that is r2flutter's primary analysis target.
- Android input may be a direct `libapp.so` or a directory that directly contains it. Extract
  split APK/XAPK inputs first.
- iOS input may be an extracted `.app` bundle or its `Frameworks/App.framework/App` binary.
- r2flutter currently requires radare2 6.2.2 or newer (a compatible radare2 git build may also
  work). If the versions are incompatible, record the gap and continue with Blutter/strings.

Check availability before use:

```bash
r2 -v
r2flutter -V
```

Install from source when needed:

```bash
git clone https://github.com/radareorg/r2flutter "$HOME/tools/r2flutter"
make -C "$HOME/tools/r2flutter"
make -C "$HOME/tools/r2flutter" user-install
export PATH="$HOME/tools/r2flutter/bin:$PATH"
```

Do not force-install or upgrade radare2 during an engagement without informing the user; its
plugin ABI must match the r2flutter build.

## Metadata pass

Write machine-readable output to `r2flutter_out/`:

```bash
R2F_OUT=out/r2flutter_out
mkdir -p "$R2F_OUT"

r2flutter -jH libapp.so > "$R2F_OUT/header.json"
r2flutter -jf libapp.so > "$R2F_OUT/functions.json"
r2flutter -jc libapp.so > "$R2F_OUT/classes.json"
r2flutter -jT libapp.so > "$R2F_OUT/types.json"
r2flutter -jz libapp.so > "$R2F_OUT/strings.json"
r2flutter -jx libapp.so > "$R2F_OUT/xrefs.json"
r2flutter -jS libapp.so > "$R2F_OUT/sbom.json"
```

`-z` reports strings reached through decoded ObjectPool entries and is preferred for evidence.
`-zz` is a broader fuzzy/carved scan; use it only as a supplement and label those strings as
heuristic. `-x` can be slow on large snapshots, so a user-requested quick scan may omit it if the
gap is documented.

Useful focused actions:

```bash
r2flutter -i -l 100 libapp.so       # sample InstructionTable entries
r2flutter -p libapp.so              # reconstructed ObjectPool
r2flutter -O 'pp+0x120' libapp.so   # decode one PP slot
r2flutter -m obfuscation-map.json -jf libapp.so
```

## Confidence and failure rules

Inspect `header.json` before trusting decoded objects:

- `version_source=exact-hash` or a verified explicit override: highest layout confidence.
- `version_source=structural-probe`: usable, but cross-check names/counts with Blutter and raw
  strings before treating them as confirmed.
- `version_source=fingerprint`: conservative fallback; label recovered structure as heuristic.
- Missing snapshot or impossible counts/addresses: do not force output into the report.

Never pass `-D` merely to make parsing succeed. Use it only when the Dart version/hash is known
independently. Keep `-n` disabled by default: its sequential name-pool fallback can shift names
after one incorrect classification.

For obfuscated apps, `-m <map.json>` accepts Flutter's `--save-obfuscation-map` output. Without
that map, report recovered obfuscated names as-is rather than guessing identities.

## radare2 analysis pass

After `make user-install`, the core plugin exposes an `r2flutter` command inside radare2:

```bash
r2 -q -e bin.relocs.apply=true libapp.so
> r2flutter -H
> r2flutter -A
> afl~method
```

Use `r2flutter -AAA` only when deeper code-reference analysis is warranted. It creates/analyzes
many functions, applies signatures, and tracks ARM64 ObjectPool usage, so it is substantially
more expensive on large snapshots. `r2flutter -AAA` is plugin-specific; it is not the same as
radare2's ordinary `aaa` command.

The plugin annotates the current r2 session with recovered flags, comments, classes, types,
function signatures, and references. Export evidence with ordinary radare2 commands or use
`r2flutter -R` to emit an importable r2 command script.

## Correlate, do not overclaim

Triangulate results as follows:

1. Use `functions.json` for Dart method names and native entrypoint addresses.
2. Use `classes.json` and `types.json` for ownership, field offsets, and inheritance that survived
   the AOT snapshot.
3. Use `strings.json` plus `xrefs.json` to connect endpoints/secrets to metadata or code. A string
   alone does not prove a live endpoint.
4. Compare recovered names and addresses with `blutter_out/asm/`, `objs.txt`, and `pp.txt`.
5. Record disagreements and layout confidence in `report.md` instead of silently choosing one
   tool's interpretation.

Do not describe r2flutter output as recovered Dart source. In reports, call it recovered AOT
metadata, reconstructed names/types, or radare2 annotations.
