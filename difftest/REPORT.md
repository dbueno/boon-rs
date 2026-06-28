# Differential test: boon-rs vs. the original BOON

Goal: build David Wagner's original SML BOON and verify the Rust port reproduces
its behavior on the bundled examples and the Juliet buffer-overflow CWEs, modulo
the one documented improvement (string-literal array init) in the README.

## Building the original BOON (2002 SML) on Apple Silicon

The original is SML/NJ + the BANE toolkit (2002, SML/NJ 110.0.x era). It does not
run natively on arm64 macOS, so:

1. **Rosetta 2** — required; the nixpkgs `smlnj` (110.99.9) ships only an
   x86_64 runtime. `softwareupdate --install-rosetta`.
2. **SML/NJ** — `nix shell nixpkgs#smlnj` (runs under Rosetta).
3. **CM modernization** (`sources.cm`, `bane/*/sources.cm`): old absolute
   `/usr/share/smlnj/lib/*.cm` paths → modern `$/basis.cm`, `$/smlnj-lib.cm`,
   `$/unix-lib.cm`, `$/ml-yacc-lib.cm`; added explicit `$/basis.cm`; replaced the
   `# if (defined ...)` arch conditional with `dummyinfo.sml` (amd64 path).
4. **Basis-library drift (1999→2025)**: `OS.FileSys.readDir` now returns
   `string option`; `Timer.checkCPUTimer` lost its `gc` field (use
   `Timer.checkGCTime`); `Substring.all` → `Substring.full`;
   `TextIO.inputLine` returns `string option`; the `implode o rev o explode`
   idiom no longer type-checks → `String.isSuffix`.
5. **`newsolver.c`**: `<values.h>` (absent on macOS) → `<limits.h>` + MAXSHORT/
   MAXLONG/MINLONG defines.
6. Build: `CM.make "sources.cm"; Walk.export();` → `boonheap.amd64-darwin`;
   `cc -O2 newsolver.c -o newsolver`; `mkdir /tmp/solver`.

Run wrapper: `difftest/boon-orig.sh`. Sanity check: `examples/main.c` reproduces
the README's documented output exactly.

## Methodology

Both analyzers get **byte-identical preprocessed input**:
`cc -E -P -nostdinc -D'__attribute__(x)=' -Icstubs [-Isupport] file.c`, with a
small analysis-neutral typedef prelude (`difftest/prelude.h`) prepended. The
prelude exists only because the bundled cstubs are *empty*: tree-sitter (boon-rs)
tolerates undeclared types, but the original's strict, typedef-tracking C parser
needs the type *names* (`FILE`, `size_t`, the `int64_t` family, the socket
structs) to disambiguate the grammar. None name string buffers, so neither tool's
verdict is affected — they only let both parse the same bytes.

## Results

### Examples — 5/5 identical

| file | findings | agree |
|---|---|---|
| main.c | POSSIBLE x@main 10..10 / 0..19 | ✅ |
| gethostbyname.c | POSSIBLE hname@main 256..256 / 1..+Inf | ✅ |
| hdrs.c | (none) | ✅ |
| fingerd.c | SLIGHT msg@fatal 5..7 / 5..7 | ✅ |
| route.c | POSSIBLE name@resolve 128..128 / 1..+Inf; name@rresolve 64..64 / 1..+Inf | ✅ |

(route required minimal real `struct hostent/netent/rtentry/sockaddr*` defs in the
prelude; without them the *original* crashes on incomplete-struct field access
while boon-rs degrades. With complete struct info both converge exactly —
including boon-rs's `name@rresolve` tightening from `2..84` to `1..+Infinity`.)

### Juliet — CWE121/122/124/126/127, 14,734 files

- **28,274 comparable variants (both analyzed): 99.57% agreement.**
- OMITGOOD (detect flaw): 14,077/14,137 agree (99.58%).
- OMITBAD (stay clean): 14,076/14,137 agree (99.57%).
- boon-rs errored on **0** files.

**121 disagreements (61 files), all one direction (`rs=FOUND`, `orig=CLEAN`),
all the same root cause.** They are exclusively `fgets`-based testcases
(`CWE129_fgets` / `CWE839_fgets`) in the **multi-file flow variants**, where the
buffer is `char buf[CHAR_ARRAY_SIZE] = ""` with
`#define CHAR_ARRAY_SIZE (3 * sizeof(data) + 2)`.

Root cause: boon-rs treats the array *dimension* `[3*sizeof(data)+2]` as a
non-constant VLA (per its documented "VLA sizes not seeded" limitation) and so
takes `alloc` from the `= ""` initializer (**1 byte**) — but it *does* evaluate
the same `sizeof` expression in the `fgets(buf, 3*sizeof(data)+2, …)` length
argument (`used` up to 14). Result: a spurious `1..14`. The original evaluates
`sizeof` consistently in *both* positions (`alloc`=14, `used`≤14) and stays clean.
This is an interaction of two boon-rs behaviors (no `sizeof` in array dimensions +
the string-literal-init model) and is **not** in the README. Minimal repro:
`char buf[(3*sizeof(int)+2)] = ""; fgets(buf, 3*sizeof(int)+2, stdin);`
→ boon-rs flags `1..12`, original clean. (A literal `char buf[14] = ""` is fine
in both.)

**597 files where only the original errored (excluded from "comparable"):**
559 `wchar_t` testcases + 38 `CWE135` wide-string testcases. The original crashes
(uncaught exception / parse error) on `wchar_t`, which the README states BOON does
not model; boon-rs degrades gracefully. Not analysis disagreements.

## Fix: evaluate `sizeof` in array dimensions

The `fgets`/`sizeof` divergence was fixed in `src/parse.rs`. The parser now keeps
a variable-name → type scope (populated in source order from declarations and
parameters), and `const_int` evaluates `sizeof` in array dimensions —
`sizeof(type)`, `sizeof(var)` (looked up in scope), and the `sizeof(int)+2`
maximal-munch cast form — using the **same** size model as `walk::sizeof_type`
(char=1, int=4, real=8; pointers/aggregates punt). So `char buf[3*sizeof(data)+2]`
now seeds `alloc`=14, consistent with the matching `fgets` length argument,
instead of degrading to a VLA and taking `alloc`=1 from the `= ""` initializer.

Re-evaluation (post-fix boon-rs joined with run-1's authoritative original
verdicts — the original is unchanged by a boon-rs-only fix):

- **28,273 / 28,274 comparable variants agree (99.996%).**
- **120 of the 121 disagreements fixed; 0 regressions introduced.**
- The single residual (`CWE122…CWE129_fgets_54e OMITBAD`) is **not** a real
  disagreement: it is a `Slight chance` on a malloc'd `line` buffer (`32..36`),
  and run-1's `orig=CLEAN` was a 30s-timeout artifact (that CWE122 file timed out
  under load). Re-run unloaded, the original reports the *same*
  `Slight chance … line@printLine() 32..36/32..36` as boon-rs. So that file
  agrees too → effective agreement is 28,274 / 28,274.
- `cargo test` still passes (7/7); the five examples remain 5/5 identical; the
  real `strcpy`-of-too-long-literal overflow is still flagged.

(Methodology note: the original BOON's external solver is fast (~60ms cold) but
slow under heavy parallel load; the per-call `timeout 30` in the harness can
misclassify a slow original run as CLEAN. This affects only the SML side under
contention; the fix verification avoided it by re-running boon-rs alone.)

## Conclusion

boon-rs faithfully reproduces the original BOON: identical on all five examples,
and after the `sizeof`-in-array-dimension fix, agreement across ~28k Juliet
variants is 99.996% (one residual, itself a load/timeout measurement artifact
that agrees when re-run unloaded) — up from 99.57% before the fix. The documented
string-literal-init improvement did not produce any disagreement in this corpus
(no `ALMOST` tier appeared).

## Reproducible harness (Nix)

The whole pipeline above is now packaged as a Nix flake so it reproduces from
pinned sources, instead of relying on a hand-built `boon-1.0/` and hardcoded
store paths:

- `nix build .#boon-orig` builds the original SML BOON from the upstream
  `boon-1.0.tar.gz` (pinned by hash) with the modernization patch
  (`nix/boon-orig.patch`) applied; on Apple Silicon the x86_64 `sml` runs via
  Rosetta. The wrapper handles the solver's cwd-relative `ssolver` exec.
- `nix flake check` runs two checks (`nix/checks.nix`):
  - `examples` — the 5 bundled examples, findings must be **identical**;
  - `juliet` — the full CWE121/122/124/126/127 corpus (14,734 files; Juliet
    pinned as the `juliet` flake input), agreement must be **≥ 99.9%** of
    comparable variants (orig-ERR excluded).

The shell/Perl logic mirrors the scripts below; the flake feeds both tools the
same `cstubs` + prelude preprocessed input and uses the same normalization.

## Artifacts

- `difftest/prelude.h` — shared typedef/struct prelude (used by the flake checks)
- `difftest/normalize.pl`, `difftest/summarize.pl` — report extraction (used by the flake checks)
- `difftest/boon-orig.sh` — run the original BOON on a `.i` (legacy; superseded by `nix run .#boon-orig`)
- `difftest/juliet-worker.sh` — per-file 2×2 classifier (legacy; superseded by `nix/checks.nix`)
- `difftest/juliet-results.csv` — raw per-file verdicts from the original run (file,rs_bad,rs_good,orig_bad,orig_good)
