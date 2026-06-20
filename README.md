# boon-rs

A Rust port of **BOON**, David Wagner's static analyzer for finding buffer
overrun vulnerabilities in C, originally written in Standard ML (the source is
in [`boon-1.0/`](boon-1.0/)). This port keeps the original analysis faithful but
replaces the hand-written C parser with [tree-sitter-c], and reimplements the
external C range solver (`newsolver.c`) directly in Rust.

> BOON models every C string as a pair of integers — `alloc` (bytes allocated)
> and `len` (bytes used, including the NUL) — generates range constraints over
> those integers from the program's string operations, solves the constraints,
> and reports any buffer whose used length could exceed its allocation. It is a
> *flow-insensitive* analysis: each variable has a single abstract value into
> which all of its uses are merged. See `boon-1.0/README`, `boon-1.0/TIPS`, and
> the paper `boon-1.0/paper.ps` for the original design.

## What this port does

`boon` reads C source, finds potential string-buffer overruns, and prints them
grouped by confidence (matching the original wording):

- **Almost certainly a buffer overflow** — the maximum allocation is smaller
  than the minimum used length.
- **Possibly a buffer overflow** — the maximum allocation is smaller than the
  maximum used length.
- **Slight chance of a buffer overflow** — the `X..Y` allocated / `X..Y` used
  heuristic the original uses to flag likely false alarms from merging.

## Building

Requires a Rust toolchain (the project pins `edition = "2021"`; tested with a
recent stable `cargo`). tree-sitter-c is pulled from crates.io.

```sh
cargo build --release
```

This produces two binaries:

- `target/release/boon` — the analyzer.
- `target/release/juliet` — the Juliet validation harness (see below).

Run the test suite (a handful of end-to-end checks of the analysis):

```sh
cargo test --release
```

## Running boon on C files

```
boon [options] file.c [file2.c ...]

  -E, --preprocess    run the C preprocessor on inputs first
      --nostdinc      preprocess with -nostdinc (use only -I dirs; implies -E)
      --cc <prog>     C compiler used for preprocessing (default: cc, or $CC)
  -I <dir>            add an include directory (for -E)
  -D <name[=val]>     define a macro (for -E)
  -q, --quiet         suppress the CAVEATS section
      --debug         print extra diagnostics
```

All input files are analyzed together in a single constraint system, so a call
in one file resolves against a definition in another — matching the original
tool's multi-file behavior.

Sources that `#include` headers or use macros must be preprocessed first. Real
system headers contain compiler extensions tree-sitter cannot parse (this is
why the original BOON shipped its own `include-wrap/` header stubs), so this
port bundles a set of **empty stub headers** in [`cstubs/`](cstubs/) and a
`--nostdinc` mode that uses only those:

```sh
boon --nostdinc -I cstubs some_program.c
```

### The bundled examples

The original example programs live in `boon-1.0/examples/`. Two of them are
self-contained and need no preprocessing:

```sh
# A snprintf bound that is too small for the formatted output:
$ cargo run --release -- boon-1.0/examples/main.c

POSSIBLE VULNERABILITIES:
Possibly a buffer overflow in `x@main()':
  10..10 bytes allocated, 0..19 bytes used.
  ...

# The classic gethostbyname() overflow (compare boon-1.0/TIPS):
$ cargo run --release -- boon-1.0/examples/gethostbyname.c

POSSIBLE VULNERABILITIES:
Possibly a buffer overflow in `hname@main()':
  256..256 bytes allocated, 1..+Infinity bytes used.
  <- len(hname@main())
  <- len((unnamed field h_name))
  ...
```

The other examples `#include <stdio.h>` etc., so preprocess them against the
stub headers:

```sh
# fingerd reproduces the fatal("pipe")/fatal("fdopen") "slight chance"
# walkthrough from boon-1.0/TIPS exactly:
$ cargo run --release -- --nostdinc -I cstubs -q boon-1.0/examples/fingerd.c

POSSIBLE VULNERABILITIES:
Slight chance of a buffer overflow in `msg@fatal()':
  5..7 bytes allocated, 5..7 bytes used.
  ...

# route.c (BSD routing tool); flags the resolve()-style buffer:
$ cargo run --release -- --nostdinc -I cstubs -q boon-1.0/examples/route.c
```

All five example programs (`main.c`, `gethostbyname.c`, `hdrs.c`, `fingerd.c`,
`route.c`) parse and analyze.

## Validating against the Juliet test suite

The [`juliet`](src/bin/juliet.rs) harness runs the analyzer over the Juliet C
testcases using the standard SARD methodology. Each Juliet testcase contains a
flawed `..._bad()` function and fixed `good*()` functions, gated by the
`OMITGOOD` / `OMITBAD` macros. The harness compiles each file twice:

- `-DOMITGOOD` keeps only the flawed code → a report here is a **true positive**.
- `-DOMITBAD` keeps only the fixed code → a report here is a **false positive**.

```
juliet [options] <dir-or-file> ...

  -I <dir>        include dir (defaults: cstubs and the Juliet support dir)
  --cc <prog>     C compiler (default: cc)
  --match <s>     only analyze files whose name contains <s> (repeat = AND)
  --limit <n>     stop after n testcases
  --list-fn       list false negatives (undetected flaws)
  --list-fp       list false positives (flagged fixed code)
```

Example — BOON's exact wheelhouse, the `CWE193` char off-by-one family whose
source is a string *literal* (a fixed buffer, a literal, a `strcpy`):

```sh
$ cargo run --release --bin juliet -- \
    --match CWE193_char --match _cpy_ --match _01.c \
    juliet-test-suite-c/testcases/CWE121_Stack_Based_Buffer_Overflow \
    juliet-test-suite-c/testcases/CWE122_Heap_Based_Buffer_Overflow

testcases analyzed : 3
Flawed code (OMITGOOD) — should be flagged:
  detected (TP)    : 3      detection rate : 100.0%
Fixed code (OMITBAD) — should be clean:
  flagged  (FP)    : 0      false-pos rate : 0.0%
```

Across **all flow variants** of that same family (baseline plus the
control-flow / inter-procedural / inter-file obfuscations `_02`…`_8x`):

```sh
$ cargo run --release --bin juliet -- \
    --match CWE193_char --match _cpy_ \
    juliet-test-suite-c/testcases/CWE121_Stack_Based_Buffer_Overflow \
    juliet-test-suite-c/testcases/CWE122_Heap_Based_Buffer_Overflow

testcases analyzed : 156
  detected (TP) : 71   detection rate : 45.5%
  flagged  (FP) : 40   false-pos rate : 25.6%
```

### Interpreting the Juliet results

These numbers are exactly what a 1997, flow-insensitive, string-range analysis
should produce, and they line up with the caveats in `boon-1.0/TIPS`:

- **On the patterns BOON models, in single-function form, it is precise** — 100%
  detection and 0 false positives on the baseline literal-source cases.
- **Detection drops on the obfuscated flow variants.** Variants that split the
  data flow across two files (`_8x`, `a`/`b`) cannot be followed by a per-file
  analysis, and BOON is flow-insensitive by design.
- **The false positives are the documented "merging" artifacts.** When good and
  bad buffers flow into a shared helper (e.g. `goodB2G` setter/getter
  indirection), their length ranges merge and the fixed version is flagged too
  — precisely the imprecision discussed in `boon-1.0/TIPS`.
- **Much of Juliet is out of scope on purpose.** BOON models string operations
  (`strcpy`/`strncpy`/`strcat`/`strncat`/`sprintf`/`snprintf`/`strlen`/
  `gets`/`fgets`/`getenv`/`malloc`/`alloca`/…), string literals, and fixed-size
  declarations. It does **not** model `memset`/`memcpy` fills, hand-written copy
  loops, `wchar_t` buffers, or integer-index bounds (CWE-129). Juliet frequently
  builds its source strings with `memset(...,'A',N)` to control the exact length,
  which BOON cannot see — so those testcases are reported as missed even though
  the limitation is fundamental to the original tool.

You can point the harness at any CWE directory; the buffer-overflow CWEs are
`CWE121` (stack), `CWE122` (heap), `CWE124`/`CWE127` (underwrite/underread), and
`CWE126` (overread).

## How the port is organized

The code mirrors the structure of the original SML so the two can be read side
by side. Each module documents the `*.sml` file it corresponds to.

| Module | Role | Original |
|---|---|---|
| [`src/ctype.rs`](src/ctype.rs) | C types and the `Str`/`Int`/`None` classification | `ctype.sml` |
| [`src/ast.rs`](src/ast.rs) | the simplified C AST the analysis consumes | (the bane AST) |
| [`src/parse.rs`](src/parse.rs) | tree-sitter-c CST → AST | `cparser.sml` + the bane C parser |
| [`src/constraint.rs`](src/constraint.rs) | range terms and the constraint system | `constraint-set.sml` |
| [`src/range.rs`](src/range.rs) | interval arithmetic with ±Infinity | `newsolver.c` (range ops) |
| [`src/solver.rs`](src/solver.rs) | the least-fixpoint range solver | `newsolver.c` |
| [`src/walk.rs`](src/walk.rs) | constraint generation from the AST | `walk.sml` |
| [`src/main.rs`](src/main.rs) | the `boon` CLI + preprocessing | the `boon`/`preproc` scripts |

### Design choices and fidelity notes

- **Parsing.** Per the task, the original C parser is replaced by tree-sitter-c.
  `parse.rs` translates only the constructs the analysis understands and degrades
  gracefully on the rest. One pre-ANSI wrinkle is handled explicitly: implicit-
  `int` definitions like `main(void)` or `fatal(char *msg)`, which tree-sitter
  mis-parses, are repaired by a small source pre-pass that inserts `int`.

- **The solver.** The original serialized constraints to text and shelled out to
  a C program (`newsolver.c`) that finds the least range solution by composing
  affine functions around cycles. This port computes the *same* least fixpoint
  in Rust the textbook way: condense the constraint dependency graph into
  strongly connected components, solve them in topological order, and within a
  cyclic component iterate with **interval widening** so positive feedback loops
  jump to ±Infinity. Because acyclic merges are never widened, finite ranges stay
  exact (e.g. the `5..7` and `1..+Infinity` results in the manual are
  reproduced); cyclic growth (as `forceLenTop` builds) becomes `+Infinity`, just
  as in the original where reaching ±32767 *is* infinity.

- **Flow-insensitive merging.** Variables are identified by name and enclosing
  function (BOON's alpha-conversion, e.g. `buf@main()`); function parameters and
  return values merge across all call sites; struct fields merge by field name
  and struct type. This reproduces both BOON's analysis power and its
  characteristic false alarms.

- **What is modelled.** The library-call models, the printf/sprintf/snprintf
  format-length computation, the `argv[]` kludge, and the `gethostbyname()`
  special case are all ported from `walk.sml`. See `boon-1.0/TIPS` for how to
  read the output and why merging produces conservative results.

## Limitations

This is a faithful port of a research prototype, and inherits its limitations
(no `memset`/`memcpy`/loop modelling, no `wchar_t`, flow-insensitive merging),
plus a couple of porting ones: pre-ANSI K&R definitions with explicitly-typed
parameter lists declared in the old style are only partially recovered, and
non-constant array sizes (VLAs) are not seeded with a size constraint. Real
system headers are not parseable; use `--nostdinc -I cstubs`.

## License

The original BOON sources in `boon-1.0/` are under the license in
`boon-1.0/LICENSE` (© Regents of the University of California). This Rust port is
provided for research and educational use under the same terms.

[tree-sitter-c]: https://github.com/tree-sitter/tree-sitter-c
