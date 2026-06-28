# Reproducible differential tests: boon-rs vs. the original SML BOON.
#
# Both analyzers are fed BYTE-IDENTICAL preprocessed input (cstubs + a shared
# typedef prelude), exactly as in difftest/REPORT.md.  Two checks:
#
#   examples  - the 5 bundled example programs; findings must be IDENTICAL.
#   juliet    - the full CWE121/122/124/126/127 corpus (14,734 files), each run
#               under OMITGOOD (flawed) and OMITBAD (fixed); FOUND/CLEAN verdicts
#               must agree on >= 99.9% of comparable variants (variants the
#               original BOON errors on - wchar_t etc. - are excluded, per the
#               report's methodology).
{ pkgs
, boon       # the Rust port (native)
, boon-orig  # the original SML BOON (x86_64; runs via Rosetta on aarch64-darwin)
, juliet     # juliet-test-suite-c source tree
, prelude    # difftest/prelude.h
, normalize  # difftest/normalize.pl
, summarize  # difftest/summarize.pl
, cstubs     # cstubs/ directory
}:

let
  inherit (pkgs) lib;

  # The Rust port installs its binary as `boon` (Cargo [[bin]] name), which is
  # not the package pname, so getExe would guess wrong — reference it directly.
  boonBin = "${boon}/bin/boon";
  boonOrigBin = lib.getExe boon-orig;

  # Tools every check needs on PATH: both analyzers, a C preprocessor, perl,
  # and coreutils (timeout, mktemp, ...).
  commonTools = [ boon boon-orig pkgs.clang pkgs.perl pkgs.coreutils pkgs.findutils ];

  ppFlags = ''-E -P -nostdinc -D'__attribute__(x)=' '';

  # The CWE families analyzed in the differential study (buffer over/underflow,
  # over/underread).  `find` over these reproduces the exact 14,734-file corpus.
  cweGlobs = "CWE121_* CWE122_* CWE124_* CWE126_* CWE127_*";

  # Per-file 2x2 classifier: emits "file,rs_bad,rs_good,orig_bad,orig_good"
  # with each verdict in {FOUND, CLEAN, ERR}.
  julietWorker = pkgs.writeShellScript "juliet-worker" ''
    set -u
    RS=${boonBin}
    ORIG=${boonOrigBin}
    PRELUDE=${prelude}
    INC="-I${cstubs} -I${juliet}/testcasesupport"
    file=$1
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    classify() { # $1 = define ; echoes "rs orig"
      local def=$1
      local ii="$tmp/$def.i" rs orig out
      if ! cc ${ppFlags} $INC -D"$def" "$file" > "$tmp/raw.i" 2>/dev/null; then
        echo "ERR ERR"; return
      fi
      cat "$PRELUDE" "$tmp/raw.i" > "$ii"
      if out=$("$RS" "$ii" 2>/dev/null); then
        grep -q "buffer overflow in" <<<"$out" && rs=FOUND || rs=CLEAN
      else rs=ERR; fi
      # The original is slow under heavy parallel load; cap each call.
      out=$(timeout 120 "$ORIG" "$ii" 2>/dev/null)
      if grep -qE "uncaught exception|Abort due to parse|^FAILED" <<<"$out"; then orig=ERR
      elif grep -q "buffer overflow in" <<<"$out"; then orig=FOUND
      else orig=CLEAN; fi
      echo "$rs $orig"
    }

    read rb ob < <(classify OMITGOOD)
    read rg og < <(classify OMITBAD)
    echo "$file,$rb,$rg,$ob,$og"
  '';

in
{
  # --- 5 bundled examples: findings must be byte-identical -------------------
  examples = pkgs.runCommand "boon-difftest-examples"
    { nativeBuildInputs = commonTools; }
    ''
      set -u
      examples=${boon-orig}/share/boon/examples
      fail=0
      echo "=== boon-rs vs original BOON: bundled examples ==="
      for name in main gethostbyname hdrs fingerd route; do
        cc ${ppFlags} -I${cstubs} "$examples/$name.c" > raw.i 2>/dev/null
        cat ${prelude} raw.i > "$name.i"
        ${boonBin}     "$name.i" 2>/dev/null | perl ${normalize} > "$name.rs.txt"   || true
        ${boonOrigBin} "$name.i" 2>/dev/null | perl ${normalize} > "$name.orig.txt" || true
        if diff -u "$name.orig.txt" "$name.rs.txt" > "$name.diff"; then
          echo "  OK   $name.c"
        else
          echo "  DIFF $name.c"; cat "$name.diff"; fail=1
        fi
      done
      [ $fail -eq 0 ] || { echo "examples differential FAILED"; exit 1; }
      echo "examples differential: 5/5 identical"
      mkdir -p "$out"
      cp ./*.rs.txt ./*.orig.txt "$out/"
    '';

  # --- full Juliet corpus: agreement must be >= 99.9% -----------------------
  juliet = pkgs.runCommand "boon-difftest-juliet"
    {
      nativeBuildInputs = commonTools;
      # This is a long run (tens of thousands of SML invocations under Rosetta).
      requiredSystemFeatures = [ "big-parallel" ];
    }
    ''
      set -u
      jobs=''${NIX_BUILD_CORES:-0}
      [ "$jobs" -gt 0 ] 2>/dev/null || jobs=$(getconf _NPROCESSORS_ONLN || echo 4)
      echo "=== boon-rs vs original BOON: Juliet ${cweGlobs} ($jobs-way parallel) ==="

      ( cd ${juliet}/testcases && find ${cweGlobs} -name '*.c' ) \
        | sed "s#^#${juliet}/testcases/#" | sort > files.txt
      echo "files to analyze: $(wc -l < files.txt)"

      # Classify every file in parallel; one CSV line per file.
      xargs -P "$jobs" -n1 ${julietWorker} < files.txt > results.csv

      echo
      perl ${summarize} results.csv | tee summary.txt

      # Threshold gate: agreement across all comparable (non-ERR) variants.
      echo
      # A variant counts only if BOTH tools produced a real verdict
      # (FOUND/CLEAN); anything else (ERR, or an empty field from a broken
      # worker line) is excluded — never silently scored as agreement.
      awk -F, '
        function ok(v) { return v=="FOUND" || v=="CLEAN" }
        ok($2) && ok($4) { cmp++; if ($2==$4) ag++ }   # OMITGOOD
        ok($3) && ok($5) { cmp++; if ($3==$5) ag++ }   # OMITBAD
        END {
          if (cmp==0) { print "no comparable variants"; exit 1 }
          pct = 100*ag/cmp
          printf "GATE: %d/%d comparable variants agree (%.4f%%); threshold 99.9%%\n", ag, cmp, pct
          if (pct < 99.9) { print "Juliet differential FAILED"; exit 1 }
          print "Juliet differential PASSED"
        }' results.csv

      mkdir -p "$out"
      cp results.csv summary.txt "$out/"
    '';
}
