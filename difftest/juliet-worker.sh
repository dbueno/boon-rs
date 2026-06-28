#!/usr/bin/env bash
# Differential worker: classify ONE Juliet .c file with both analyzers, under
# both OMITGOOD (flawed) and OMITBAD (fixed) builds.  Feeds byte-identical
# preprocessed input (cstubs + shared typedef prelude) to both tools.
# Emits one CSV line: file,rs_bad,rs_good,orig_bad,orig_good
# Each verdict is FOUND | CLEAN | ERR.
set -u
ROOT=/Users/dbueno/proj/boon-rs
BOON=$ROOT/boon-1.0
SML=/nix/store/s3dqqcrdv95xyp6jaskpmjfpgr2xq211-smlnj-110.99.9/bin/sml
RS=$ROOT/target/release/boon
PRELUDE=$ROOT/difftest/prelude.h
INC=(-I$ROOT/cstubs -I$ROOT/juliet-test-suite-c/testcasesupport)

file=$1
tmp=$(mktemp -d /tmp/jdiff.XXXXXX)
trap 'rm -rf "$tmp"' EXIT

classify() { # $1 = define ; echo "rs orig"
  local def=$1
  local ii="$tmp/$def.i"
  if ! cc -E -P -nostdinc -D'__attribute__(x)=' "${INC[@]}" -D"$def" "$file" > "$tmp/raw.i" 2>/dev/null; then
    echo "ERR ERR"; return
  fi
  cat "$PRELUDE" "$tmp/raw.i" > "$ii"
  # boon-rs
  local rs orig out
  if out=$("$RS" "$ii" 2>/dev/null); then
    if grep -q "buffer overflow in" <<<"$out"; then rs=FOUND; else rs=CLEAN; fi
  else rs=ERR; fi
  # original BOON (must run from its dir, with itself on PATH for ssolver/newsolver)
  out=$(cd "$BOON" && PATH="$BOON:$PATH" timeout 30 "$SML" @SMLload="$BOON/boonheap" "$ii" 2>/dev/null)
  if grep -qE "uncaught exception|Abort due to parse|^FAILED" <<<"$out"; then orig=ERR
  elif grep -q "buffer overflow in" <<<"$out"; then orig=FOUND
  else orig=CLEAN; fi
  echo "$rs $orig"
}

read rb ob < <(classify OMITGOOD)
read rg og < <(classify OMITBAD)
echo "$file,$rb,$rg,$ob,$og"
