#!/usr/bin/env bash
# Fast boon-rs-only classifier (no SML). Emits: file,rs_bad,rs_good
set -u
ROOT=/Users/dbueno/proj/boon-rs
RS=$ROOT/target/release/boon
PRELUDE=$ROOT/difftest/prelude.h
INC=(-I$ROOT/cstubs -I$ROOT/juliet-test-suite-c/testcasesupport)
file=$1
tmp=$(mktemp -d /tmp/rsdiff.XXXXXX); trap 'rm -rf "$tmp"' EXIT
classify() {
  local def=$1
  if ! cc -E -P -nostdinc -D'__attribute__(x)=' "${INC[@]}" -D"$def" "$file" > "$tmp/raw.i" 2>/dev/null; then
    echo ERR; return
  fi
  cat "$PRELUDE" "$tmp/raw.i" > "$tmp/x.i"
  if out=$("$RS" "$tmp/x.i" 2>/dev/null); then
    grep -q "buffer overflow in" <<<"$out" && echo FOUND || echo CLEAN
  else echo ERR; fi
}
echo "$file,$(classify OMITGOOD),$(classify OMITBAD)"
