#!/usr/bin/env bash
# Run the ORIGINAL (SML) BOON on one or more preprocessed .i files.
# Prints only the vulnerability report to stdout (progress/timing dropped).
# Usage: boon-orig.sh file1.i [file2.i ...]
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BOON="$ROOT/boon-1.0"
# resolve input paths to absolute before we cd
args=()
for f in "$@"; do
  case "$f" in
    /*) args+=("$f") ;;
    *)  args+=("$(pwd)/$f") ;;
  esac
done
cd "$BOON" || exit 99
nix --extra-experimental-features 'nix-command flakes' shell nixpkgs#smlnj --command \
  bash -c 'PATH="$PWD:$PATH" sml @SMLload="$PWD/boonheap" "$@"' _ "${args[@]}" \
  2>/dev/null
