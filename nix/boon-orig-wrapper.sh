#!@shell@
# Run the original SML BOON heap.  The heap execs its constraint solver as the
# bare relative name "ssolver", which this SML/NJ resolves against the current
# directory (not $PATH); so we cd into the dir holding ssolver/newsolver and
# first rewrite any relative input-file arguments to absolute paths.
d="@libexec@"
args=()
for a in "$@"; do
  if [ -e "$a" ] && [ "${a#/}" = "$a" ]; then
    args+=("$PWD/$a")
  else
    args+=("$a")
  fi
done
export PATH="$d:$PATH"
cd "$d" || exit 1
exec @sml@ @SMLload="@heap@" "${args[@]}"
