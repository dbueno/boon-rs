# Reproducible build of David Wagner's original SML BOON (boon-1.0, 2002) from
# the upstream tarball.  The 2002 source does not build on a modern SML/NJ +
# macOS, so `boon-orig.patch` modernizes the CM files and accounts for basis
# drift (see difftest/REPORT.md and the patch itself for the rationale).
#
# IMPORTANT: nixpkgs `smlnj` is x86_64-only.  This is a NATIVE derivation that
# *invokes* the x86_64 `sml` during its build (passed in as `smlnj`), so on
# aarch64-darwin it needs only Rosetta 2 — not a daemon configured to build
# x86_64-darwin derivations.  The flake passes the right (x86_64) smlnj.
{ stdenv
, lib
, fetchurl
, smlnj
, makeWrapper
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "boon-orig";
  version = "1.0";

  src = fetchurl {
    url = "https://people.eecs.berkeley.edu/~daw/boon/boon-1.0.tar.gz";
    hash = "sha256-lXr4V3O1dwMjvcfL45y3Pst0UYqlsM/P+dsjNd/2/bU=";
  };

  patches = [ ./boon-orig.patch ];

  nativeBuildInputs = [ smlnj makeWrapper ];

  # The build is a CM compile driven by the interactive `sml`, then a plain cc
  # of the external constraint solver.  Nothing to configure.
  dontConfigure = true;

  buildPhase = ''
    runHook preBuild

    # CM writes its cache under $HOME; keep it inside the build sandbox.
    export HOME="$TMPDIR"

    # Build the SML heap image (boonheap.<arch>-<os>) via the documented
    # `CM.make "sources.cm"; Walk.export();` incantation.
    echo 'CM.make "sources.cm"; Walk.export();' | sml

    # External constraint solver.
    $CC -O2 newsolver.c -o newsolver

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p "$out/libexec/boon" "$out/share/boon"

    # Heap image (e.g. boonheap.amd64-darwin) + the solver scripts/binary it
    # execs at analysis time (ssolver -> newsolver, both looked up on PATH).
    cp boonheap.* "$out/libexec/boon/"
    install -m755 ssolver newsolver "$out/libexec/boon/"

    # Bundle the example C sources so the differential checks have a stable,
    # tarball-pinned copy to analyze.
    cp -R examples "$out/share/boon/examples"

    # `boon-orig file.i ...` : the heap execs the solver as the *relative* name
    # "ssolver" (this SML/NJ's Unix.execute resolves against cwd, not PATH), so
    # the wrapper cd's into libexec/boon — and therefore resolves any relative
    # input file arguments to absolute paths first.  sml auto-appends the arch
    # suffix to the @SMLload base name.
    mkdir -p "$out/bin"
    substitute ${./boon-orig-wrapper.sh} "$out/bin/boon-orig" \
      --subst-var-by shell   ${stdenv.shell} \
      --subst-var-by libexec "$out/libexec/boon" \
      --subst-var-by sml     ${smlnj}/bin/sml \
      --subst-var-by heap    "$out/libexec/boon/boonheap"
    chmod +x "$out/bin/boon-orig"

    runHook postInstall
  '';

  # The exported heap is a self-contained SML/NJ image; no further fixup.
  dontStrip = true;

  meta = {
    description = "Original SML BOON static buffer-overrun detector (Wagner et al., 2002), built from upstream";
    homepage = "https://people.eecs.berkeley.edu/~daw/boon/";
    license = lib.licenses.bsdOriginal;
    platforms = [ "aarch64-darwin" "x86_64-darwin" "x86_64-linux" ];
    mainProgram = "boon-orig";
  };
})
