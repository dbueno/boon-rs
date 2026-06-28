{
  description = "boon-rs: a Rust port of BOON, with a reproducible differential test against the original SML BOON";

  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";

    # Original BOON, fetched from upstream and built reproducibly (see
    # nix/boon-orig.nix).  Pinned by hash in that file, not as a flake input,
    # because it is a plain tarball.

    # NIST Juliet C/C++ test suite (with a Unix build system), pinned by commit
    # so the differential corpus is reproducible.
    juliet = {
      url = "github:arichardson/juliet-test-suite-c/f88433e3443648a17671398797a04ea1f8e1a274";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, utils, naersk, juliet }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };

        # The original BOON needs SML/NJ, which nixpkgs only provides for
        # x86_64.  On aarch64-darwin we build the x86_64 package and run it via
        # Rosetta 2 (requires `extra-platforms = x86_64-darwin` in nix.conf).
        smlnjSystem = {
          "aarch64-darwin" = "x86_64-darwin";
          "x86_64-darwin" = "x86_64-darwin";
          "x86_64-linux" = "x86_64-linux";
        }.${system} or null;
        smlnjSupported = smlnjSystem != null;
        pkgsSml = import nixpkgs { system = smlnjSystem; };

        boon = naersk-lib.buildPackage {
          pname = "boon-rs";
          root = ./.;
        };

        # Built as a NATIVE derivation that invokes the x86_64 `sml` (via
        # Rosetta on aarch64-darwin) during its build — so it needs only Rosetta,
        # not an `extra-platforms` daemon that can *build* x86_64 derivations.
        boon-orig = pkgs.callPackage ./nix/boon-orig.nix {
          smlnj = pkgsSml.smlnj;
        };

        checks = import ./nix/checks.nix {
          inherit pkgs boon boon-orig juliet;
          prelude = ./difftest/prelude.h;
          normalize = ./difftest/normalize.pl;
          summarize = ./difftest/summarize.pl;
          cstubs = ./cstubs;
        };
      in
      {
        packages = {
          default = boon;
          boon = boon;
        } // pkgs.lib.optionalAttrs smlnjSupported {
          inherit boon-orig;
        };

        apps = {
          default = { type = "app"; program = "${boon}/bin/boon"; };
          boon = { type = "app"; program = "${boon}/bin/boon"; };
        } // pkgs.lib.optionalAttrs smlnjSupported {
          boon-orig = { type = "app"; program = "${boon-orig}/bin/boon-orig"; };
        };

        # `nix flake check` runs both differential tests against the original
        # BOON.  Only available where SML/NJ can run (see smlnjSystem above).
        checks = pkgs.lib.optionalAttrs smlnjSupported {
          inherit (checks) examples juliet;
        };

        devShells.default = with pkgs; mkShell {
          buildInputs = [ cargo rustc rustfmt pre-commit rustPackages.clippy ]
            ++ lib.optionals smlnjSupported [ boon-orig ];
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
      }
    );
}
