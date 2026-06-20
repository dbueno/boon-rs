//! `boon` — command-line driver for the Rust port of BOON.
//!
//! Usage:
//!   boon [options] file.c [file2.c ...]
//!
//! Options:
//!   -E, --preprocess      Run the C preprocessor on each input first
//!                         (needed for sources that `#include` headers or use
//!                         macros, e.g. the Juliet test suite). Default: off.
//!       --cc <prog>       C compiler to use for preprocessing (default: cc).
//!   -I <dir>              Add an include directory (forwarded to the cpp).
//!   -D <name[=val]>       Define a macro (forwarded to the cpp).
//!       --debug           Print extra diagnostics (constraint/var counts).
//!   -q, --quiet           Suppress the CAVEATS section.
//!   -h, --help            Show this help.
//!
//! All input files are analyzed together in a single constraint system, so a
//! call in one file resolves against a definition in another — matching the
//! original tool's multi-file behavior.

use boon_rs::parse::parse_program;
use boon_rs::walk::{analyze, Report};
use std::path::Path;
use std::process::Command;

struct Options {
    preprocess: bool,
    nostdinc: bool,
    cc: String,
    includes: Vec<String>,
    defines: Vec<String>,
    debug: bool,
    quiet: bool,
    files: Vec<String>,
}

fn usage() -> &'static str {
    "Usage: boon [options] file.c [...]\n\
     \n\
     Options:\n\
     \x20 -E, --preprocess    run the C preprocessor on inputs first\n\
     \x20     --nostdinc      preprocess with -nostdinc (use only -I dirs;\n\
     \x20                     implies -E; pair with -I cstubs)\n\
     \x20     --cc <prog>     C compiler for preprocessing (default: cc)\n\
     \x20 -I <dir>            add an include directory (for -E)\n\
     \x20 -D <name[=val]>     define a macro (for -E)\n\
     \x20     --debug         print extra diagnostics\n\
     \x20 -q, --quiet         suppress the CAVEATS section\n\
     \x20 -h, --help          show this help\n"
}

fn parse_args() -> Result<Options, String> {
    let mut opts = Options {
        preprocess: false,
        nostdinc: false,
        cc: std::env::var("CC").unwrap_or_else(|_| "cc".to_string()),
        includes: Vec::new(),
        defines: Vec::new(),
        debug: false,
        quiet: false,
        files: Vec::new(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-E" | "--preprocess" => opts.preprocess = true,
            "--nostdinc" => {
                opts.nostdinc = true;
                opts.preprocess = true;
            }
            "--debug" => opts.debug = true,
            "-q" | "--quiet" => opts.quiet = true,
            "-h" | "--help" => {
                print!("{}", usage());
                std::process::exit(0);
            }
            "--cc" => opts.cc = args.next().ok_or("--cc needs an argument")?,
            "-I" => opts.includes.push(args.next().ok_or("-I needs an argument")?),
            "-D" => opts.defines.push(args.next().ok_or("-D needs an argument")?),
            s if s.starts_with("-I") => opts.includes.push(s[2..].to_string()),
            s if s.starts_with("-D") => opts.defines.push(s[2..].to_string()),
            s if s.starts_with('-') && s.len() > 1 => {
                return Err(format!("unknown option `{}`", s));
            }
            _ => opts.files.push(a),
        }
    }
    if opts.files.is_empty() {
        return Err("no input files".to_string());
    }
    Ok(opts)
}

/// Run the C preprocessor on `file`, returning the preprocessed source.
fn preprocess(opts: &Options, file: &str) -> Result<String, String> {
    let mut cmd = Command::new(&opts.cc);
    // `-E` preprocess only, `-P` drop line markers (keeps tree-sitter happy).
    cmd.arg("-E").arg("-P");
    // Neutralize GNU attributes the grammar may stumble on.
    cmd.arg("-D__attribute__(x)=");
    if opts.nostdinc {
        // Use only the supplied (-I) include dirs — typically the bundled
        // `cstubs/` stub headers — so real system headers (full of compiler
        // extensions tree-sitter can't parse) are never pulled in.
        cmd.arg("-nostdinc");
    }
    for i in &opts.includes {
        cmd.arg(format!("-I{}", i));
    }
    for d in &opts.defines {
        cmd.arg(format!("-D{}", d));
    }
    cmd.arg(file);
    let out = cmd
        .output()
        .map_err(|e| format!("failed to run `{}`: {}", opts.cc, e))?;
    if !out.status.success() {
        return Err(format!(
            "preprocessor failed for {}:\n{}",
            file,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn read_source(opts: &Options, file: &str) -> Result<String, String> {
    if opts.preprocess {
        preprocess(opts, file)
    } else {
        std::fs::read_to_string(file).map_err(|e| format!("cannot read {}: {}", file, e))
    }
}

fn print_report(report: &Report, quiet: bool) {
    println!("\nPOSSIBLE VULNERABILITIES:");
    for h in &report.holes0 {
        println!("{}", h);
    }
    for h in &report.holes1 {
        println!("{}", h);
    }
    for h in &report.holes2 {
        println!("{}", h);
    }
    if report.total_holes() == 0 {
        println!("(none found)");
    }
    if !quiet {
        println!("\nCAVEATS:");
        // Deduplicate identical caveats to keep the output readable.
        let mut seen = std::collections::HashSet::new();
        for w in &report.warnings {
            if seen.insert(w.clone()) {
                println!("{}", w);
            }
        }
    }
}

fn main() {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("boon: {}\n", e);
            eprint!("{}", usage());
            std::process::exit(2);
        }
    };

    // Parse every input and merge declarations into one program, so the
    // analysis sees the whole set of files together.
    let mut all_decls = Vec::new();
    let mut last_file = String::from("input");
    for file in &opts.files {
        let src = match read_source(&opts, file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("boon: {}", e);
                std::process::exit(1);
            }
        };
        match parse_program(&src) {
            Some(mut p) => all_decls.append(&mut p.decls),
            None => {
                eprintln!("boon: failed to parse {}", file);
                std::process::exit(1);
            }
        }
        last_file = Path::new(file)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.clone());
    }

    let program = boon_rs::ast::Program { decls: all_decls };
    if opts.debug {
        eprintln!("boon: {} top-level declarations", program.decls.len());
    }
    let report = analyze(&program, &last_file);
    print_report(&report, opts.quiet);
}
