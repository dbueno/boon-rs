//! Juliet validation harness for the Rust port of BOON.
//!
//! Runs `boon` over Juliet C testcases using the standard SARD "good/bad"
//! methodology and reports detection / false-positive rates.
//!
//! Each Juliet testcase file contains a flawed `..._bad()` function and one or
//! more fixed `good*()` functions, gated by the `OMITGOOD` / `OMITBAD` macros.
//! We compile each file twice:
//!   * `-DOMITGOOD` — only the flawed code remains; a report here is a true
//!     positive (the flaw was detected).
//!   * `-DOMITBAD`  — only the fixed code remains; a report here is a false
//!     positive.
//!
//! Usage:
//!   juliet [options] <dir-or-file> [...]
//!
//! Options:
//!   -I <dir>        extra include dir (defaults: cstubs, the Juliet support dir)
//!   --cc <prog>     C compiler (default: cc)
//!   --limit <n>     stop after analyzing n testcases
//!   --list-fn       list false negatives (undetected bad cases)
//!   --list-fp       list false positives (flagged good cases)
//!
//! Only `.c` files are processed (BOON analyzes C). Multi-file testcase splits
//! (the `_8x` / `a`+`b` flow variants) are analyzed per file, so cross-file
//! flows are necessarily missed — as they are by the flow-insensitive original.

use boon_rs::parse::parse_program;
use boon_rs::walk::analyze;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Cfg {
    cc: String,
    includes: Vec<String>,
    limit: usize,
    list_fn: bool,
    list_fp: bool,
    /// Only analyze files whose name contains one of these substrings.
    matches: Vec<String>,
    roots: Vec<String>,
}

fn main() {
    let cfg = parse_args();
    let mut files = Vec::new();
    for r in &cfg.roots {
        collect_c_files(Path::new(r), &mut files);
    }
    files.sort();
    if !cfg.matches.is_empty() {
        files.retain(|f| {
            let name = f.file_name().unwrap().to_string_lossy();
            // A file must contain every --match substring (AND).
            cfg.matches.iter().all(|m| name.contains(m.as_str()))
        });
    }
    if files.is_empty() {
        eprintln!("juliet: no .c files found");
        std::process::exit(1);
    }

    let mut analyzed = 0usize;
    let mut tp = 0usize; // bad detected
    let mut fnn = 0usize; // bad missed (false negative)
    let mut fp = 0usize; // good flagged (false positive)
    let mut tn = 0usize; // good clean (true negative)
    let mut skipped = 0usize;
    let mut fn_list = Vec::new();
    let mut fp_list = Vec::new();

    for f in &files {
        if analyzed >= cfg.limit {
            break;
        }
        let fname = f.file_name().unwrap().to_string_lossy().into_owned();

        let bad = run_one(&cfg, f, &["OMITGOOD"]);
        let good = run_one(&cfg, f, &["OMITBAD"]);
        let (bad, good) = match (bad, good) {
            (Some(b), Some(g)) => (b, g),
            _ => {
                skipped += 1;
                continue;
            }
        };
        analyzed += 1;

        if bad {
            tp += 1;
        } else {
            fnn += 1;
            if cfg.list_fn {
                fn_list.push(fname.clone());
            }
        }
        if good {
            fp += 1;
            if cfg.list_fp {
                fp_list.push(fname.clone());
            }
        } else {
            tn += 1;
        }
    }

    println!("\n=== BOON / Juliet validation ===");
    println!("testcases analyzed : {}", analyzed);
    println!("skipped (parse/cpp): {}", skipped);
    println!();
    println!("Flawed code (OMITGOOD) — should be flagged:");
    println!("  detected (TP)    : {}", tp);
    println!("  missed   (FN)    : {}", fnn);
    if analyzed > 0 {
        println!(
            "  detection rate   : {:.1}%",
            100.0 * tp as f64 / analyzed as f64
        );
    }
    println!();
    println!("Fixed code (OMITBAD) — should be clean:");
    println!("  flagged  (FP)    : {}", fp);
    println!("  clean    (TN)    : {}", tn);
    if analyzed > 0 {
        println!(
            "  false-pos rate   : {:.1}%",
            100.0 * fp as f64 / analyzed as f64
        );
    }
    if cfg.list_fn && !fn_list.is_empty() {
        println!("\nFalse negatives (undetected flaws):");
        for f in &fn_list {
            println!("  {}", f);
        }
    }
    if cfg.list_fp && !fp_list.is_empty() {
        println!("\nFalse positives (flagged fixed code):");
        for f in &fp_list {
            println!("  {}", f);
        }
    }
}

/// Preprocess `file` with the given extra defines, then analyze it.
/// Returns `Some(found_overflow)` or `None` if preprocessing/parsing failed.
fn run_one(cfg: &Cfg, file: &Path, defines: &[&str]) -> Option<bool> {
    let mut cmd = Command::new(&cfg.cc);
    cmd.arg("-E").arg("-P").arg("-nostdinc").arg("-D__attribute__(x)=");
    for inc in &cfg.includes {
        cmd.arg(format!("-I{}", inc));
    }
    for d in defines {
        cmd.arg(format!("-D{}", d));
    }
    cmd.arg(file);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let src = String::from_utf8_lossy(&out.stdout);
    let prog = parse_program(&src)?;
    let report = analyze(&prog, &file.file_name().unwrap().to_string_lossy());
    Some(report.total_holes() > 0)
}

fn collect_c_files(p: &Path, out: &mut Vec<PathBuf>) {
    if p.is_file() {
        if p.extension().map(|e| e == "c").unwrap_or(false) {
            out.push(p.to_path_buf());
        }
        return;
    }
    if let Ok(rd) = std::fs::read_dir(p) {
        let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        entries.sort();
        for e in entries {
            collect_c_files(&e, out);
        }
    }
}

fn parse_args() -> Cfg {
    let mut cfg = Cfg {
        cc: std::env::var("CC").unwrap_or_else(|_| "cc".to_string()),
        includes: Vec::new(),
        limit: usize::MAX,
        list_fn: false,
        list_fp: false,
        matches: Vec::new(),
        roots: Vec::new(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-I" => cfg.includes.push(args.next().expect("-I needs an arg")),
            "--cc" => cfg.cc = args.next().expect("--cc needs an arg"),
            "--limit" => {
                cfg.limit = args
                    .next()
                    .and_then(|s| s.parse().ok())
                    .expect("--limit needs a number")
            }
            "--list-fn" => cfg.list_fn = true,
            "--list-fp" => cfg.list_fp = true,
            "--match" => cfg.matches.push(args.next().expect("--match needs an arg")),
            s if s.starts_with("-I") => cfg.includes.push(s[2..].to_string()),
            _ => cfg.roots.push(a),
        }
    }
    if cfg.includes.is_empty() {
        // Sensible defaults relative to the repo root.
        cfg.includes.push("cstubs".to_string());
        cfg.includes
            .push("juliet-test-suite-c/testcasesupport".to_string());
    }
    if cfg.roots.is_empty() {
        cfg.roots
            .push("juliet-test-suite-c/testcases/CWE121_Stack_Based_Buffer_Overflow".to_string());
    }
    cfg
}
