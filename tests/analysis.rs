//! End-to-end tests for the BOON port: parse a C snippet, run the analysis,
//! and check the reported buffer overruns.

use boon_rs::parse::parse_program;
use boon_rs::walk::{analyze, Report};

fn run(src: &str) -> Report {
    let prog = parse_program(src).expect("parse");
    analyze(&prog, "test.c")
}

/// A string literal too long for a fixed buffer is an "almost certain" overrun.
#[test]
fn detects_strcpy_overflow() {
    let r = run(r#"
        void f() {
            char buf[4];
            strcpy(buf, "hello");
        }
    "#);
    assert_eq!(r.holes0.len(), 1, "expected one definite overflow");
    assert!(r.holes0[0].contains("buf@f()"));
    // "hello" is 6 bytes incl. NUL; buf holds 4.
    assert!(r.holes0[0].contains("4..4 bytes allocated"));
    assert!(r.holes0[0].contains("6..6 bytes used"));
}

/// A buffer large enough for the literal is not flagged.
#[test]
fn no_overflow_when_buffer_fits() {
    let r = run(r#"
        void f() {
            char buf[16];
            strcpy(buf, "hello");
        }
    "#);
    assert_eq!(r.total_holes(), 0, "no overflow expected");
}

/// `gethostbyname()`'s result has unbounded length, so copying it into a
/// fixed buffer is flagged with `len = ..+Infinity` (the classic example).
#[test]
fn gethostbyname_unbounded() {
    let r = run(r#"
        struct hostent { char *h_name; int h_length; };
        struct hostent *gethostbyname(char *);
        void f() {
            char host[64];
            struct hostent *hp;
            hp = gethostbyname("x");
            strcpy(host, hp->h_name);
        }
    "#);
    assert!(r.total_holes() >= 1);
    let all = format!("{:?}", r);
    assert!(all.contains("host@f()"));
    assert!(all.contains("+Infinity"));
}

/// Merging two call sites of one function widens a parameter's length range,
/// reproducing the `fatal("pipe")` / `fatal("fdopen")` "slight chance" case.
#[test]
fn merged_call_sites_slight_chance() {
    let r = run(r#"
        void use(char *p) { char b[1]; strcpy(b, p); }
        void g(char *msg) { use(msg); }
        void caller() {
            g("pipe");
            g("fdopen");
        }
    "#);
    // msg merges 5 ("pipe") and 7 ("fdopen") => 5..7 alloc / 5..7 used.
    let all = format!("{:?}", r);
    assert!(all.contains("msg@g()"), "got: {}", all);
}

/// Distinct local variables in different functions must not be merged.
#[test]
fn locals_are_function_scoped() {
    let r = run(r#"
        void a() { char buf[4]; strcpy(buf, "ok"); }
        void b() { char buf[2]; strcpy(buf, "toolong"); }
    "#);
    // a's buf (4) holds "ok" (3) -> safe; only b's buf (2) overflows.
    assert_eq!(r.total_holes(), 1);
    assert!(format!("{:?}", r).contains("buf@b()"));
}
