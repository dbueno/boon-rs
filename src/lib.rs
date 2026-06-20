//! BOON, ported to Rust.
//!
//! A static analysis that looks for buffer overruns in C source, faithful to
//! David Wagner's original BOON (the SML implementation in `boon-1.0/`), but
//! parsing with tree-sitter-c instead of the original C parser.
//!
//! Pipeline: [`parse`] turns C source (a tree-sitter CST) into the simplified
//! [`ast`]; [`walk`] traverses the AST and emits range constraints over string
//! `(siz, len)` pairs and integers via [`constraint`]; [`solver`] finds the
//! least range solution and reports any buffer that could hold a string longer
//! than its allocation.

pub mod ast;
pub mod constraint;
pub mod ctype;
pub mod parse;
pub mod range;
pub mod solver;
pub mod walk;
