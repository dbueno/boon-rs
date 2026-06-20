//! A simplified C abstract syntax tree.
//!
//! This is the data the analysis ([`crate::walk`]) consumes. It is built from
//! a tree-sitter-c concrete syntax tree by [`crate::parse`]. It keeps only the
//! structure BOON cares about; many C details (qualifiers, exact integer
//! widths, attributes, ...) are deliberately dropped.
//!
//! The node set corresponds to the constructors handled in the original
//! `walk.sml` (`AST.Variable`, `AST.Operation`, `AST.Application`, ...).

use crate::ctype::CType;

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
}

/// Unary operators (and the prefix/postfix increment/decrement forms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
    BitNot,
    Deref,
    Address,
    PreInc,
    PreDec,
    PostInc,
    PostDec,
}

/// Expressions.
#[derive(Debug, Clone)]
pub enum Expr {
    /// An identifier reference (raw source name; scoping is resolved in walk).
    Var(String),
    IntConst(i64),
    /// A character constant `'a'`. Modelled as `None`.
    CharConst,
    /// A string literal; holds the *decoded* contents (without surrounding
    /// quotes, with escapes interpreted enough to count length).
    StrConst(String),
    /// Any other constant (floating point, etc.). Modelled as `None`.
    OtherConst,
    Conditional(Box<Expr>, Box<Expr>, Box<Expr>),
    /// Function application: callee and argument list.
    Call(Box<Expr>, Vec<Expr>),
    Unary(UnOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// Assignment `lhs op= rhs`. `op` is `None` for a plain `=`.
    Assign(Box<Expr>, Option<BinOp>, Box<Expr>),
    Comma(Box<Expr>, Box<Expr>),
    Cast(CType, Box<Expr>),
    SizeofExpr(Box<Expr>),
    SizeofType(CType),
    /// `e.id` (arrow == false) or `e->id` (arrow == true).
    Field(Box<Expr>, String, bool),
    /// `a[i]`.
    Index(Box<Expr>, Box<Expr>),
}

/// An initializer for a variable declaration.
#[derive(Debug, Clone)]
pub enum Init {
    /// `= expr`
    Single(Expr),
    /// `= { ... }` (we don't track the element detail).
    List,
}

/// A variable declaration.
#[derive(Debug, Clone)]
pub struct VarDecl {
    pub name: String,
    pub ctype: CType,
    pub init: Option<Init>,
}

/// A function parameter.
#[derive(Debug, Clone)]
pub struct Param {
    pub name: Option<String>,
    pub ctype: CType,
}

/// An item inside a block: either a declaration or a statement.
#[derive(Debug, Clone)]
pub enum BlockItem {
    Decl(VarDecl),
    Stmt(Stmt),
}

/// A block (compound statement).
pub type Block = Vec<BlockItem>;

/// Statements.
#[derive(Debug, Clone)]
pub enum Stmt {
    /// `return e;`
    Return(Option<Expr>),
    /// An expression statement.
    Expr(Expr),
    If(Expr, Box<Stmt>, Option<Box<Stmt>>),
    While(Expr, Box<Stmt>),
    DoWhile(Box<Stmt>, Expr),
    For(Option<Expr>, Option<Expr>, Option<Expr>, Box<Stmt>),
    Switch(Expr, Box<Stmt>),
    /// `case`/`default` with an optional inner statement.
    Case(Option<Box<Stmt>>),
    /// A labeled statement (label dropped).
    Labeled(Option<Box<Stmt>>),
    Goto,
    Break,
    Continue,
    Block(Block),
    /// A declaration appearing where a statement is expected (C99). Carried so
    /// nested blocks can declare locals.
    Decl(VarDecl),
}

/// Top-level declarations.
#[derive(Debug, Clone)]
pub enum TopDecl {
    Var(VarDecl),
    /// A function definition (with body).
    FunDef {
        name: String,
        return_type: CType,
        params: Vec<Param>,
        body: Block,
    },
    /// A function prototype.
    FunDecl {
        name: String,
        return_type: CType,
        /// `None` for old-style declarations with no parameter list.
        params: Option<Vec<Param>>,
    },
    /// A `typedef name = ctype`.
    TypeDef { name: String, ctype: CType },
    /// A `struct`/`union` definition (registers fields).
    StructDef {
        tag: String,
        fields: Vec<(String, CType)>,
    },
}

/// A parsed translation unit.
#[derive(Debug, Clone)]
pub struct Program {
    pub decls: Vec<TopDecl>,
}
