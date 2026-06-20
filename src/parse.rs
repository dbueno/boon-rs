//! Build the simplified [`crate::ast`] from a tree-sitter-c parse tree.
//!
//! This replaces BOON's original hand-written C parser. We translate only the
//! constructs the analysis understands; anything unrecognized degrades to a
//! harmless `None`-typed expression or is skipped, which keeps the analyzer
//! robust on real-world (preprocessed) source.

use crate::ast::*;
use crate::ctype::{CType, Deriv, Spec, Storage};
use tree_sitter::Node;

/// Parse C `source` into a [`Program`]. Returns `None` if tree-sitter fails to
/// produce a tree at all.
pub fn parse_program(source: &str) -> Option<Program> {
    let source = fixup_implicit_int(source);
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_c::language())
        .expect("load tree-sitter-c grammar");
    let tree = parser.parse(&source, None)?;
    let p = Parser {
        src: source.as_bytes(),
    };
    let mut decls = Vec::new();
    let root = tree.root_node();
    let mut cur = root.walk();
    for child in root.named_children(&mut cur) {
        p.top_decl(child, &mut decls);
    }
    Some(Program { decls })
}

struct Parser<'a> {
    src: &'a [u8],
}

/// Pre-ANSI C allows an omitted return type (implicit `int`), e.g.
/// `main(void) { ... }` or `fatal(char *msg) { ... }`. tree-sitter-c cannot
/// parse these — it mistakes the function name for the return type — so we
/// prepend an explicit `int ` to top-level lines that begin with
/// `identifier(`. This is conservative: such a line is, in valid C, either an
/// implicit-`int` function definition or prototype, both of which become
/// well-formed once `int` is added. Normal typed declarations begin with a
/// type token followed by whitespace, so they are left untouched.
fn fixup_implicit_int(source: &str) -> String {
    const KEYWORDS: &[&str] = &[
        "if", "for", "while", "switch", "return", "sizeof", "do", "else", "goto", "case",
        "default", "break", "continue", "typedef", "struct", "union", "enum", "static", "extern",
        "const", "volatile", "register", "auto", "inline", "signed", "unsigned", "void", "char",
        "short", "int", "long", "float", "double", "_Bool", "_Complex", "asm", "__asm__",
        "__inline__", "__extension__",
    ];
    let mut out = String::with_capacity(source.len() + 64);
    for line in source.split_inclusive('\n') {
        if starts_with_implicit_int_def(line, KEYWORDS) {
            out.push_str("int ");
        }
        out.push_str(line);
    }
    out
}

fn starts_with_implicit_int_def(line: &str, keywords: &[&str]) -> bool {
    // Must start at column 0 (no leading whitespace) with an identifier that is
    // immediately followed by `(`.
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let c0 = bytes[0];
    if !(c0.is_ascii_alphabetic() || c0 == b'_') {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    let ident = &line[..i];
    // Skip optional spaces/tabs between the identifier and `(`.
    let mut j = i;
    while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
        j += 1;
    }
    if j >= bytes.len() || bytes[j] != b'(' {
        return false;
    }
    !keywords.contains(&ident)
}

/// Result of parsing a declarator: the declared name and the derivation chain,
/// plus function parameters if it declares a function (not a function pointer).
struct DeclInfo {
    name: Option<String>,
    derivs: Vec<Deriv>,
    func_params: Option<Vec<Param>>,
    /// Whether a parenthesized declarator wrapped the name (=> function pointer
    /// rather than a function declaration).
    via_parens: bool,
}

impl<'a> Parser<'a> {
    fn text(&self, n: Node) -> String {
        n.utf8_text(self.src).unwrap_or("").to_string()
    }

    // ------------------------------------------------------------------
    // Top-level declarations
    // ------------------------------------------------------------------

    fn top_decl(&self, n: Node, out: &mut Vec<TopDecl>) {
        match n.kind() {
            "function_definition" => self.function_definition(n, out),
            "declaration" => self.declaration(n, out),
            "type_definition" => self.type_definition(n, out),
            "struct_specifier" | "union_specifier" => {
                // A bare struct/union definition: register its fields.
                self.register_struct(n, out);
            }
            // Preprocessor leftovers, comments, empty ';', etc. are ignored.
            _ => {}
        }
    }

    fn function_definition(&self, n: Node, out: &mut Vec<TopDecl>) {
        let (spec, storage) = self.type_spec(n, out);
        let decl = match n.child_by_field_name("declarator") {
            Some(d) => d,
            None => return,
        };
        let info = self.declarator(decl, out);

        // Work around a tree-sitter quirk: an implicit-`int` definition such
        // as `main(void) { ... }` is parsed with the function *name* as the
        // return type (`type_identifier`) and the parameters as a
        // `parenthesized_declarator`. Detect that (no real function_declarator
        // was found) and reinterpret.
        if info.func_params.is_none() {
            if let Spec::Named(fname) = &spec {
                let params = self.kr_params(decl, out);
                let body = match n.child_by_field_name("body") {
                    Some(b) => self.block(b, out),
                    None => Vec::new(),
                };
                out.push(TopDecl::FunDef {
                    name: fname.clone(),
                    return_type: CType::int(),
                    params,
                    body,
                });
                return;
            }
        }

        let name = match info.name {
            Some(s) => s,
            None => return,
        };
        let params = info.func_params.unwrap_or_default();
        // Return type = base spec + derivs collected outside the function.
        let return_type = CType {
            storage,
            spec,
            derivs: info.derivs,
        };
        let body = match n.child_by_field_name("body") {
            Some(b) => self.block(b, out),
            None => Vec::new(),
        };
        out.push(TopDecl::FunDef {
            name,
            return_type,
            params,
            body,
        });
    }

    fn declaration(&self, n: Node, out: &mut Vec<TopDecl>) {
        let (spec, storage) = self.type_spec(n, out);
        // Each declaration can declare several names.
        let mut cur = n.walk();
        for child in n.named_children(&mut cur) {
            if !is_declarator(child.kind()) {
                continue;
            }
            let (declarator, init) = self.split_init(child);
            let info = self.declarator(declarator, out);
            let name = match info.name {
                Some(ref s) => s.clone(),
                None => continue,
            };
            let ctype = CType {
                storage,
                spec: spec.clone(),
                derivs: info.derivs.clone(),
            };
            if let Some(params) = info.func_params {
                if !info.via_parens {
                    // A function prototype.
                    out.push(TopDecl::FunDecl {
                        name,
                        return_type: ctype,
                        params: Some(params),
                    });
                    continue;
                }
                // else: a function-pointer variable -> fall through as a var.
            }
            out.push(TopDecl::Var(VarDecl {
                name,
                ctype,
                init,
            }));
        }
    }

    fn type_definition(&self, n: Node, out: &mut Vec<TopDecl>) {
        let (spec, _storage) = self.type_spec(n, out);
        let type_node = n.child_by_field_name("type");
        let mut cur = n.walk();
        for child in n.named_children(&mut cur) {
            // Skip the base type specifier; everything else is a declarator.
            // In a typedef the new name is a bare `type_identifier`, so accept
            // that here (it is not treated as a declarator elsewhere).
            if Some(child) == type_node {
                continue;
            }
            if !is_declarator(child.kind()) && child.kind() != "type_identifier" {
                continue;
            }
            let info = self.declarator(child, out);
            if let Some(name) = info.name {
                out.push(TopDecl::TypeDef {
                    name,
                    ctype: CType {
                        storage: None,
                        spec: spec.clone(),
                        derivs: info.derivs,
                    },
                });
            }
        }
    }

    /// Register a `struct`/`union` definition's fields as a [`TopDecl::StructDef`].
    fn register_struct(&self, n: Node, out: &mut Vec<TopDecl>) -> Option<String> {
        let tag = n.child_by_field_name("name").map(|t| self.text(t))?;
        let body = n.child_by_field_name("body")?;
        let fields = self.struct_fields(body, out);
        out.push(TopDecl::StructDef {
            tag: tag.clone(),
            fields,
        });
        Some(tag)
    }

    fn struct_fields(&self, body: Node, out: &mut Vec<TopDecl>) -> Vec<(String, CType)> {
        let mut fields = Vec::new();
        let mut cur = body.walk();
        for fd in body.named_children(&mut cur) {
            if fd.kind() != "field_declaration" {
                continue;
            }
            let (spec, storage) = self.type_spec(fd, out);
            let mut fcur = fd.walk();
            for child in fd.named_children(&mut fcur) {
                if !is_declarator(child.kind()) {
                    continue;
                }
                let info = self.declarator(child, out);
                if let Some(name) = info.name {
                    fields.push((
                        name,
                        CType {
                            storage,
                            spec: spec.clone(),
                            derivs: info.derivs,
                        },
                    ));
                }
            }
        }
        fields
    }

    // ------------------------------------------------------------------
    // Type specifiers and declarators
    // ------------------------------------------------------------------

    /// Extract the base [`Spec`] and storage class from a node that has a
    /// `type` field. Side effect: registers any inline struct defs.
    fn type_spec(&self, n: Node, out: &mut Vec<TopDecl>) -> (Spec, Option<Storage>) {
        let mut storage = None;
        let mut cur = n.walk();
        for child in n.named_children(&mut cur) {
            if child.kind() == "storage_class_specifier" {
                match self.text(child).as_str() {
                    "static" => storage = Some(Storage::Static),
                    "extern" => storage = Some(Storage::Extern),
                    _ => {}
                }
            }
        }
        let spec = match n.child_by_field_name("type") {
            Some(t) => self.spec_from_node(t, out),
            None => Spec::Int, // implicit int
        };
        (spec, storage)
    }

    fn spec_from_node(&self, t: Node, out: &mut Vec<TopDecl>) -> Spec {
        match t.kind() {
            "primitive_type" => prim_spec(&self.text(t)),
            "sized_type_specifier" => {
                let txt = self.text(t);
                if txt.contains("char") {
                    Spec::Char
                } else if txt.contains("double") || txt.contains("float") {
                    Spec::Real
                } else {
                    Spec::Int
                }
            }
            "type_identifier" => Spec::Named(self.text(t)),
            "struct_specifier" | "union_specifier" => {
                if t.child_by_field_name("body").is_some() {
                    if let Some(tag) = self.register_struct(t, out) {
                        Spec::NamedAggregate(tag)
                    } else {
                        let body = t.child_by_field_name("body").unwrap();
                        Spec::Aggregate {
                            tag: None,
                            fields: Some(self.struct_fields(body, out)),
                        }
                    }
                } else if let Some(name) = t.child_by_field_name("name") {
                    Spec::NamedAggregate(self.text(name))
                } else {
                    Spec::Aggregate {
                        tag: None,
                        fields: None,
                    }
                }
            }
            "enum_specifier" => Spec::Int,
            _ => Spec::Int,
        }
    }

    /// Split an `init_declarator` into (declarator, optional init).
    fn split_init<'t>(&self, n: Node<'t>) -> (Node<'t>, Option<Init>) {
        if n.kind() == "init_declarator" {
            let decl = n.child_by_field_name("declarator").unwrap_or(n);
            let init = n.child_by_field_name("value").map(|v| self.initializer(v));
            (decl, init)
        } else {
            (n, None)
        }
    }

    fn initializer(&self, n: Node) -> Init {
        if n.kind() == "initializer_list" {
            Init::List
        } else {
            Init::Single(self.expr(n))
        }
    }

    /// Parse a declarator, returning the name and derivation chain
    /// (outermost-first).
    fn declarator(&self, n: Node, out: &mut Vec<TopDecl>) -> DeclInfo {
        match n.kind() {
            "identifier" | "field_identifier" | "type_identifier" => DeclInfo {
                name: Some(self.text(n)),
                derivs: Vec::new(),
                func_params: None,
                via_parens: false,
            },
            "init_declarator" => {
                let d = n.child_by_field_name("declarator").unwrap_or(n);
                self.declarator(d, out)
            }
            "pointer_declarator" => {
                let inner = n.child_by_field_name("declarator");
                let mut info = inner
                    .map(|d| self.declarator(d, out))
                    .unwrap_or_else(DeclInfo::empty);
                info.derivs.insert(0, Deriv::Pointer);
                info
            }
            "array_declarator" => {
                let inner = n.child_by_field_name("declarator");
                let mut info = inner
                    .map(|d| self.declarator(d, out))
                    .unwrap_or_else(DeclInfo::empty);
                let size = n.child_by_field_name("size").and_then(|s| self.const_int(s));
                info.derivs.insert(0, Deriv::Array(size));
                info
            }
            "function_declarator" => {
                let inner = n.child_by_field_name("declarator");
                let mut info = inner
                    .map(|d| self.declarator(d, out))
                    .unwrap_or_else(DeclInfo::empty);
                let params = self.parameters(n, out);
                if info.func_params.is_none() {
                    info.func_params = Some(params);
                }
                info
            }
            "parenthesized_declarator" => {
                let mut info = DeclInfo::empty();
                let mut cur = n.walk();
                for child in n.named_children(&mut cur) {
                    if is_declarator(child.kind()) {
                        info = self.declarator(child, out);
                        break;
                    }
                }
                info.via_parens = true;
                info
            }
            "abstract_pointer_declarator" => {
                let mut info = n
                    .named_child(0)
                    .filter(|c| is_declarator(c.kind()))
                    .map(|d| self.declarator(d, out))
                    .unwrap_or_else(DeclInfo::empty);
                info.derivs.insert(0, Deriv::Pointer);
                info
            }
            "abstract_array_declarator" => {
                let mut info = n
                    .named_child(0)
                    .filter(|c| is_declarator(c.kind()))
                    .map(|d| self.declarator(d, out))
                    .unwrap_or_else(DeclInfo::empty);
                let size = n.child_by_field_name("size").and_then(|s| self.const_int(s));
                info.derivs.insert(0, Deriv::Array(size));
                info
            }
            "abstract_function_declarator" => {
                let mut info = DeclInfo::empty();
                info.func_params = Some(self.parameters(n, out));
                info
            }
            _ => DeclInfo::empty(),
        }
    }

    /// Extract parameters from the misparsed declarator of an implicit-`int`
    /// definition. Handles `(void)` (no params) and bare identifier names
    /// (K&R style, treated as `int`-typed for lack of better information).
    fn kr_params(&self, decl: Node, _out: &mut Vec<TopDecl>) -> Vec<Param> {
        let mut params = Vec::new();
        if decl.kind() != "parenthesized_declarator" {
            return params;
        }
        let mut cur = decl.walk();
        for child in decl.named_children(&mut cur) {
            if child.kind() == "identifier" {
                let nm = self.text(child);
                if nm != "void" {
                    params.push(Param {
                        name: Some(nm),
                        ctype: CType::int(),
                    });
                }
            }
        }
        params
    }

    fn parameters(&self, func_decl: Node, out: &mut Vec<TopDecl>) -> Vec<Param> {
        let mut params = Vec::new();
        let plist = match func_decl.child_by_field_name("parameters") {
            Some(p) => p,
            None => return params,
        };
        let mut cur = plist.walk();
        for pd in plist.named_children(&mut cur) {
            if pd.kind() != "parameter_declaration" {
                continue; // variadic '...' etc.
            }
            let (spec, storage) = self.type_spec(pd, out);
            let mut name = None;
            let mut derivs = Vec::new();
            let mut fcur = pd.walk();
            for child in pd.named_children(&mut fcur) {
                if is_declarator(child.kind()) {
                    let info = self.declarator(child, out);
                    name = info.name;
                    derivs = info.derivs;
                    break;
                }
            }
            params.push(Param {
                name,
                ctype: CType {
                    storage,
                    spec: spec.clone(),
                    derivs,
                },
            });
        }
        params
    }

    /// A type used in a cast / sizeof: `type_descriptor`.
    fn type_descriptor(&self, n: Node, out: &mut Vec<TopDecl>) -> CType {
        let spec = match n.child_by_field_name("type") {
            Some(t) => self.spec_from_node(t, out),
            None => Spec::Int,
        };
        let derivs = n
            .child_by_field_name("declarator")
            .map(|d| self.declarator(d, out).derivs)
            .unwrap_or_default();
        CType {
            storage: None,
            spec,
            derivs,
        }
    }

    // ------------------------------------------------------------------
    // Statements
    // ------------------------------------------------------------------

    fn block(&self, n: Node, out: &mut Vec<TopDecl>) -> Block {
        let mut items = Vec::new();
        let mut cur = n.walk();
        for child in n.named_children(&mut cur) {
            self.block_item(child, &mut items, out);
        }
        items
    }

    fn block_item(&self, n: Node, items: &mut Vec<BlockItem>, out: &mut Vec<TopDecl>) {
        if n.kind() == "declaration" {
            let mut tmp = Vec::new();
            self.declaration(n, &mut tmp);
            for td in tmp {
                match td {
                    TopDecl::Var(v) => items.push(BlockItem::Decl(v)),
                    // Local typedefs/struct defs/protos: hoist to top level so
                    // their types/fields are visible to the analysis.
                    other => out.push(other),
                }
            }
        } else if let Some(s) = self.stmt(n, out) {
            items.push(BlockItem::Stmt(s));
        }
    }

    fn stmt(&self, n: Node, out: &mut Vec<TopDecl>) -> Option<Stmt> {
        let s = match n.kind() {
            "compound_statement" => Stmt::Block(self.block(n, out)),
            "expression_statement" => match n.named_child(0) {
                Some(e) if is_expr(e.kind()) => Stmt::Expr(self.expr(e)),
                _ => return None,
            },
            "return_statement" => {
                let e = n
                    .named_child(0)
                    .filter(|c| is_expr(c.kind()))
                    .map(|c| self.expr(c));
                Stmt::Return(e)
            }
            "if_statement" => {
                let cond = self.cond_expr(n);
                let cons = n
                    .child_by_field_name("consequence")
                    .and_then(|c| self.stmt(c, out))
                    .unwrap_or(Stmt::Block(Vec::new()));
                let alt = n
                    .child_by_field_name("alternative")
                    .and_then(|a| {
                        let target = if a.kind() == "else_clause" {
                            a.named_child(0).unwrap_or(a)
                        } else {
                            a
                        };
                        self.stmt(target, out)
                    })
                    .map(Box::new);
                Stmt::If(cond, Box::new(cons), alt)
            }
            "while_statement" => {
                let cond = self.cond_expr(n);
                let body = n
                    .child_by_field_name("body")
                    .and_then(|b| self.stmt(b, out))
                    .unwrap_or(Stmt::Block(Vec::new()));
                Stmt::While(cond, Box::new(body))
            }
            "do_statement" => {
                let body = n
                    .child_by_field_name("body")
                    .and_then(|b| self.stmt(b, out))
                    .unwrap_or(Stmt::Block(Vec::new()));
                let cond = self.cond_expr(n);
                Stmt::DoWhile(Box::new(body), cond)
            }
            "for_statement" => self.for_statement(n, out),
            "switch_statement" => {
                let cond = self.cond_expr(n);
                let body = n
                    .child_by_field_name("body")
                    .and_then(|b| self.stmt(b, out))
                    .unwrap_or(Stmt::Block(Vec::new()));
                Stmt::Switch(cond, Box::new(body))
            }
            "case_statement" => {
                let mut inner = None;
                let mut cur = n.walk();
                for child in n.named_children(&mut cur) {
                    if is_stmt(child.kind()) {
                        inner = self.stmt(child, out).map(Box::new);
                        break;
                    }
                }
                Stmt::Case(inner)
            }
            "labeled_statement" => {
                let mut lc = n.walk();
                let inner = n
                    .named_children(&mut lc)
                    .find(|c| is_stmt(c.kind()))
                    .and_then(|c| self.stmt(c, out))
                    .map(Box::new);
                Stmt::Labeled(inner)
            }
            "goto_statement" => Stmt::Goto,
            "break_statement" => Stmt::Break,
            "continue_statement" => Stmt::Continue,
            "declaration" => {
                let mut tmp = Vec::new();
                self.declaration(n, &mut tmp);
                let mut decls: Vec<VarDecl> = Vec::new();
                for td in tmp {
                    match td {
                        TopDecl::Var(v) => decls.push(v),
                        other => out.push(other),
                    }
                }
                if decls.is_empty() {
                    return None;
                }
                let items = decls.into_iter().map(BlockItem::Decl).collect();
                Stmt::Block(items)
            }
            _ => return None,
        };
        Some(s)
    }

    fn for_statement(&self, n: Node, out: &mut Vec<TopDecl>) -> Stmt {
        let init = n.child_by_field_name("initializer").and_then(|c| {
            if is_expr(c.kind()) {
                Some(self.expr(c))
            } else {
                None
            }
        });
        // A declaration in the for-initializer: hoist the declared vars so the
        // analysis sees them (flow-insensitive, so position does not matter).
        if let Some(c) = n.child_by_field_name("initializer") {
            if c.kind() == "declaration" {
                let mut tmp = Vec::new();
                self.declaration(c, &mut tmp);
                for td in tmp {
                    out.push(td);
                }
            }
        }
        let cond = n.child_by_field_name("condition").map(|c| self.expr(c));
        let update = n.child_by_field_name("update").map(|c| self.expr(c));
        let body = n
            .child_by_field_name("body")
            .and_then(|b| self.stmt(b, out))
            .unwrap_or(Stmt::Block(Vec::new()));
        Stmt::For(init, cond, update, Box::new(body))
    }

    fn cond_expr(&self, n: Node) -> Expr {
        match n.child_by_field_name("condition") {
            Some(c) => {
                let inner = if c.kind() == "parenthesized_expression" {
                    c.named_child(0).unwrap_or(c)
                } else {
                    c
                };
                self.expr(inner)
            }
            None => Expr::OtherConst,
        }
    }

    // ------------------------------------------------------------------
    // Expressions
    // ------------------------------------------------------------------

    fn expr(&self, n: Node) -> Expr {
        match n.kind() {
            "identifier" => Expr::Var(self.text(n)),
            "number_literal" => match self.const_int(n) {
                Some(i) => Expr::IntConst(i),
                None => Expr::OtherConst, // floating-point etc.
            },
            "char_literal" => Expr::CharConst,
            "string_literal" => Expr::StrConst(self.string_content(n)),
            "concatenated_string" => {
                let mut s = String::new();
                let mut cur = n.walk();
                for child in n.named_children(&mut cur) {
                    if child.kind() == "string_literal" {
                        s.push_str(&self.string_content(child));
                    }
                }
                Expr::StrConst(s)
            }
            "true" | "false" => Expr::IntConst(if n.kind() == "true" { 1 } else { 0 }),
            "null" => Expr::OtherConst,
            "parenthesized_expression" => n
                .named_child(0)
                .map(|c| self.expr(c))
                .unwrap_or(Expr::OtherConst),
            "comma_expression" => {
                let l = n.child_by_field_name("left").map(|c| self.expr(c));
                let r = n.child_by_field_name("right").map(|c| self.expr(c));
                match (l, r) {
                    (Some(a), Some(b)) => Expr::Comma(Box::new(a), Box::new(b)),
                    _ => Expr::OtherConst,
                }
            }
            "conditional_expression" => {
                let c = self.field_expr(n, "condition");
                let t = self.field_expr(n, "consequence");
                let e = self.field_expr(n, "alternative");
                Expr::Conditional(Box::new(c), Box::new(t), Box::new(e))
            }
            "assignment_expression" => {
                let lhs = self.field_expr(n, "left");
                let rhs = self.field_expr(n, "right");
                let op = n
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .and_then(|o| compound_assign_op(&o));
                Expr::Assign(Box::new(lhs), op, Box::new(rhs))
            }
            "binary_expression" => {
                let lhs = self.field_expr(n, "left");
                let rhs = self.field_expr(n, "right");
                let op = n
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .and_then(|o| bin_op(&o))
                    .unwrap_or(BinOp::Add);
                Expr::Binary(op, Box::new(lhs), Box::new(rhs))
            }
            "unary_expression" => {
                let arg = self.field_expr(n, "argument");
                let op = n
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or_default();
                let uop = match op.as_str() {
                    "-" => UnOp::Neg,
                    "!" => UnOp::Not,
                    "~" => UnOp::BitNot,
                    "+" => return arg,
                    _ => UnOp::Not,
                };
                Expr::Unary(uop, Box::new(arg))
            }
            "pointer_expression" => {
                let arg = self.field_expr(n, "argument");
                let op = n
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or_default();
                let uop = if op == "&" { UnOp::Address } else { UnOp::Deref };
                Expr::Unary(uop, Box::new(arg))
            }
            "update_expression" => {
                let arg = self.field_expr(n, "argument");
                let op = n
                    .child_by_field_name("operator")
                    .map(|o| self.text(o))
                    .unwrap_or_default();
                let prefix = n
                    .child(0)
                    .map(|c| c.kind() == "++" || c.kind() == "--")
                    .unwrap_or(false);
                let uop = match (op.as_str(), prefix) {
                    ("++", true) => UnOp::PreInc,
                    ("++", false) => UnOp::PostInc,
                    ("--", true) => UnOp::PreDec,
                    _ => UnOp::PostDec,
                };
                Expr::Unary(uop, Box::new(arg))
            }
            "call_expression" => {
                let callee = self.field_expr(n, "function");
                let mut args = Vec::new();
                if let Some(al) = n.child_by_field_name("arguments") {
                    let mut cur = al.walk();
                    for a in al.named_children(&mut cur) {
                        if is_expr(a.kind()) {
                            args.push(self.expr(a));
                        }
                    }
                }
                Expr::Call(Box::new(callee), args)
            }
            "subscript_expression" => {
                let arr = self.field_expr(n, "argument");
                let idx = self.field_expr(n, "index");
                Expr::Index(Box::new(arr), Box::new(idx))
            }
            "field_expression" => {
                let base = self.field_expr(n, "argument");
                let field = n
                    .child_by_field_name("field")
                    .map(|f| self.text(f))
                    .unwrap_or_default();
                let arrow = n
                    .child_by_field_name("operator")
                    .map(|o| self.text(o) == "->")
                    .unwrap_or(false);
                Expr::Field(Box::new(base), field, arrow)
            }
            "cast_expression" => {
                let ty = n
                    .child_by_field_name("type")
                    .map(|t| {
                        let mut sink = Vec::new();
                        self.type_descriptor(t, &mut sink)
                    })
                    .unwrap_or_else(CType::int);
                let val = self.field_expr(n, "value");
                Expr::Cast(ty, Box::new(val))
            }
            "sizeof_expression" => {
                if let Some(t) = n.child_by_field_name("type") {
                    let mut sink = Vec::new();
                    Expr::SizeofType(self.type_descriptor(t, &mut sink))
                } else if let Some(v) = n.child_by_field_name("value") {
                    let inner = if v.kind() == "parenthesized_expression" {
                        v.named_child(0).unwrap_or(v)
                    } else {
                        v
                    };
                    Expr::SizeofExpr(Box::new(self.expr(inner)))
                } else {
                    Expr::IntConst(4)
                }
            }
            "compound_literal_expression" => Expr::OtherConst,
            _ => n
                .named_child(0)
                .filter(|c| is_expr(c.kind()))
                .map(|c| self.expr(c))
                .unwrap_or(Expr::OtherConst),
        }
    }

    fn field_expr(&self, n: Node, field: &str) -> Expr {
        n.child_by_field_name(field)
            .map(|c| self.expr(c))
            .unwrap_or(Expr::OtherConst)
    }

    // ------------------------------------------------------------------
    // Literals
    // ------------------------------------------------------------------

    /// Parse an integer constant if `n` is one (handles hex/oct/dec + suffixes,
    /// and constant-folds simple integer arithmetic in array sizes).
    fn const_int(&self, n: Node) -> Option<i64> {
        match n.kind() {
            "number_literal" => parse_c_int(&self.text(n)),
            "parenthesized_expression" => n.named_child(0).and_then(|c| self.const_int(c)),
            "binary_expression" => {
                let l = n
                    .child_by_field_name("left")
                    .and_then(|c| self.const_int(c))?;
                let r = n
                    .child_by_field_name("right")
                    .and_then(|c| self.const_int(c))?;
                let op = self.text(n.child_by_field_name("operator")?);
                match op.as_str() {
                    "+" => Some(l + r),
                    "-" => Some(l - r),
                    "*" => Some(l * r),
                    "/" if r != 0 => Some(l / r),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Extract the textual content of a string literal (between quotes),
    /// interpreting escapes well enough to count its length correctly.
    fn string_content(&self, n: Node) -> String {
        let mut s = String::new();
        let mut cur = n.walk();
        for child in n.named_children(&mut cur) {
            match child.kind() {
                "string_content" => s.push_str(&self.text(child)),
                "escape_sequence" => s.push('\u{1}'), // counts as one byte
                _ => {}
            }
        }
        if s.is_empty() && n.named_child_count() == 0 {
            let raw = self.text(n);
            let trimmed = raw.trim_matches('"');
            s.push_str(trimmed);
        }
        s
    }
}

impl DeclInfo {
    fn empty() -> DeclInfo {
        DeclInfo {
            name: None,
            derivs: Vec::new(),
            func_params: None,
            via_parens: false,
        }
    }
}

fn prim_spec(s: &str) -> Spec {
    match s {
        "char" => Spec::Char,
        "void" => Spec::Void,
        "float" | "double" => Spec::Real,
        _ => Spec::Int, // bool, int, short, long, ...
    }
}

fn is_declarator(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "pointer_declarator"
            | "array_declarator"
            | "function_declarator"
            | "init_declarator"
            | "parenthesized_declarator"
            | "field_identifier"
            | "abstract_pointer_declarator"
            | "abstract_array_declarator"
            | "abstract_function_declarator"
    )
}

fn is_expr(kind: &str) -> bool {
    !matches!(
        kind,
        "comment" | ";" | "{" | "}" | "(" | ")" | "," | "type_descriptor"
    ) && !is_stmt(kind)
}

fn is_stmt(kind: &str) -> bool {
    matches!(
        kind,
        "compound_statement"
            | "expression_statement"
            | "return_statement"
            | "if_statement"
            | "while_statement"
            | "do_statement"
            | "for_statement"
            | "switch_statement"
            | "case_statement"
            | "labeled_statement"
            | "goto_statement"
            | "break_statement"
            | "continue_statement"
            | "declaration"
    )
}

fn bin_op(op: &str) -> Option<BinOp> {
    Some(match op {
        "+" => BinOp::Add,
        "-" => BinOp::Sub,
        "*" => BinOp::Mul,
        "/" => BinOp::Div,
        "%" => BinOp::Mod,
        "<" => BinOp::Lt,
        "<=" => BinOp::Le,
        ">" => BinOp::Gt,
        ">=" => BinOp::Ge,
        "==" => BinOp::Eq,
        "!=" => BinOp::Ne,
        "&&" => BinOp::And,
        "||" => BinOp::Or,
        "&" => BinOp::BitAnd,
        "|" => BinOp::BitOr,
        "^" => BinOp::BitXor,
        "<<" => BinOp::Shl,
        ">>" => BinOp::Shr,
        _ => return None,
    })
}

fn compound_assign_op(op: &str) -> Option<BinOp> {
    Some(match op {
        "+=" => BinOp::Add,
        "-=" => BinOp::Sub,
        "*=" => BinOp::Mul,
        "/=" => BinOp::Div,
        "%=" => BinOp::Mod,
        "&=" => BinOp::BitAnd,
        "|=" => BinOp::BitOr,
        "^=" => BinOp::BitXor,
        "<<=" => BinOp::Shl,
        ">>=" => BinOp::Shr,
        _ => return None, // plain "="
    })
}

/// Parse a C integer literal (decimal/hex/octal/binary, ignoring u/l suffixes).
fn parse_c_int(s: &str) -> Option<i64> {
    let t = s.trim();
    let t = t.trim_end_matches(|c| matches!(c, 'u' | 'U' | 'l' | 'L'));
    if t.is_empty() {
        return None;
    }
    let (neg, t) = if let Some(rest) = t.strip_prefix('-') {
        (true, rest)
    } else {
        (false, t)
    };
    let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).ok()?
    } else if let Some(b) = t.strip_prefix("0b").or_else(|| t.strip_prefix("0B")) {
        i64::from_str_radix(b, 2).ok()?
    } else if t.len() > 1 && t.starts_with('0') && t.chars().all(|c| c.is_ascii_digit()) {
        i64::from_str_radix(t, 8).ok()?
    } else {
        t.parse::<i64>().ok()?
    };
    Some(if neg { -v } else { v })
}
