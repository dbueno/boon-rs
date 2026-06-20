//! The analysis itself: walk the AST and emit range constraints.
//!
//! This is the Rust port of `walk.sml`, the heart of BOON. Every expression is
//! given a [`Ctx`] (the SML `Context`): a string is modelled by a `(siz, len)`
//! pair of range variables, an integer by a single range variable, and
//! everything else by `None`. Library calls (`strcpy`, `malloc`, `sprintf`,
//! ...) are modelled by [`Walker::check_str_op`]. A buffer overrun is reported
//! whenever a buffer's allocation `siz` need not be `>=` its used length `len`
//! (registered via `queryge` and checked after solving).
//!
//! The analysis is flow-insensitive: each variable (identified by name and
//! enclosing function) has a single `Ctx`, and all assignments/uses are
//! "merged" into it — exactly as in the original (see `TIPS`).

use crate::ast::*;
use crate::constraint::{QueryKind, System, Term};
use crate::ctype::{CType, Deriv, Kind, Spec, Storage, TypeEnv};
use crate::range::{self, Range};
use std::collections::{HashMap, HashSet};

/// The analysis context attached to an expression.
#[derive(Debug, Clone)]
pub enum Ctx {
    /// An integer value.
    Int(Term),
    /// A string buffer: `siz` bytes allocated, `len` bytes used (incl. `\0`).
    Str { siz: Term, len: Term },
    /// No string/integer information.
    None,
}

/// What the analysis found.
#[derive(Debug, Default)]
pub struct Report {
    /// "Almost certainly a buffer overflow" (max alloc < min len).
    pub holes0: Vec<String>,
    /// "Possibly a buffer overflow" (max alloc < max len).
    pub holes1: Vec<String>,
    /// "Slight chance of a buffer overflow" (the `X..Y / X..Y` heuristic).
    pub holes2: Vec<String>,
    /// Caveats / warnings emitted during analysis.
    pub warnings: Vec<String>,
}

impl Report {
    pub fn total_holes(&self) -> usize {
        self.holes0.len() + self.holes1.len() + self.holes2.len()
    }
}

struct VarInfo {
    ctx: Ctx,
    /// The variable's declared C type (for field/deref type resolution).
    ctype: CType,
    #[allow(dead_code)]
    visible: bool,
}

/// The special variable used to model `argv[i]` in `main` (a major kludge,
/// faithfully reproduced from the original).
const STAR_ARGV: &str = "argv[0]@main()";

pub struct Walker {
    sys: System,
    tenv: TypeEnv,
    /// Canonical-name -> variable info.
    var_map: HashMap<String, VarInfo>,
    /// Function name -> formal-parameter contexts.
    fun_map: HashMap<String, Vec<Ctx>>,
    /// Field name -> [(struct type, field context)] (merged across structs).
    struct_map: HashMap<String, Vec<(CType, Ctx)>>,
    /// Raw global name -> canonical name.
    global_canon: HashMap<String, String>,
    alloc_id: usize,
    /// The function currently being analyzed (for local naming).
    cur_func: Option<String>,
    /// Raw names of locals/params visible in the current function.
    locals: HashSet<String>,
    file: String,
    warned_strcat: bool,
    warnings: Vec<String>,
}

impl Walker {
    fn new(file: &str) -> Walker {
        Walker {
            sys: System::new(),
            tenv: TypeEnv::new(),
            var_map: HashMap::new(),
            fun_map: HashMap::new(),
            struct_map: HashMap::new(),
            global_canon: HashMap::new(),
            alloc_id: 0,
            cur_func: None,
            locals: HashSet::new(),
            file: file.to_string(),
            warned_strcat: false,
            warnings: Vec::new(),
        }
    }

    fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    // ------------------------------------------------------------------
    // Names and scoping (alpha-conversion, done lazily here)
    // ------------------------------------------------------------------

    fn fret_name(name: &str) -> String {
        format!("@{}_return", name)
    }

    fn canonical_local(&self, raw: &str) -> String {
        match &self.cur_func {
            Some(f) => format!("{}@{}()", raw, f),
            None => raw.to_string(),
        }
    }

    /// Resolve a raw identifier to its canonical (scoped) name.
    fn resolve_name(&self, raw: &str) -> String {
        if self.locals.contains(raw) {
            self.canonical_local(raw)
        } else if let Some(c) = self.global_canon.get(raw) {
            c.clone()
        } else {
            raw.to_string()
        }
    }

    // ------------------------------------------------------------------
    // Context construction
    // ------------------------------------------------------------------

    /// `freshStr`: a new `(siz, len)` pair plus the buffer-overrun query
    /// `siz >= len`.
    fn fresh_str(&mut self, name: Option<&str>) -> Ctx {
        let (siz, len) = match name {
            Some(n) => (
                self.sys.fresh(Some(format!("siz({})", n))),
                self.sys.fresh(Some(format!("len({})", n))),
            ),
            None => (self.sys.fresh(None), self.sys.fresh(None)),
        };
        let report_name = name.unwrap_or("(unnamed)").to_string();
        self.sys
            .queryge(&siz, &len, QueryKind::Overflow { name: report_name });
        Ctx::Str { siz, len }
    }

    fn fresh_alloc_str(&mut self) -> Ctx {
        let id = self.alloc_id;
        self.alloc_id += 1;
        let name = format!("alloc@{}", id);
        self.fresh_str(Some(&name))
    }

    /// String lengths grow without bound (`forceLenTop`): `1 ⊆ t` and
    /// `t+1 ⊆ t`, which drives `t` to `1..+Infinity`.
    fn force_len_top(&mut self, t: &Term) {
        self.sys.subset(&Term::constant(1), t);
        let t1 = t.add(&Term::constant(1));
        self.sys.subset(&t1, t);
    }

    /// `freshVarCtx`: build the context for a variable of the given type.
    fn fresh_var_ctx(&mut self, ty: &CType, name: &str) -> Ctx {
        // Special case `char x[N]`: seed `N ⊆ siz`.
        if let (Spec::Char, [Deriv::Array(size)]) = (&ty.spec, ty.derivs.as_slice()) {
            let s = self.fresh_str(Some(name));
            if let (Ctx::Str { siz, .. }, Some(n)) = (&s, size) {
                let nn = Term::constant(*n);
                self.sys.subset(&nn, siz);
            }
            return s;
        }
        let resolved = self.tenv.resolve(ty);
        match resolved.kind() {
            Kind::Str => self.fresh_str(Some(name)),
            Kind::Int => Ctx::Int(self.sys.fresh(Some(name.to_string()))),
            Kind::None => Ctx::None,
        }
    }

    fn get_ctx(&self, canonical: &str) -> Option<Ctx> {
        self.var_map.get(canonical).map(|v| v.ctx.clone())
    }

    /// `createVar` / `newVar`: ensure a variable exists; return its context.
    fn new_var(&mut self, canonical: &str, ty: &CType, visible: bool) -> Ctx {
        if let Some(c) = self.get_ctx(canonical) {
            return c;
        }
        let ctx = self.fresh_var_ctx(ty, canonical);
        self.var_map.insert(
            canonical.to_string(),
            VarInfo {
                ctx: ctx.clone(),
                ctype: ty.clone(),
                visible,
            },
        );
        ctx
    }

    fn get_var_type(&self, canonical: &str) -> Option<CType> {
        self.var_map.get(canonical).map(|v| v.ctype.clone())
    }

    // ------------------------------------------------------------------
    // assignment / pointer arithmetic
    // ------------------------------------------------------------------

    /// `assign (dst, src)` — the effect of `dst = src`.
    fn assign(&mut self, dst: &Ctx, src: &Ctx) {
        match (dst, src) {
            (Ctx::None, _) | (_, Ctx::None) => {}
            (Ctx::Int(di), Ctx::Int(si)) => self.sys.subset(si, di),
            (Ctx::Str { siz: ds, len: dl }, Ctx::Str { siz: ss, len: sl }) => {
                self.sys.subset(sl, dl);
                self.sys.subset(ss, ds);
            }
            // int -> string: implicit cast to char *; ignore.
            (Ctx::Str { .. }, Ctx::Int(_)) => {}
            _ => self.warn("BUG: unexpected assignment types."),
        }
    }

    /// `assign'`: assignment in an initializer — for two strings only the
    /// length flows (the size is fixed by the declaration).
    fn assign_init(&mut self, dst: &Ctx, src: &Ctx) {
        if let (Ctx::Str { len: dl, .. }, Ctx::Str { len: sl, .. }) = (dst, src) {
            self.sys.subset(sl, dl);
        } else {
            self.assign(dst, src);
        }
    }

    /// `advance (Str, Int i)` = `Str { siz - i, len - i }` (pointer + integer).
    fn advance(&self, s: &Ctx, i: &Term) -> Ctx {
        if let Ctx::Str { siz, len } = s {
            Ctx::Str {
                siz: siz.sub(i),
                len: len.sub(i),
            }
        } else {
            Ctx::None
        }
    }

    // ------------------------------------------------------------------
    // Library-call models (`checkStrOp`)
    // ------------------------------------------------------------------

    fn warn_strcat(&mut self) {
        if !self.warned_strcat {
            self.warn("str[n]cat() calls are not checked...");
            self.warned_strcat = true;
        }
    }

    /// Model a known library call. Returns `Some(result_ctx)` if `name` is a
    /// recognized string/allocation routine, else `None`.
    fn check_str_op(&mut self, name: &str, args: &[Ctx]) -> Option<Ctx> {
        match (name, args) {
            ("strcpy", [Ctx::Str { len: dl, .. }, src @ Ctx::Str { len: sl, .. }]) => {
                self.sys.subset(sl, dl);
                Some(src.clone())
            }
            ("strncpy", [dst @ Ctx::Str { len: dl, .. }, Ctx::Str { len: sl, .. }, Ctx::Int(i)]) =>
            {
                let m = self.sys.min(sl, i);
                self.sys.subset(&m, dl);
                Some(dst.clone())
            }
            ("strlen", [Ctx::Str { len, .. }]) => Some(Ctx::Int(len.sub(&Term::constant(1)))),
            ("strspn" | "strcspn", [Ctx::Str { len, .. }]) => {
                let t = self.sys.fresh(None);
                self.sys.subset(&Term::constant(0), &t);
                let lm1 = len.sub(&Term::constant(1));
                self.sys.subset(&lm1, &t);
                Some(Ctx::Int(t))
            }
            ("strdup", [Ctx::Str { len, .. }]) => {
                let new = self.fresh_alloc_str();
                if let Ctx::Str { siz: ns, len: nl } = &new {
                    self.sys.subset(len, ns);
                    self.sys.subset(len, nl);
                }
                Some(new)
            }
            ("strcat", [dst @ Ctx::Str { len: dl, .. }, Ctx::Str { len: sl, .. }]) => {
                self.warn_strcat();
                self.sys.subset(sl, dl);
                Some(dst.clone())
            }
            ("strncat", [dst @ Ctx::Str { len: dl, .. }, Ctx::Str { len: sl, .. }, Ctx::Int(i)]) =>
            {
                self.warn_strcat();
                let slm1 = sl.sub(&Term::constant(1));
                let m = self.sys.min(&slm1, i);
                let lhs = m.add(dl);
                self.sys.subset(&lhs, dl);
                Some(dst.clone())
            }
            (
                "strchr" | "strrchr" | "strstr" | "strpbrk" | "index" | "rindex",
                [Ctx::Str { siz, len }, _],
            ) => {
                let n = self.fresh_str(None);
                if let Ctx::Str { siz: ns, len: nl } = &n {
                    self.sys.subset(&Term::constant(1), ns);
                    self.sys.subset(siz, ns);
                    self.sys.subset(&Term::constant(1), nl);
                    self.sys.subset(len, nl);
                }
                Some(n)
            }
            ("fgets", [s @ Ctx::Str { len, .. }, Ctx::Int(i), _]) => {
                self.sys.subset(&Term::constant(1), len);
                self.sys.subset(i, len);
                Some(s.clone())
            }
            ("gets", [s @ Ctx::Str { len, .. }]) => {
                self.warn("Dear god, a call to gets()!");
                let len = len.clone();
                self.force_len_top(&len);
                Some(s.clone())
            }
            ("getenv", _) => {
                let t = self.sys.fresh(Some("@getenv_return".to_string()));
                self.force_len_top(&t);
                Some(Ctx::Str {
                    siz: t.clone(),
                    len: t,
                })
            }
            ("malloc" | "valloc" | "xmalloc" | "alloca" | "__builtin_alloca", [Ctx::Int(i)]) => {
                let new = self.fresh_alloc_str();
                if let Ctx::Str { siz: ns, .. } = &new {
                    self.sys.subset(i, ns);
                }
                Some(new)
            }
            ("fprintf" | "printf", _) => Some(Ctx::None),
            ("gethostbyname" | "gethostbyaddr" | "gethostbyname2", _) => {
                let hostent = CType {
                    storage: None,
                    spec: Spec::NamedAggregate("hostent".to_string()),
                    derivs: vec![],
                };
                if let Some(Ctx::Str { len: nl, .. }) = self.get_field(&hostent, "h_name") {
                    let top = self.sys.top();
                    if let Some(Ctx::Int(l)) = self.get_field(&hostent, "h_length") {
                        self.sys.subset(&top, &l);
                    }
                    self.force_len_top(&nl);
                }
                Some(Ctx::None)
            }
            ("gethostname", [Ctx::Str { len, .. }, Ctx::Int(i)]) => {
                self.sys.subset(i, len);
                Some(Ctx::None)
            }
            ("syserror", _) => {
                let t = self.sys.fresh(Some("@syserror_return".to_string()));
                self.sys.subset(&Term::constant(0), &t);
                self.sys.subset(&Term::constant(48), &t);
                Some(Ctx::Int(t))
            }
            ("syssignal", _) => {
                let t = self.sys.fresh(Some("@syssignal_return".to_string()));
                self.sys.subset(&Term::constant(0), &t);
                self.sys.subset(&Term::constant(25), &t);
                Some(Ctx::Int(t))
            }
            _ => None,
        }
    }

    // ------------------------------------------------------------------
    // Functions: formals, returns
    // ------------------------------------------------------------------

    fn apply_fun(&mut self, name: &str, args: &[Ctx]) -> Ctx {
        if let Some(x) = self.check_str_op(name, args) {
            return x;
        }
        self.do_formals(name, args);
        self.do_ret(name)
    }

    fn do_formals(&mut self, name: &str, args: &[Ctx]) {
        let formals = match self.fun_map.get(name) {
            Some(f) => f.clone(),
            None => {
                self.warn(format!("undeclared function {}().", name));
                return;
            }
        };
        if formals.len() != args.len() && !formals.is_empty() {
            self.warn(format!("Wrong number of fun args calling `{}'?", name));
        }
        for (f, a) in formals.iter().zip(args.iter()) {
            self.assign(f, a);
        }
    }

    fn do_ret(&mut self, name: &str) -> Ctx {
        let fret = Self::fret_name(name);
        match self.get_ctx(&fret) {
            Some(c) => c,
            None => {
                self.warn(format!("no return info for {}().", name));
                Ctx::None
            }
        }
    }

    /// `rememberFunParams`: record (and create) the contexts for a function's
    /// formal parameters, merging with any prototype already seen.
    fn remember_fun_params(&mut self, func: &str, params: &[Param], ignore_names: bool) {
        let prev = self.fun_map.get(func).cloned().unwrap_or_default();
        let mut new_info: Vec<Ctx> = Vec::new();
        let saved_func = self.cur_func.clone();
        self.cur_func = Some(func.to_string());
        for (i, p) in params.iter().enumerate() {
            let ctx = if let Some(existing) = prev.get(i) {
                // Reuse the prototype's context; bind the (possibly new) name.
                if !ignore_names {
                    if let Some(nm) = &p.name {
                        let canon = self.canonical_local(nm);
                        self.var_map.insert(
                            canon,
                            VarInfo {
                                ctx: existing.clone(),
                                ctype: p.ctype.clone(),
                                visible: true,
                            },
                        );
                    }
                }
                existing.clone()
            } else if ignore_names || p.name.is_none() {
                // Prototype, or unnamed parameter: a fresh, unbound context.
                let nm = p.name.clone().unwrap_or_else(|| format!("arg{}", i));
                self.fresh_var_ctx(&p.ctype, &nm)
            } else {
                // A named definition parameter: create it as a local variable.
                let nm = p.name.clone().unwrap();
                let canon = self.canonical_local(&nm);
                self.new_var(&canon, &p.ctype, true)
            };
            new_info.push(ctx);
        }
        // Keep any extra prototype contexts beyond the params we just saw.
        for c in prev.into_iter().skip(new_info.len()) {
            new_info.push(c);
        }
        self.cur_func = saved_func;
        self.fun_map.insert(func.to_string(), new_info);
    }

    // ------------------------------------------------------------------
    // Struct fields (`getField`)
    // ------------------------------------------------------------------

    fn type_eq(&self, a: &CType, b: &CType) -> bool {
        let ra = self.tenv.resolve(a);
        let rb = self.tenv.resolve(b);
        if ra.derivs.len() != rb.derivs.len() {
            return false;
        }
        spec_eq(&ra.spec, &rb.spec)
    }

    fn field_ctype(&self, ct: &CType, id: &str) -> CType {
        self.tenv.field_type(ct, id).unwrap_or_else(CType::void)
    }

    fn get_field(&mut self, ct: &CType, id: &str) -> Option<Ctx> {
        // Look for an existing field context for a compatible struct type.
        if let Some(pairs) = self.struct_map.get(id) {
            for (ct2, ctx) in pairs {
                if self.type_eq(ct, ct2) {
                    return Some(ctx.clone());
                }
            }
        }
        // Otherwise create one from the field's declared type.
        let ft = self.field_ctype(ct, id);
        let name = format!("(unnamed field {})", id);
        let ctx = self.fresh_var_ctx(&ft, &name);
        self.struct_map
            .entry(id.to_string())
            .or_default()
            .push((ct.clone(), ctx.clone()));
        Some(ctx)
    }

    // ------------------------------------------------------------------
    // Expressions
    // ------------------------------------------------------------------

    fn expr(&mut self, e: &Expr) -> (Ctx, CType) {
        match e {
            Expr::Var(raw) => {
                let canon = self.resolve_name(raw);
                match self.get_ctx(&canon) {
                    Some(c) => {
                        let ct = self.get_var_type(&canon).unwrap_or_else(CType::void);
                        (c, ct)
                    }
                    None => {
                        let ct = CType::void();
                        (self.new_unknown_var(&canon, &ct), ct)
                    }
                }
            }
            Expr::IntConst(i) => (Ctx::Int(Term::constant(*i)), CType::int()),
            Expr::CharConst => (Ctx::None, CType::char()),
            Expr::StrConst(s) => {
                let slen = (s.chars().count() as i64) + 1; // + trailing '\0'
                let l = Term::constant(slen);
                (
                    Ctx::Str {
                        siz: l.clone(),
                        len: l,
                    },
                    CType::string(),
                )
            }
            Expr::OtherConst => (Ctx::None, CType::void()),
            Expr::Conditional(c, e2, e3) => {
                let _ = self.expr(c);
                let (t2, ct2) = { let p = self.expr(e2); promote(p) };
                let (t3, _ct3) = { let p = self.expr(e3); promote(p) };
                let merged = match (&t2, &t3) {
                    (Ctx::Int(i), Ctx::Int(j)) => {
                        let t = self.sys.fresh(None);
                        self.sys.subset(i, &t);
                        self.sys.subset(j, &t);
                        Ctx::Int(t)
                    }
                    (Ctx::Str { siz: s2, len: l2 }, Ctx::Str { siz: s3, len: l3 }) => {
                        let s = self.fresh_str(None);
                        if let Ctx::Str { siz: ns, len: nl } = &s {
                            self.sys.subset(s2, ns);
                            self.sys.subset(s3, ns);
                            self.sys.subset(l2, nl);
                            self.sys.subset(l3, nl);
                        }
                        s
                    }
                    _ => Ctx::None,
                };
                (merged, ct2)
            }
            Expr::Call(callee, args) => self.call(callee, args),
            Expr::Unary(op, arg) => self.unary(*op, arg),
            Expr::Binary(op, a, b) => self.binary(*op, a, b),
            Expr::Assign(lhs, op, rhs) => self.assignment(lhs, *op, rhs),
            Expr::Comma(a, b) => {
                let _ = self.expr(a);
                { let p = self.expr(b); promote(p) }
            }
            Expr::Cast(t, e) => {
                let (ev, _) = self.expr(e);
                let ct = self.tenv.resolve(t);
                let out = match (ct.kind(), &ev) {
                    (Kind::Int, Ctx::Int(_)) => ev,
                    (Kind::Int, _) => Ctx::Int(self.sys.top()),
                    (Kind::Str, Ctx::Str { .. }) => ev,
                    (Kind::Str, _) => Ctx::None,
                    (Kind::None, _) => Ctx::None,
                };
                (out, ct)
            }
            Expr::SizeofExpr(e) => {
                let (ev, ct) = self.expr(e);
                match ev {
                    Ctx::Str { siz, .. } => (Ctx::Int(siz), CType::int()),
                    _ => (self.sizeof_type(&ct), CType::int()),
                }
            }
            Expr::SizeofType(t) => (self.sizeof_type(t), CType::int()),
            Expr::Field(base, id, arrow) => {
                if *arrow {
                    // e->id == (*e).id
                    let deref = Expr::Unary(UnOp::Deref, base.clone());
                    let field = Expr::Field(Box::new(deref), id.clone(), false);
                    self.expr(&field)
                } else {
                    let (_, ct) = { let p = self.expr(base); promote(p) };
                    let ft = self.field_ctype(&ct, id);
                    let ctx = self.get_field(&ct, id).unwrap_or(Ctx::None);
                    (ctx, ft)
                }
            }
            Expr::Index(a, i) => {
                // a[i] == *(a + i)
                let sum = Expr::Binary(BinOp::Add, a.clone(), i.clone());
                let deref = Expr::Unary(UnOp::Deref, Box::new(sum));
                self.expr(&deref)
            }
        }
    }

    fn call(&mut self, callee: &Expr, args: &[Expr]) -> (Ctx, CType) {
        // Evaluate the callee's type for the result type.
        let (_, callee_ct) = { let p = self.expr(callee); promote(p) };
        let ret_ct = callee_ct.return_type();
        let arg_ctxs: Vec<Ctx> = args.iter().map(|a| { let p = self.expr(a); promote(p) }.0).collect();
        if let Expr::Var(name) = callee {
            let ctx = match name.as_str() {
                "sprintf" => self.model_sprintf(args, &arg_ctxs),
                "snprintf" => self.model_snprintf(args, &arg_ctxs),
                _ => self.apply_fun(name, &arg_ctxs),
            };
            (ctx, ret_ct)
        } else {
            self.warn("function pointers; analysis is unsafe...");
            (Ctx::None, ret_ct)
        }
    }

    fn unary(&mut self, op: UnOp, arg: &Expr) -> (Ctx, CType) {
        match op {
            UnOp::Deref => self.eval_deref(arg),
            UnOp::Address => {
                let (_, ct) = self.expr(arg);
                self.warn("pointers; analysis is unsafe.");
                let mut ct = ct;
                ct.derivs.insert(0, Deriv::Pointer);
                (Ctx::None, ct)
            }
            UnOp::Neg => {
                let (v, ct) = self.expr(arg);
                match v {
                    Ctx::Int(i) => (Ctx::Int(i.negate()), ct),
                    _ => (Ctx::None, ct),
                }
            }
            UnOp::Not => {
                let _ = self.expr(arg);
                (Ctx::Int(self.bool_term()), CType::int())
            }
            UnOp::BitNot => {
                let (v, ct) = self.expr(arg);
                (v, ct)
            }
            UnOp::PreInc | UnOp::PostInc => {
                self.assignment(arg, Some(BinOp::Add), &Expr::IntConst(1))
            }
            UnOp::PreDec | UnOp::PostDec => {
                self.assignment(arg, Some(BinOp::Sub), &Expr::IntConst(1))
            }
        }
    }

    /// A fresh integer in `0..1` (the result of comparisons / logical ops).
    fn bool_term(&mut self) -> Term {
        let t = self.sys.fresh(None);
        self.sys.subset(&Term::constant(0), &t);
        self.sys.subset(&Term::constant(1), &t);
        t
    }

    fn binary(&mut self, op: BinOp, a: &Expr, b: &Expr) -> (Ctx, CType) {
        let (ta, cta) = { let p = self.expr(a); promote(p) };
        let (tb, _ctb) = { let p = self.expr(b); promote(p) };
        let ct = match op {
            BinOp::Add | BinOp::Sub => {
                if cta.is_pointer() || cta.is_array() {
                    cta.clone()
                } else {
                    CType::int()
                }
            }
            _ => CType::int(),
        };
        match (op, &ta, &tb) {
            (BinOp::Add, Ctx::Int(i), Ctx::Int(j)) => (Ctx::Int(i.add(j)), ct),
            (BinOp::Sub, Ctx::Int(i), Ctx::Int(j)) => (Ctx::Int(i.sub(j)), ct),
            (BinOp::Mul, Ctx::Int(i), Ctx::Int(j)) => {
                let m = self.sys.mul(i, j);
                (Ctx::Int(m), ct)
            }
            (BinOp::Div, Ctx::Int(i), Ctx::Int(j)) => {
                let d = self.sys.div(i, j);
                (Ctx::Int(d), ct)
            }
            // pointer/string + int  ->  advance
            (BinOp::Add, Ctx::Str { .. }, Ctx::Int(i)) => (self.advance(&ta, i), ct),
            // comparisons / logical / bitwise / shift / mod on ints -> 0..1
            (
                BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge | BinOp::Eq | BinOp::Ne | BinOp::Mod
                | BinOp::And | BinOp::Or | BinOp::BitAnd | BinOp::BitOr | BinOp::BitXor
                | BinOp::Shl | BinOp::Shr,
                Ctx::Int(_),
                Ctx::Int(_),
            ) => (Ctx::Int(self.bool_term()), ct),
            _ => (Ctx::None, ct),
        }
    }

    fn assignment(&mut self, lhs: &Expr, op: Option<BinOp>, rhs: &Expr) -> (Ctx, CType) {
        if let Some(o) = op {
            // lhs op= rhs  ==>  lhs = (lhs op rhs)
            let combined = Expr::Binary(o, Box::new(lhs.clone()), Box::new(rhs.clone()));
            return self.assignment(lhs, None, &combined);
        }
        let (dst, _) = self.expr(lhs);
        let (src, ct) = { let p = self.expr(rhs); promote(p) };
        self.assign(&dst, &src);
        (src, ct)
    }

    /// Evaluate `*operand`, including the `argv[i]` kludge and the
    /// "deref past the end" fencepost check.
    fn eval_deref(&mut self, operand: &Expr) -> (Ctx, CType) {
        let (octx, oct) = { let p = self.expr(operand); promote(p) };
        let result_ct = oct.deref();
        match octx {
            Ctx::Str { len, .. } => {
                // Redundant, but here for emphasis: dereferencing a string.
                self.sys.queryge(
                    &len,
                    &Term::constant(1),
                    QueryKind::Deref {
                        desc: "string dereference".to_string(),
                    },
                );
                (Ctx::None, result_ct)
            }
            Ctx::Int(_) => (Ctx::None, result_ct),
            Ctx::None => {
                // The argv[] kludge: *(argv@main()) or *(argv@main() + e).
                if self.is_argv(operand) {
                    match self.get_ctx(STAR_ARGV) {
                        Some(c) => (c, result_ct),
                        None => (Ctx::None, result_ct),
                    }
                } else {
                    (Ctx::None, result_ct)
                }
            }
        }
    }

    fn is_argv(&self, operand: &Expr) -> bool {
        // The operand is the `argv` *parameter* of main (`argv@main()`); the
        // value it dereferences to is the special `argv[0]@main()` string.
        let check = |raw: &str| self.resolve_name(raw) == "argv@main()";
        match operand {
            Expr::Var(v) => check(v),
            Expr::Binary(BinOp::Add, a, _) => {
                matches!(a.as_ref(), Expr::Var(v) if check(v))
            }
            _ => false,
        }
    }

    fn sizeof_type(&mut self, t: &CType) -> Ctx {
        let resolved = self.tenv.resolve(t);
        if !resolved.derivs.is_empty() {
            // pointer/array/function: size is platform-dependent; punt.
            return Ctx::None;
        }
        let n = match resolved.spec {
            Spec::Char => 1,
            Spec::Int => 4,
            Spec::Real => 8,
            _ => return Ctx::None,
        };
        Ctx::Int(Term::constant(n))
    }

    fn new_unknown_var(&mut self, canonical: &str, ct: &CType) -> Ctx {
        // A previously-unmentioned symbol (e.g. resolved at link time).
        self.new_var(canonical, ct, true)
    }

    // ------------------------------------------------------------------
    // printf-family format modelling
    // ------------------------------------------------------------------

    fn model_sprintf(&mut self, args: &[Expr], ctxs: &[Ctx]) -> Ctx {
        // sprintf(dst, fmt, ...)
        if let (Some(Expr::StrConst(fmt)), Some(Ctx::Str { len: dl, .. })) =
            (args.get(1), ctxs.first())
        {
            let rest = &ctxs[2.min(ctxs.len())..];
            let parsed = self.parse_fmt(fmt, rest);
            let dl = dl.clone();
            self.sys.subset(&parsed, &dl);
            return ctxs[0].clone();
        }
        match ctxs.first() {
            Some(Ctx::None) | None => {
                self.warn("sprintf(unknown,...)");
                Ctx::None
            }
            Some(dst @ Ctx::Str { len, .. }) => {
                self.warn("sprintf(.,unknown,...)");
                let len = len.clone();
                self.force_len_top(&len);
                dst.clone()
            }
            _ => {
                self.warn("Weird sprintf() call.");
                Ctx::None
            }
        }
    }

    fn model_snprintf(&mut self, args: &[Expr], ctxs: &[Ctx]) -> Ctx {
        // snprintf(dst, n, fmt, ...)
        if let (Some(Expr::StrConst(fmt)), Some(Ctx::Str { len: dl, .. }), Some(nt)) =
            (args.get(2), ctxs.first(), ctxs.get(1))
        {
            let rest = &ctxs[3.min(ctxs.len())..];
            let parsed = self.parse_fmt(fmt, rest);
            let dl = dl.clone();
            match nt {
                Ctx::Int(n) => {
                    let n = n.clone();
                    let m = self.sys.min(&parsed, &n);
                    self.sys.subset(&m, &dl);
                }
                _ => {
                    self.warn("ignoring 2nd arg...");
                    self.sys.subset(&parsed, &dl);
                }
            }
            return ctxs[0].clone();
        }
        match ctxs.first() {
            Some(Ctx::None) | None => {
                self.warn("snprintf(unknown,...)");
                Ctx::None
            }
            _ => {
                self.warn("Weird snprintf() call.");
                Ctx::None
            }
        }
    }

    /// `parseFmt`: compute a term for the length of the string produced by a
    /// printf-style format `f` with the given following argument contexts.
    fn parse_fmt(&mut self, f: &str, pl: &[Ctx]) -> Term {
        let chars: Vec<char> = f.chars().collect();
        let mut pli = 0usize;
        self.fmt_scan(&chars, 0, pl, &mut pli)
    }

    fn fmt_scan(&mut self, f: &[char], i: usize, pl: &[Ctx], pli: &mut usize) -> Term {
        if i >= f.len() {
            return Term::constant(1); // the trailing '\0'
        }
        if f[i] == '%' {
            if i + 1 >= f.len() {
                return Term::constant(2);
            }
            if f[i + 1] == '%' {
                let rest = self.fmt_scan(f, i + 2, pl, pli);
                return Term::constant(1).add(&rest);
            }
            return self.expand_percent(f, i + 1, pl, pli);
        }
        let rest = self.fmt_scan(f, i + 1, pl, pli);
        Term::constant(1).add(&rest)
    }

    fn expand_percent(&mut self, f: &[char], mut i: usize, pl: &[Ctx], pli: &mut usize) -> Term {
        // Skip flags.
        while i < f.len() && matches!(f[i], '#' | '0' | '-' | '+' | 'h' | 'l' | 'L' | ' ') {
            i += 1;
        }
        // Width.
        let (width, i2) = self.read_num(f, i, pl, pli);
        i = i2;
        // Precision.
        let mut prec = None;
        if i < f.len() && f[i] == '.' {
            let (p, i3) = self.read_num(f, i + 1, pl, pli);
            prec = p;
            i = i3;
        }
        if i >= f.len() {
            return Term::constant(1);
        }
        let c = f[i];
        self.expand_conv(c, width, prec, f, i + 1, pl, pli)
    }

    /// Read an optional width/precision number (`*` consumes an int argument).
    fn read_num(
        &mut self,
        f: &[char],
        i: usize,
        pl: &[Ctx],
        pli: &mut usize,
    ) -> (Option<Term>, usize) {
        if i < f.len() && f[i] == '*' {
            // Consume an int argument as the width/precision.
            let t = match pl.get(*pli) {
                Some(Ctx::Int(x)) => Some(x.clone()),
                _ => None,
            };
            *pli += 1;
            return (t, i + 1);
        }
        let start = i;
        let mut j = i;
        while j < f.len() && f[j].is_ascii_digit() {
            j += 1;
        }
        if j > start {
            let n: i64 = f[start..j].iter().collect::<String>().parse().unwrap_or(0);
            (Some(Term::constant(n)), j)
        } else {
            (None, j)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn expand_conv(
        &mut self,
        c: char,
        width: Option<Term>,
        prec: Option<Term>,
        f: &[char],
        next: usize,
        pl: &[Ctx],
        pli: &mut usize,
    ) -> Term {
        let body = if c == 's' {
            let n = match pl.get(*pli) {
                Some(Ctx::Str { len, .. }) => len.sub(&Term::constant(1)),
                _ => {
                    let t = self.sys.fresh(None);
                    self.force_len_top(&t);
                    t
                }
            };
            *pli += 1;
            let n1 = match &prec {
                Some(m) => self.sys.min(m, &n),
                None => n.clone(),
            };
            match &width {
                Some(m) => self.sys.union_term(m, &n),
                None => n1,
            }
        } else if "dixXuU".contains(c) {
            *pli += 1;
            let t = self.sys.fresh(None);
            self.sys.subset(&Term::constant(1), &t);
            self.sys.subset(&Term::constant(20), &t);
            t
        } else if c == 'o' {
            *pli += 1;
            let t = self.sys.fresh(None);
            self.sys.subset(&Term::constant(1), &t);
            self.sys.subset(&Term::constant(22), &t);
            t
        } else if c == 'c' {
            *pli += 1;
            Term::constant(1)
        } else if "eEfgG".contains(c) {
            *pli += 1;
            let t = self.sys.fresh(None);
            self.sys.subset(&Term::constant(1), &t);
            self.sys.subset(&Term::constant(32), &t);
            t
        } else if c == 'p' {
            *pli += 1;
            let t = self.sys.fresh(None);
            self.sys.subset(&Term::constant(1), &t);
            self.sys.subset(&Term::constant(20), &t);
            t
        } else {
            // Unknown conversion: be conservative, contribute one byte.
            Term::constant(1)
        };
        let rest = self.fmt_scan(f, next, pl, pli);
        body.add(&rest)
    }

    // ------------------------------------------------------------------
    // Statements and declarations
    // ------------------------------------------------------------------

    fn stmt(&mut self, s: &Stmt) {
        match s {
            Stmt::Return(Some(e)) => {
                if let Some(func) = self.cur_func.clone() {
                    let fret = Self::fret_name(&func);
                    if let Some(fctx) = self.get_ctx(&fret) {
                        let (ec, _) = self.expr(e);
                        self.assign(&fctx, &ec);
                        return;
                    }
                }
                let _ = self.expr(e);
            }
            Stmt::Return(None) => {}
            Stmt::Expr(e) => {
                let _ = self.expr(e);
            }
            Stmt::If(c, t, e) => {
                let _ = self.expr(c);
                self.stmt(t);
                if let Some(e) = e {
                    self.stmt(e);
                }
            }
            Stmt::While(c, b) | Stmt::Switch(c, b) => {
                let _ = self.expr(c);
                self.stmt(b);
            }
            Stmt::DoWhile(b, c) => {
                let _ = self.expr(c);
                self.stmt(b);
            }
            Stmt::For(i, c, u, b) => {
                if let Some(i) = i {
                    let _ = self.expr(i);
                }
                if let Some(c) = c {
                    let _ = self.expr(c);
                }
                if let Some(u) = u {
                    let _ = self.expr(u);
                }
                self.stmt(b);
            }
            Stmt::Case(Some(s)) | Stmt::Labeled(Some(s)) => self.stmt(s),
            Stmt::Case(None) | Stmt::Labeled(None) => {}
            Stmt::Goto | Stmt::Break | Stmt::Continue => {}
            Stmt::Block(items) => self.walk_block(items),
            Stmt::Decl(v) => self.decl_two(v),
        }
    }

    /// Walk a block: declarations were already created in the function's first
    /// sub-pass; here we run their initializers and the statements in order.
    fn walk_block(&mut self, items: &[BlockItem]) {
        for it in items {
            match it {
                BlockItem::Decl(v) => self.decl_two(v),
                BlockItem::Stmt(s) => self.stmt(s),
            }
        }
    }

    /// `declaration Two`: process a variable declaration's initializer.
    fn decl_two(&mut self, v: &VarDecl) {
        let canon = self.canonical_local(&v.name);
        // Ensure the variable exists (it should already).
        let var_ctx = self.new_var(&canon, &v.ctype, true);
        match &v.init {
            None => {}
            Some(Init::Single(e)) => {
                let (src, _) = self.expr(e);
                self.do_init(&v.ctype, &var_ctx, e, &src);
            }
            Some(Init::List) => {
                self.warn("VarDecl InitialList.");
            }
        }
    }

    fn do_init(&mut self, ty: &CType, var_ctx: &Ctx, init_expr: &Expr, src: &Ctx) {
        match (&ty.spec, ty.derivs.as_slice()) {
            (Spec::Char, [Deriv::Array(Some(_))]) => {
                // char a[N] = "...": only the length flows.
                self.assign_init(var_ctx, src);
            }
            (Spec::Char, [Deriv::Array(None)]) => {
                // char a[] = "...": the array size equals the string size.
                if let (Ctx::Str { siz: vs, .. }, Expr::StrConst(_), Ctx::Str { siz: es, .. }) =
                    (var_ctx, init_expr, src)
                {
                    self.sys.eq(vs, es);
                    self.assign_init(var_ctx, src);
                } else {
                    self.assign(var_ctx, src);
                }
            }
            _ => self.assign(var_ctx, src),
        }
    }

    // ------------------------------------------------------------------
    // Two-pass driver over the program
    // ------------------------------------------------------------------

    /// Pass 0: collect typedefs and struct definitions so types resolve.
    fn collect_types(&mut self, prog: &Program) {
        for d in &prog.decls {
            match d {
                TopDecl::TypeDef { name, ctype } => {
                    self.tenv.typedefs.insert(name.clone(), ctype.clone());
                }
                TopDecl::StructDef { tag, fields } => {
                    self.tenv.structs.insert(tag.clone(), fields.clone());
                }
                _ => {}
            }
        }
    }

    /// Pass 1: register globals, function prototypes, formals, and returns.
    fn pass_one(&mut self, prog: &Program) {
        for d in &prog.decls {
            match d {
                TopDecl::Var(v) => {
                    let canon = match v.ctype.storage {
                        Some(Storage::Static) => format!("{}@{}", v.name, self.file),
                        _ => v.name.clone(),
                    };
                    self.global_canon.insert(v.name.clone(), canon.clone());
                    self.cur_func = None;
                    self.new_var(&canon, &v.ctype, true);
                }
                TopDecl::FunDef {
                    name,
                    return_type,
                    params,
                    ..
                } => {
                    let fret = Self::fret_name(name);
                    self.cur_func = None;
                    self.new_var(&fret, return_type, false);
                    self.remember_fun_params(name, params, false);
                }
                TopDecl::FunDecl {
                    name,
                    return_type,
                    params,
                } => {
                    let fret = Self::fret_name(name);
                    self.cur_func = None;
                    self.new_var(&fret, return_type, false);
                    if let Some(params) = params {
                        self.remember_fun_params(name, params, true);
                    }
                }
                _ => {}
            }
        }
    }

    /// `genericBounds`: set up `argc`/`argv` and feed them to `main`.
    fn generic_bounds(&mut self) {
        let t = self.sys.fresh(Some("caller".to_string()));
        self.sys.subset(&Term::constant(0), &t);
        let t1 = t.add(&Term::constant(1));
        self.sys.subset(&t1, &t); // argc in 0..+Infinity
        let argc = Ctx::Int(t);
        let argv = self.fresh_str(Some(STAR_ARGV));
        self.var_map.insert(
            STAR_ARGV.to_string(),
            VarInfo {
                ctx: argv,
                ctype: CType::string(),
                visible: true,
            },
        );
        self.do_formals("main", &[argc, Ctx::None]);
    }

    /// Pass 2: generate constraints for function bodies and global inits.
    fn pass_two(&mut self, prog: &Program) {
        for d in &prog.decls {
            match d {
                TopDecl::Var(v) => {
                    self.cur_func = None;
                    self.locals.clear();
                    self.decl_two(v);
                }
                TopDecl::FunDef {
                    name, params, body, ..
                } => {
                    self.cur_func = Some(name.clone());
                    // Build the local-name set and pre-create all locals (the
                    // per-block "first sub-pass"). Names collapse to the
                    // function scope, so registering them all up front is
                    // equivalent.
                    self.locals.clear();
                    for p in params {
                        if let Some(n) = &p.name {
                            self.locals.insert(n.clone());
                        }
                    }
                    let mut local_decls: Vec<VarDecl> = Vec::new();
                    collect_block_locals(body, &mut local_decls);
                    for v in &local_decls {
                        self.locals.insert(v.name.clone());
                    }
                    for v in &local_decls {
                        let canon = self.canonical_local(&v.name);
                        self.new_var(&canon, &v.ctype, true);
                    }
                    // Walk the body (initializers + statements).
                    let body = body.clone();
                    self.walk_block(&body);
                }
                _ => {}
            }
        }
    }

    /// Solve and turn the failed queries into the final report.
    fn finish(mut self) -> Report {
        let results = self.sys.solve();
        let mut report = Report {
            warnings: std::mem::take(&mut self.warnings),
            ..Default::default()
        };
        for qr in results {
            match &qr.kind {
                QueryKind::Overflow { name } => {
                    let sr = qr.a_range;
                    let lr = qr.b_range;
                    let msg = format!(
                        "`{}':\n  {} bytes allocated, {} bytes used.\n{}",
                        name,
                        range::range_str(sr),
                        range::range_str(lr),
                        qr.depends
                    );
                    match chance(sr, lr) {
                        0 => report
                            .holes0
                            .push(format!("Almost certainly a buffer overflow in {}", msg)),
                        1 => report
                            .holes1
                            .push(format!("Possibly a buffer overflow in {}", msg)),
                        _ => report
                            .holes2
                            .push(format!("Slight chance of a buffer overflow in {}", msg)),
                    }
                }
                QueryKind::Deref { desc } => {
                    report
                        .warnings
                        .push(format!("Possible deref after end in `{}`.", desc));
                }
            }
        }
        report
    }
}

/// Analyze one already-parsed program. `file` is used for static-variable
/// naming and reporting.
pub fn analyze(prog: &Program, file: &str) -> Report {
    let mut w = Walker::new(file);
    w.collect_types(prog);
    w.pass_one(prog);
    w.generic_bounds();
    w.pass_two(prog);
    w.finish()
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

/// `promoteToPtr`: an array type decays to a pointer type in expression
/// position. Only the C type changes, not the analysis context.
fn promote(p: (Ctx, CType)) -> (Ctx, CType) {
    (p.0, p.1.array_to_ptr())
}

/// Recursively collect all local variable declarations in a block (they all
/// share the enclosing function's scope in BOON's naming).
fn collect_block_locals(block: &Block, out: &mut Vec<VarDecl>) {
    for it in block {
        match it {
            BlockItem::Decl(v) => out.push(v.clone()),
            BlockItem::Stmt(s) => collect_stmt_locals(s, out),
        }
    }
}

fn collect_stmt_locals(s: &Stmt, out: &mut Vec<VarDecl>) {
    match s {
        Stmt::Decl(v) => out.push(v.clone()),
        Stmt::Block(items) => collect_block_locals(items, out),
        Stmt::If(_, t, e) => {
            collect_stmt_locals(t, out);
            if let Some(e) = e {
                collect_stmt_locals(e, out);
            }
        }
        Stmt::While(_, b) | Stmt::Switch(_, b) | Stmt::DoWhile(b, _) | Stmt::For(_, _, _, b) => {
            collect_stmt_locals(b, out)
        }
        Stmt::Case(Some(b)) | Stmt::Labeled(Some(b)) => collect_stmt_locals(b, out),
        _ => {}
    }
}

/// `elt (a, b)`: is endpoint `a` strictly less than endpoint `b`?
fn elt(a: i64, b: i64) -> bool {
    if a <= range::NEGINF {
        // -Infinity < anything except -Infinity
        b > range::NEGINF
    } else if a >= range::INF {
        false
    } else if b >= range::INF {
        true
    } else if b <= range::NEGINF {
        false
    } else {
        a < b
    }
}

/// Classify an overflow into hole level 0/1/2 (`chance`).
/// `sr` is the allocation (siz) range, `lr` is the used-length (len) range.
fn chance(sr: Range, lr: Range) -> u8 {
    if elt(sr.hi, lr.lo) {
        0 // max alloc < min len: almost certainly
    } else if elt(sr.hi, lr.hi) {
        1 // max alloc < max len: possibly
    } else {
        2 // slight chance
    }
}

fn spec_eq(a: &Spec, b: &Spec) -> bool {
    use Spec::*;
    match (a, b) {
        (Void, Void) | (Char, Char) | (Int, Int) | (Real, Real) => true,
        (Aggregate { tag: Some(x), .. }, Aggregate { tag: Some(y), .. }) => x == y,
        (NamedAggregate(x), NamedAggregate(y)) => x == y,
        (Aggregate { tag: Some(x), .. }, NamedAggregate(y))
        | (NamedAggregate(x), Aggregate { tag: Some(y), .. }) => x == y,
        (Named(x), Named(y)) => x == y,
        _ => false,
    }
}
