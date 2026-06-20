//! Constraint terms and the constraint system.
//!
//! This ports `constraint-sig.sml` / `constraint-set.sml`. A [`Term`] is a
//! linear combination of set variables plus an integer constant
//! (`5*S0 + S3 - 1`). The [`System`] collects constraints over terms and,
//! when [`System::solve`] is called, hands them to [`crate::solver`] and
//! evaluates the deferred `queryge` checks (which is how buffer overruns are
//! reported).
//!
//! The original tool serialized constraints to text and shelled out to the C
//! `newsolver`. Here we keep everything in memory and solve in Rust; the
//! constraint *forms* and their meaning are unchanged.

use crate::range::Range;
use crate::solver::{self, Solution};

/// A set variable, identified by a small integer label.
pub type VarId = usize;

/// A linear term: `sum(coeff_i * var_i) + konst`.
#[derive(Debug, Clone, Default)]
pub struct Term {
    /// `(coeff, var)` pairs. The same variable may appear more than once with
    /// coefficients of opposite sign (the original keeps positive and negative
    /// multiples distinct because `2S - S != S` for ranges).
    pub terms: Vec<(i64, VarId)>,
    pub konst: i64,
}

impl Term {
    pub fn constant(k: i64) -> Term {
        Term {
            terms: Vec::new(),
            konst: k,
        }
    }

    fn var(v: VarId) -> Term {
        Term {
            terms: vec![(1, v)],
            konst: 0,
        }
    }

    /// True if this term is a plain integer constant.
    pub fn is_constant(&self) -> bool {
        self.terms.is_empty()
    }

    /// If this term is exactly `1 * v` (+0), return `v`.
    fn single_var(&self) -> Option<VarId> {
        if self.konst == 0 && self.terms.len() == 1 && self.terms[0].0 == 1 {
            Some(self.terms[0].1)
        } else {
            None
        }
    }

    pub fn add(&self, other: &Term) -> Term {
        // Naive accumulation, mirroring `addLists`: combine like terms only
        // when their coefficients have the same sign.
        let mut result: Vec<(i64, VarId)> = self.terms.clone();
        for &(c, v) in &other.terms {
            let mut merged = false;
            for slot in result.iter_mut() {
                if slot.1 == v && ((slot.0 >= 0 && c >= 0) || (slot.0 <= 0 && c <= 0)) {
                    slot.0 += c;
                    merged = true;
                    break;
                }
            }
            if !merged {
                result.push((c, v));
            }
        }
        Term {
            terms: result,
            konst: self.konst + other.konst,
        }
    }

    pub fn negate(&self) -> Term {
        Term {
            terms: self.terms.iter().map(|&(c, v)| (-c, v)).collect(),
            konst: -self.konst,
        }
    }

    pub fn sub(&self, other: &Term) -> Term {
        self.add(&other.negate())
    }

    fn scale(&self, c: i64) -> Term {
        Term {
            terms: self.terms.iter().map(|&(cc, v)| (c * cc, v)).collect(),
            konst: c * self.konst,
        }
    }
}

/// What a `queryge` check means, so the post-solve reporting can format the
/// right message.
#[derive(Debug, Clone)]
pub enum QueryKind {
    /// A buffer-overrun check `siz >= len` for a named buffer.
    Overflow { name: String },
    /// A "deref past the end" check (`len >= 1`).
    Deref { desc: String },
}

/// A deferred `>=` query: assert `a >= b` (i.e. every value of `a` is at least
/// every value of `b`); if the solver says that need not hold, it is reported.
#[derive(Debug, Clone)]
pub struct Query {
    pub a: Term,
    pub b: Term,
    pub kind: QueryKind,
}

/// The kinds of constraint the solver understands.
#[derive(Debug, Clone)]
pub enum Constraint {
    /// `eval(lhs) ⊆ var` (the constant/extra-var part of the RHS has already
    /// been folded into `lhs`).
    Subset { lhs: Term, var: VarId },
    /// `min(items) ⊆ var`.
    MinSubset { items: Vec<MinItem>, var: VarId },
}

/// One operand of a `min` constraint.
#[derive(Debug, Clone)]
pub enum MinItem {
    Const(i64),
    Term(i64, VarId),
}

/// The result of a triggered (failed) query.
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub kind: QueryKind,
    pub a_range: Range,
    pub b_range: Range,
    /// Human-readable dependency chain (best effort), like the original
    /// `<- siz(...) <- len(...)` output.
    pub depends: String,
}

/// The constraint system: collects variables and constraints, then solves.
pub struct System {
    /// Optional source-level name for each variable (for reporting).
    pub names: Vec<Option<String>>,
    /// Union-find parent for variable equality (`unify`).
    parent: Vec<VarId>,
    pub constraints: Vec<Constraint>,
    pub queries: Vec<Query>,
    /// Variables pinned to an exact range (`X = c`).
    pub fixed: Vec<(VarId, Range)>,
    /// Hard lower bounds (`X >= c`).
    pub hard_lo: Vec<(VarId, i64)>,
    top_var: Option<VarId>,
}

impl System {
    pub fn new() -> System {
        System {
            names: Vec::new(),
            parent: Vec::new(),
            constraints: Vec::new(),
            queries: Vec::new(),
            fixed: Vec::new(),
            hard_lo: Vec::new(),
            top_var: None,
        }
    }

    /// Create a fresh set variable, optionally named, and return `1*v` as a term.
    pub fn fresh(&mut self, name: Option<String>) -> Term {
        let id = self.names.len();
        self.names.push(name);
        self.parent.push(id);
        Term::var(id)
    }

    /// The lattice top, `-Infinity..+Infinity`, as a (cached) variable pinned
    /// to the full range. Mirrors `Constraint.top` (`top subset t`).
    pub fn top(&mut self) -> Term {
        if let Some(v) = self.top_var {
            return Term::var(v);
        }
        let t = self.fresh(Some("top".to_string()));
        let v = t.single_var().unwrap();
        self.fixed.push((v, Range::top()));
        self.top_var = Some(v);
        t
    }

    // ---- union-find over variables (for `=` unification) ----

    pub fn find(&mut self, v: VarId) -> VarId {
        let mut root = v;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        // Path compression.
        let mut cur = v;
        while self.parent[cur] != root {
            let next = self.parent[cur];
            self.parent[cur] = root;
            cur = next;
        }
        root
    }

    fn union(&mut self, a: VarId, b: VarId) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            // Keep a named representative if possible, for nicer reports.
            if self.names[ra].is_some() || self.names[rb].is_none() {
                self.parent[rb] = ra;
            } else {
                self.parent[ra] = rb;
            }
        }
    }

    // ---- constraint construction (mirrors the SML operators) ----

    /// `lhs ⊆ rhs`. The original requires the RHS to be a single set variable
    /// (plus possibly a constant and extra vars, which get moved to the LHS).
    pub fn subset(&mut self, lhs: &Term, rhs: &Term) {
        if rhs.terms.is_empty() {
            // `x subset c` is meaningless in the original (it raises). Skip.
            return;
        }
        // Take the RHS's first variable as the target; move everything else of
        // the RHS over to the LHS (negated). In practice the RHS is a bare var.
        let (rcoeff, rvar) = rhs.terms[0];
        let rest = Term {
            terms: rhs.terms[1..].to_vec(),
            konst: rhs.konst,
        };
        let mut eff_lhs = lhs.sub(&rest);
        // The target coefficient should be 1; if not, scale (best effort).
        if rcoeff != 1 && rcoeff != 0 {
            eff_lhs = eff_lhs.scale_safe(rcoeff);
        }
        self.constraints.push(Constraint::Subset {
            lhs: eff_lhs,
            var: rvar,
        });
    }

    /// `min(x, y) ⊆ z`, returning a fresh `z`. Mirrors `Constraint.min`
    /// (which routes `x`,`y` through fresh intermediates first).
    pub fn min(&mut self, x: &Term, y: &Term) -> Term {
        let z = self.fresh(None);
        let zv = z.single_var().unwrap();
        let mut items = Vec::new();
        self.push_min_item(&mut items, x);
        self.push_min_item(&mut items, y);
        self.constraints.push(Constraint::MinSubset { items, var: zv });
        z
    }

    fn push_min_item(&mut self, items: &mut Vec<MinItem>, t: &Term) {
        if t.is_constant() {
            items.push(MinItem::Const(t.konst));
        } else if let Some(v) = t.single_var() {
            items.push(MinItem::Term(1, v));
        } else {
            // General term: route through a fresh intermediate `w` with t ⊆ w.
            let w = self.fresh(None);
            let wv = w.single_var().unwrap();
            self.subset(t, &w);
            items.push(MinItem::Term(1, wv));
            let _ = wv;
        }
    }

    /// `x union y`, returning a fresh variable that is a superset of both.
    pub fn union_term(&mut self, x: &Term, y: &Term) -> Term {
        let z = self.fresh(None);
        self.subset(x, &z);
        self.subset(y, &z);
        z
    }

    /// `a = b` (unification). Handles the only forms the analysis produces:
    /// `var = const` (pin) and `var = var` (merge).
    pub fn eq(&mut self, a: &Term, b: &Term) {
        if b.is_constant() {
            if let Some(v) = a.single_var_any() {
                self.fixed.push((v.1, Range::singleton(b.konst - v.0)));
                return;
            }
        }
        if a.is_constant() {
            if let Some(v) = b.single_var_any() {
                self.fixed.push((v.1, Range::singleton(a.konst - v.0)));
                return;
            }
        }
        if let (Some(va), Some(vb)) = (a.single_var(), b.single_var()) {
            self.union(va, vb);
            return;
        }
        // Fallback: mutual subset (rare; not produced by the standard models).
        self.subset(a, b);
        self.subset(b, a);
    }

    /// `x * y`. Only modelled precisely when one operand is a constant
    /// (`mulTerms`/`constMulTerm`); otherwise the result is `top` (the SML
    /// `mulTerms` does the same).
    pub fn mul(&mut self, x: &Term, y: &Term) -> Term {
        if x.is_constant() {
            return y.scale(x.konst);
        }
        if y.is_constant() {
            return x.scale(y.konst);
        }
        self.top()
    }

    /// `x / y`: always `top` (the original `op /` is a stub returning top).
    pub fn div(&mut self, _x: &Term, _y: &Term) -> Term {
        self.top()
    }

    /// `a >= c` hard lower bound (`Constraint.>=` with a constant RHS).
    pub fn hard_ge(&mut self, a: &Term, c: i64) {
        if let Some(v) = a.single_var() {
            self.hard_lo.push((v, c));
        }
    }

    /// Register a deferred `a >= b` query (`Constraint.queryge`).
    pub fn queryge(&mut self, a: &Term, b: &Term, kind: QueryKind) {
        self.queries.push(Query {
            a: a.clone(),
            b: b.clone(),
            kind,
        });
    }

    /// Solve the system and return the triggered (failed) queries.
    pub fn solve(&mut self) -> Vec<QueryResult> {
        // Canonicalize all variable references through union-find first.
        let n = self.names.len();
        let mut canon = vec![0usize; n];
        for v in 0..n {
            canon[v] = self.find(v);
        }
        solver::solve(self, &canon)
    }
}

impl Term {
    /// Like [`Term::single_var`] but also returns the constant offset and
    /// allows any single-variable term `1*v + k`.
    fn single_var_any(&self) -> Option<(i64, VarId)> {
        if self.terms.len() == 1 && self.terms[0].0 == 1 {
            Some((self.konst, self.terms[0].1))
        } else {
            None
        }
    }

    fn scale_safe(&self, c: i64) -> Term {
        self.scale(c)
    }
}

impl Default for System {
    fn default() -> Self {
        System::new()
    }
}

/// Re-export so callers can name the solution type.
pub type _Solution = Solution;
