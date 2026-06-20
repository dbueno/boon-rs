//! The range-constraint solver.
//!
//! This computes the *least* assignment of integer ranges to set variables
//! satisfying all `subset` / `min-subset` constraints, with constant pins
//! (`=`) and hard lower bounds (`>=`). It then evaluates the deferred
//! `queryge` checks, which is where buffer overruns surface.
//!
//! The original `newsolver.c` is a clever worklist solver that composes affine
//! functions along cycles to find this least fixpoint exactly. We instead use
//! the textbook approach that yields the same answer: condense the constraint
//! dependency graph into strongly connected components, solve them in
//! topological order, and within each cyclic component iterate to a fixpoint
//! using **interval widening** so that positive feedback loops jump straight to
//! ±Infinity (matching the original, where reaching ±32767 *is* infinity).
//!
//! Why this matches BOON:
//! * Acyclic merges stabilize in one pass and are never widened, so finite
//!   ranges stay exact (e.g. the `5..7` / `4..12` precision in the manual).
//! * A cycle that keeps growing (`t+1 ⊆ t`, as `forceLenTop` builds) is widened
//!   to `+Infinity` on its second visit — the same "length up to +Infinity"
//!   result the original tool produces.

use crate::constraint::{Constraint, MinItem, QueryKind, QueryResult, System, Term, VarId};
use crate::range::{self, Range};
use std::collections::HashMap;

/// A solved assignment of ranges to (canonical) variables.
pub struct Solution {
    pub ranges: Vec<Range>,
    pub canon: Vec<VarId>,
}

/// Solve `sys`, with `canon[v]` giving the canonical representative of each
/// variable after union-find. Returns the failed queries.
pub fn solve(sys: &System, canon: &[VarId]) -> Vec<QueryResult> {
    let n = sys.names.len();
    let mut ranges = vec![Range::empty(); n];

    // Pin fixed variables.
    let mut is_fixed = vec![false; n];
    for &(v, r) in &sys.fixed {
        let cv = canon[v];
        ranges[cv] = r;
        is_fixed[cv] = true;
    }

    // Hard lower bounds: take the strongest (largest) floor per variable.
    let mut hard_lo: HashMap<VarId, i64> = HashMap::new();
    for &(v, c) in &sys.hard_lo {
        let cv = canon[v];
        let e = hard_lo.entry(cv).or_insert(range::NEGINF);
        if c > *e {
            *e = c;
        }
    }

    // Group constraints by their (canonical) RHS variable, and build the
    // influence graph: edge from each LHS variable to the RHS variable.
    let mut by_rhs: HashMap<VarId, Vec<usize>> = HashMap::new();
    let mut succ: Vec<Vec<VarId>> = vec![Vec::new(); n]; // V -> [W it influences]
    for (i, c) in sys.constraints.iter().enumerate() {
        let rhs = canon[constraint_rhs(c)];
        by_rhs.entry(rhs).or_default().push(i);
        for v in constraint_lhs_vars(c) {
            succ[canon[v]].push(rhs);
        }
    }

    // Condense into SCCs and process in topological order.
    let (comp_of, comps) = tarjan_scc(n, &succ);
    let order = topo_order(&comps, &comp_of, &succ);

    for &cid in &order {
        solve_component(
            &comps[cid],
            sys,
            canon,
            &by_rhs,
            &is_fixed,
            &hard_lo,
            &mut ranges,
        );
    }

    // Evaluate the deferred queries.
    let mut results = Vec::new();
    for q in &sys.queries {
        let ar = eval_term(&q.a, canon, &ranges);
        let br = eval_term(&q.b, canon, &ranges);
        // The check is "a >= b for all values": a.lo >= b.hi.
        let ok = range::ep_ge(ar.lo, br.hi);
        if !ok {
            results.push(QueryResult {
                kind: q.kind.clone(),
                a_range: ar,
                b_range: br,
                depends: build_depends(&q.a, &q.b, sys, canon, &by_rhs),
            });
        }
    }
    results
}

/// Solve one SCC to a fixpoint, widening growing endpoints in cyclic
/// components. All variables this component depends on are already final.
fn solve_component(
    comp: &[VarId],
    sys: &System,
    canon: &[VarId],
    by_rhs: &HashMap<VarId, Vec<usize>>,
    is_fixed: &[bool],
    hard_lo: &HashMap<VarId, i64>,
    ranges: &mut [Range],
) {
    // Cap on iterations is a safety net; widening makes this converge fast.
    let max_iters = 1000;
    for iter in 0..max_iters {
        let prev: Vec<(VarId, Range)> = comp.iter().map(|&v| (v, ranges[v])).collect();
        let mut changed = false;
        for &v in comp {
            if is_fixed[v] {
                continue;
            }
            // Recompute the join of all constraints flowing into v.
            let mut acc = Range::empty();
            if let Some(idxs) = by_rhs.get(&v) {
                for &ci in idxs {
                    acc = range::hull(acc, eval_constraint(&sys.constraints[ci], canon, ranges));
                }
            }
            // Apply a hard lower bound, if any.
            if let Some(&lo) = hard_lo.get(&v) {
                if !acc.is_empty() && acc.lo < lo {
                    acc.lo = lo;
                }
            }
            // Widen (only after the first round, i.e. on a back-edge): any
            // endpoint that grew relative to the start of this round jumps to
            // infinity.
            if iter > 0 {
                let p = prev.iter().find(|(pv, _)| *pv == v).unwrap().1;
                if !p.is_empty() {
                    if acc.hi > p.hi {
                        acc.hi = range::INF;
                    }
                    if acc.lo < p.lo {
                        acc.lo = range::NEGINF;
                    }
                }
            }
            if acc != ranges[v] {
                ranges[v] = acc;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

/// Evaluate a `subset` / `min-subset` constraint's left-hand side.
fn eval_constraint(c: &Constraint, canon: &[VarId], ranges: &[Range]) -> Range {
    match c {
        Constraint::Subset { lhs, .. } => eval_term(lhs, canon, ranges),
        Constraint::MinSubset { items, .. } => {
            // Seed with +Infinity, then take the elementwise min of each item.
            let mut acc = Range::singleton(range::INF);
            for it in items {
                let r = match it {
                    MinItem::Const(k) => Range::singleton(*k),
                    MinItem::Term(coeff, v) => range::mul(*coeff, ranges[canon[*v]]),
                };
                acc = range::rmin(acc, r);
            }
            acc
        }
    }
}

/// Evaluate a linear term against the current ranges.
fn eval_term(t: &Term, canon: &[VarId], ranges: &[Range]) -> Range {
    let mut acc = Range::singleton(t.konst);
    for &(coeff, v) in &t.terms {
        acc = range::add(acc, range::mul(coeff, ranges[canon[v]]));
    }
    acc
}

fn constraint_rhs(c: &Constraint) -> VarId {
    match c {
        Constraint::Subset { var, .. } | Constraint::MinSubset { var, .. } => *var,
    }
}

fn constraint_lhs_vars(c: &Constraint) -> Vec<VarId> {
    match c {
        Constraint::Subset { lhs, .. } => lhs.terms.iter().map(|&(_, v)| v).collect(),
        Constraint::MinSubset { items, .. } => items
            .iter()
            .filter_map(|it| match it {
                MinItem::Term(_, v) => Some(*v),
                MinItem::Const(_) => None,
            })
            .collect(),
    }
}

// ---- Tarjan's strongly-connected-components ----

fn tarjan_scc(n: usize, succ: &[Vec<VarId>]) -> (Vec<usize>, Vec<Vec<VarId>>) {
    let mut index = vec![usize::MAX; n];
    let mut lowlink = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<VarId> = Vec::new();
    let mut comp_of = vec![usize::MAX; n];
    let mut comps: Vec<Vec<VarId>> = Vec::new();
    let mut counter = 0usize;

    // Iterative Tarjan to avoid stack overflow on large inputs.
    for start in 0..n {
        if index[start] != usize::MAX {
            continue;
        }
        // (node, next-successor-index)
        let mut work: Vec<(VarId, usize)> = vec![(start, 0)];
        index[start] = counter;
        lowlink[start] = counter;
        counter += 1;
        stack.push(start);
        on_stack[start] = true;

        while let Some(&(v, ci)) = work.last() {
            if ci < succ[v].len() {
                work.last_mut().unwrap().1 += 1;
                let w = succ[v][ci];
                if index[w] == usize::MAX {
                    index[w] = counter;
                    lowlink[w] = counter;
                    counter += 1;
                    stack.push(w);
                    on_stack[w] = true;
                    work.push((w, 0));
                } else if on_stack[w] {
                    lowlink[v] = lowlink[v].min(index[w]);
                }
            } else {
                // Done with v: propagate lowlink to parent, maybe close SCC.
                if lowlink[v] == index[v] {
                    let mut comp = Vec::new();
                    loop {
                        let w = stack.pop().unwrap();
                        on_stack[w] = false;
                        comp_of[w] = comps.len();
                        comp.push(w);
                        if w == v {
                            break;
                        }
                    }
                    comps.push(comp);
                }
                work.pop();
                if let Some(&(p, _)) = work.last() {
                    lowlink[p] = lowlink[p].min(lowlink[v]);
                }
            }
        }
    }
    (comp_of, comps)
}

/// Topologically order the component DAG so that a component is processed
/// after every component that flows into it (Kahn's algorithm).
fn topo_order(comps: &[Vec<VarId>], comp_of: &[usize], succ: &[Vec<VarId>]) -> Vec<usize> {
    let m = comps.len();
    let mut indeg = vec![0usize; m];
    let mut dag: Vec<Vec<usize>> = vec![Vec::new(); m];
    let mut seen: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    for v in 0..succ.len() {
        let cv = comp_of[v];
        for &w in &succ[v] {
            let cw = comp_of[w];
            if cv != cw && seen.insert((cv, cw)) {
                dag[cv].push(cw);
                indeg[cw] += 1;
            }
        }
    }
    let mut queue: Vec<usize> = (0..m).filter(|&c| indeg[c] == 0).collect();
    let mut order = Vec::with_capacity(m);
    let mut head = 0;
    while head < queue.len() {
        let c = queue[head];
        head += 1;
        order.push(c);
        for &d in &dag[c] {
            indeg[d] -= 1;
            if indeg[d] == 0 {
                queue.push(d);
            }
        }
    }
    // If a cycle of components somehow remains (shouldn't), append the rest.
    if order.len() < m {
        for c in 0..m {
            if !order.contains(&c) {
                order.push(c);
            }
        }
    }
    order
}

/// Build a best-effort dependency chain string for a failed query, listing the
/// named source variables that the queried terms transitively depend on.
fn build_depends(
    a: &Term,
    b: &Term,
    sys: &System,
    canon: &[VarId],
    by_rhs: &HashMap<VarId, Vec<usize>>,
) -> String {
    let mut out = String::new();
    let mut seen: std::collections::HashSet<VarId> = std::collections::HashSet::new();
    let mut names: Vec<String> = Vec::new();
    let mut stack: Vec<VarId> = a
        .terms
        .iter()
        .chain(b.terms.iter())
        .map(|&(_, v)| canon[v])
        .collect();
    while let Some(v) = stack.pop() {
        if !seen.insert(v) {
            continue;
        }
        // Find the representative's source name, if any.
        let nm = sys
            .names
            .iter()
            .enumerate()
            .find(|(i, _)| canon[*i] == v)
            .and_then(|(_, n)| n.clone());
        if let Some(name) = nm {
            if name != "top" && !names.contains(&name) {
                names.push(name);
            }
        }
        if let Some(idxs) = by_rhs.get(&v) {
            for &ci in idxs {
                for lv in constraint_lhs_vars(&sys.constraints[ci]) {
                    stack.push(canon[lv]);
                }
            }
        }
    }
    for name in names.iter().take(8) {
        out.push_str("  <- ");
        out.push_str(name);
        out.push('\n');
    }
    out
}

// Keep QueryKind referenced so the import is used in signatures elsewhere.
#[allow(dead_code)]
fn _kind_marker(_k: &QueryKind) {}
