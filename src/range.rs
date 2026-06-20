//! Integer ranges with explicit infinities, ported from the `range_t`
//! arithmetic in `newsolver.c`.
//!
//! Following the original solver, "infinity" is not unbounded: it is the
//! sentinel value [`INF`] = 32767 (`MAXSHORT`). Any computed endpoint at or
//! beyond ±`INF` is treated as infinite. This matters for faithfulness — the
//! original tool reports "+Infinity" once a value reaches this threshold.

/// Positive infinity sentinel (`MAXSHORT` in the original C solver).
pub const INF: i64 = 32767;
/// Negative infinity sentinel.
pub const NEGINF: i64 = -32767;

/// Clamp a value into the representable range, collapsing out-of-range values
/// to ±infinity (`inf()` in the C solver).
pub fn clamp(x: i64) -> i64 {
    if x >= INF {
        INF
    } else if x <= NEGINF {
        NEGINF
    } else {
        x
    }
}

/// An inclusive integer range `lo..hi`. A range is *empty* when `lo > hi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub lo: i64,
    pub hi: i64,
}

impl Range {
    pub fn new(lo: i64, hi: i64) -> Range {
        Range {
            lo: clamp(lo),
            hi: clamp(hi),
        }
    }

    /// The empty range `(INF, NEGINF)`.
    pub fn empty() -> Range {
        Range {
            lo: INF,
            hi: NEGINF,
        }
    }

    /// The single value `n`.
    pub fn singleton(n: i64) -> Range {
        let c = clamp(n);
        Range { lo: c, hi: c }
    }

    /// The full range `-Infinity..+Infinity` (the lattice top).
    pub fn top() -> Range {
        Range {
            lo: NEGINF,
            hi: INF,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.lo > self.hi
    }

    pub fn lo_is_neginf(&self) -> bool {
        self.lo <= NEGINF
    }
    pub fn hi_is_inf(&self) -> bool {
        self.hi >= INF
    }
}

/// Endpoint addition with infinity rules (`infadd0` with default folding).
/// `default_bad` is used when adding +Inf and -Inf (an indeterminate form):
/// the C solver passes NEGINF for the lo endpoint and INF for the hi endpoint.
fn add_ep(x: i64, y: i64, default_bad: i64) -> i64 {
    if x < INF && x > NEGINF && y < INF && y > NEGINF {
        return clamp(x + y);
    }
    let sx = inf_sign(x);
    let sy = inf_sign(y);
    match sx + sy {
        1 | 2 | 3 | 4 => INF,
        -1 | -2 | -3 | -4 => NEGINF,
        _ => default_bad, // +Inf + -Inf
    }
}

fn inf_sign(x: i64) -> i64 {
    if x >= INF {
        2
    } else if x <= NEGINF {
        -2
    } else if x > 0 {
        1
    } else if x < 0 {
        -1
    } else {
        0
    }
}

fn mul_ep(x: i64, y: i64) -> i64 {
    if x < INF && x > NEGINF && y < INF && y > NEGINF {
        return clamp(x * y);
    }
    match inf_sign(x) * inf_sign(y) {
        2 | 4 => INF,
        -2 | -4 => NEGINF,
        _ => 0, // 0 * +/-Inf
    }
}

/// `rangeadd`: empty if either operand is empty.
pub fn add(x: Range, y: Range) -> Range {
    if x.is_empty() || y.is_empty() {
        return Range::empty();
    }
    Range {
        lo: add_ep(x.lo, y.lo, NEGINF),
        hi: add_ep(x.hi, y.hi, INF),
    }
}

/// `rangemul`: scale a range by an integer coefficient.
pub fn mul(c: i64, y: Range) -> Range {
    if y.is_empty() {
        return Range::empty();
    }
    if c == 0 {
        return Range::singleton(0);
    }
    if c > 0 {
        Range {
            lo: mul_ep(c, y.lo),
            hi: mul_ep(c, y.hi),
        }
    } else {
        // Negative coefficient flips the endpoints.
        Range {
            lo: mul_ep(c, y.hi),
            hi: mul_ep(c, y.lo),
        }
    }
}

/// `rangesub`.
pub fn sub(x: Range, y: Range) -> Range {
    add(x, mul(-1, y))
}

/// Convex hull / join (`rangeinrange` semantics): the smallest range
/// containing both. Unlike the C `rangeunion`, an empty operand acts as the
/// lattice bottom (identity), matching how `rangeinrange` grows a set's range.
pub fn hull(x: Range, y: Range) -> Range {
    if x.is_empty() {
        return y;
    }
    if y.is_empty() {
        return x;
    }
    Range {
        lo: x.lo.min(y.lo),
        hi: x.hi.max(y.hi),
    }
}

/// `rangemin`: the elementwise minimum of two value sets,
/// `{min(a,b) : a in x, b in y}` = `[min(lo), min(hi)]`.
pub fn rmin(x: Range, y: Range) -> Range {
    if x.is_empty() || y.is_empty() {
        return Range::empty();
    }
    Range {
        lo: x.lo.min(y.lo),
        hi: x.hi.min(y.hi),
    }
}

/// `endptGe`: is endpoint `x` >= endpoint `y` (with infinity rules)?
pub fn ep_ge(x: i64, y: i64) -> bool {
    if x >= INF {
        true
    } else if x <= NEGINF {
        y <= NEGINF
    } else if y >= INF {
        false
    } else if y <= NEGINF {
        true
    } else {
        x >= y
    }
}

/// Format an endpoint the way the original tool does.
pub fn ep_str(x: i64) -> String {
    if x >= INF {
        "+Infinity".to_string()
    } else if x <= NEGINF {
        "-Infinity".to_string()
    } else {
        x.to_string()
    }
}

/// Format a range as `lo..hi`.
pub fn range_str(r: Range) -> String {
    format!("{}..{}", ep_str(r.lo), ep_str(r.hi))
}
