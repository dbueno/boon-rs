//! C types and the classification that drives BOON's analysis.
//!
//! This is the Rust counterpart of the original `ctype.sml` / `ctype-sig.sml`.
//! BOON does not need a full C type checker; it only needs enough type
//! information to decide, for every expression, whether it should be modelled
//! as a *string* (a `char` buffer), an *integer*, or as *nothing* (`None`).
//! That three-way classification is computed by [`CType::kind`], which mirrors
//! `Walk.tkind` in the original source.

use std::collections::HashMap;

/// The "base" of a C type, i.e. the type specifier with all typedefs and
/// struct tags resolved away as far as is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    Void,
    /// `char` / `signed char` / `unsigned char`.
    Char,
    /// Any integer type (`int`, `short`, `long`, `enum`, ...). BOON lumps them
    /// all together because it only tracks integer *values*, not widths.
    Int,
    /// `float` / `double` / `long double`.
    Real,
    /// A `struct`/`union`. `tag` is the (optional) tag name; `fields`, when
    /// present, lists the members in declaration order.
    Aggregate {
        tag: Option<String>,
        fields: Option<Vec<(String, CType)>>,
    },
    /// An as-yet-unresolved typedef name.
    Named(String),
    /// An as-yet-unresolved `struct`/`union` tag (no definition in scope).
    NamedAggregate(String),
}

/// A type "derivation" applied on top of a [`Spec`]. Derivations are stored
/// outermost-first, matching the SML representation (`char *p` is
/// `Spec::Char` with `[Pointer]`; `char a[10]` is `Spec::Char` with
/// `[Array(Some(10))]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deriv {
    Pointer,
    /// Array; the size, if it is a simple integer constant, is recorded.
    Array(Option<i64>),
    /// Function type. We don't need the parameter detail here.
    Function,
}

/// Storage class, only `static`/`extern` matter (for alpha-conversion scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    Static,
    Extern,
}

/// A C type: a specifier plus a list of derivations plus a storage class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CType {
    pub storage: Option<Storage>,
    pub spec: Spec,
    /// Outermost-first list of derivations.
    pub derivs: Vec<Deriv>,
}

/// The three-way classification used throughout the analysis (`Walk.typKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A `char` buffer: `char *` or `char[]` (exactly one level of pointer or
    /// array). Modelled with a `(siz, len)` pair.
    Str,
    /// An integer value.
    Int,
    /// Everything else (modelled as `None`).
    None,
}

impl CType {
    pub fn new(spec: Spec) -> Self {
        CType {
            storage: None,
            spec,
            derivs: Vec::new(),
        }
    }

    pub fn void() -> Self {
        CType::new(Spec::Void)
    }
    pub fn int() -> Self {
        CType::new(Spec::Int)
    }
    pub fn char() -> Self {
        CType::new(Spec::Char)
    }
    /// `char *`, the type of a string literal.
    pub fn string() -> Self {
        CType {
            storage: None,
            spec: Spec::Char,
            derivs: vec![Deriv::Pointer],
        }
    }

    pub fn is_array(&self) -> bool {
        matches!(self.derivs.first(), Some(Deriv::Array(_)))
    }

    pub fn is_pointer(&self) -> bool {
        matches!(self.derivs.first(), Some(Deriv::Pointer))
    }

    pub fn is_function(&self) -> bool {
        matches!(self.derivs.first(), Some(Deriv::Function))
    }

    /// Promote an array type to a pointer type (`char a[10]` -> `char *`),
    /// matching `CType.arrayToPtr`. Used when arrays decay in expressions.
    pub fn array_to_ptr(&self) -> CType {
        if self.is_array() {
            let mut d = self.derivs.clone();
            d[0] = Deriv::Pointer;
            CType {
                storage: self.storage,
                spec: self.spec.clone(),
                derivs: d,
            }
        } else {
            self.clone()
        }
    }

    /// Strip one level of pointer/array (the result of dereferencing).
    pub fn deref(&self) -> CType {
        let mut d = self.derivs.clone();
        if !d.is_empty() {
            d.remove(0);
        }
        CType {
            storage: self.storage,
            spec: self.spec.clone(),
            derivs: d,
        }
    }

    /// The return type of a function type (`CType.returnType`): drop a leading
    /// `Function` derivation (optionally behind a `Pointer`, for fn pointers).
    pub fn return_type(&self) -> CType {
        let mut d = self.derivs.clone();
        match d.first() {
            Some(Deriv::Function) => {
                d.remove(0);
            }
            Some(Deriv::Pointer) if matches!(d.get(1), Some(Deriv::Function)) => {
                d.remove(0);
                d.remove(0);
            }
            _ => {
                // Not a function type; return as-is (best effort).
            }
        }
        CType {
            storage: None,
            spec: self.spec.clone(),
            derivs: d,
        }
    }

    /// BOON's `tkind`: classify into Str / Int / None.
    ///
    /// Rules (faithful to `Walk.tkind`):
    /// * `char`/`uchar` with exactly one `Pointer` or `Array` derivation -> Str
    /// * any integer base (incl. plain `char`) with no derivations -> Int
    /// * void/real/aggregate with no derivations -> None
    /// * anything else with at least one derivation -> None
    pub fn kind(&self) -> Kind {
        match (&self.spec, self.derivs.as_slice()) {
            (Spec::Char, [Deriv::Array(_)]) | (Spec::Char, [Deriv::Pointer]) => Kind::Str,
            // A lone integer (or char) scalar.
            (Spec::Char, []) | (Spec::Int, []) => Kind::Int,
            (Spec::Void, []) | (Spec::Real, []) => Kind::None,
            (Spec::Aggregate { .. }, _) | (Spec::NamedAggregate(_), _) => Kind::None,
            // Anything with remaining derivations (int*, char[][], fn ptr, ...).
            (_, [_, ..]) => Kind::None,
            // Unresolved typedef with no derivs: treat conservatively as None.
            (Spec::Named(_), []) => Kind::None,
        }
    }
}

/// Tables of typedefs and struct definitions, used to resolve named types.
///
/// This stands in for the bane parser's scope-aware `lookup` function; for the
/// purposes of BOON we only need typedef bodies and struct field lists, which
/// we collect globally during the first pass.
#[derive(Default)]
pub struct TypeEnv {
    pub typedefs: HashMap<String, CType>,
    /// struct/union tag -> field list.
    pub structs: HashMap<String, Vec<(String, CType)>>,
}

impl TypeEnv {
    pub fn new() -> Self {
        TypeEnv::default()
    }

    /// Resolve typedef names and struct tags in `t`, "as far as pointers"
    /// (mirrors `CType.resolveType`). Resolution stops once a level of pointer
    /// is reached, so recursive struct definitions terminate.
    pub fn resolve(&self, t: &CType) -> CType {
        self.resolve_depth(t, 0)
    }

    fn resolve_depth(&self, t: &CType, depth: usize) -> CType {
        if depth > 64 {
            return t.clone();
        }
        match &t.spec {
            Spec::Named(name) => {
                if let Some(def) = self.typedefs.get(name) {
                    // result derivs = use-site derivs ++ typedef derivs
                    let mut derivs = t.derivs.clone();
                    derivs.extend(def.derivs.iter().cloned());
                    let merged = CType {
                        storage: t.storage.or(def.storage),
                        spec: def.spec.clone(),
                        derivs,
                    };
                    self.resolve_depth(&merged, depth + 1)
                } else {
                    t.clone()
                }
            }
            Spec::NamedAggregate(tag) => {
                if let Some(fields) = self.structs.get(tag) {
                    CType {
                        storage: t.storage,
                        spec: Spec::Aggregate {
                            tag: Some(tag.clone()),
                            fields: Some(fields.clone()),
                        },
                        derivs: t.derivs.clone(),
                    }
                } else {
                    t.clone()
                }
            }
            _ => t.clone(),
        }
    }

    /// Find the type of struct field `id` in (resolved) type `t`
    /// (`CType.fieldType`). Returns `None` if not found / not a struct.
    pub fn field_type(&self, t: &CType, id: &str) -> Option<CType> {
        let resolved = self.resolve(t);
        if let Spec::Aggregate {
            fields: Some(fields),
            ..
        } = &resolved.spec
        {
            for (name, fty) in fields {
                if name == id {
                    return Some(self.resolve(fty));
                }
            }
        }
        None
    }
}
