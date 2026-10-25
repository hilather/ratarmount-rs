//! Reporting hooks at Clippy's existing resolved-item lookup, plus N2 HIR refusal.
//! No source path, import, reexport, symbol, flag or operation resolver lives here.
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
static RAW_N2: Mutex<Vec<(Span, String, Option<Span>)>> = Mutex::new(Vec::new());
#[derive(Clone)]
struct SourceLeaf {
    reason: String,
    attribute: Span,
    leaf: Span,
    broad: bool,
    active: bool,
}
static SOURCE_LEAVES: Mutex<Vec<SourceLeaf>> = Mutex::new(Vec::new());
pub fn register_leaf(reason: &str, attribute: Span, leaf: Span, kind: &str, active: bool) {
    SOURCE_LEAVES.lock().unwrap().push(SourceLeaf {
        reason: reason.to_owned(),
        attribute,
        leaf,
        broad: matches!(kind, "fn" | "mod" | "impl" | "closure" | "block" | "item"),
        active,
    });
}

pub fn n2_raw_pending(span: Span, detail: &str, module_span: Option<Span>) {
    RAW_N2
        .lock()
        .unwrap()
        .push((span, detail.to_owned(), module_span));
}
use std::sync::atomic::{AtomicBool, Ordering};
static SYNTAX_SEEN: AtomicBool = AtomicBool::new(false);
static EXPANSION_SEEN: AtomicBool = AtomicBool::new(false);
pub fn expansion_observed(records: u32, matched: u32) {
    EXPANSION_SEEN.store(true, Ordering::Relaxed);
    emit(json!({"kind":"expansion_complete","records":records,"matched":matched}));
}
pub fn syntax_observed() {
    SYNTAX_SEEN.store(true, Ordering::Relaxed);
}

use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::definitions::DefPathData;
use rustc_hir::{HirId, Node};
use rustc_lint::{LateContext, LintContext};
use rustc_middle::ty::{self, Ty, TyCtxt};
use rustc_session::Session;
use rustc_session::lint::Lint;
use rustc_span::Span;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub fn enabled() -> bool {
    std::env::var_os("INTERNAL_READ_REPORT").is_some()
}

pub fn config() -> &'static Value {
    static CONF: OnceLock<Value> = OnceLock::new();
    CONF.get_or_init(|| {
        let path = std::env::var("INTERNAL_READ_CONFIG").expect("policy config required");
        serde_json::from_slice(&std::fs::read(path).expect("read policy config"))
            .expect("valid policy config")
    })
}

pub fn emit(mut row: Value) {
    if !enabled() {
        return;
    }
    row["schema"] = json!(1);
    let path = std::env::var_os("INTERNAL_READ_REPORT").unwrap();
    let mut out = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open compiler policy report");
    serde_json::to_writer(&mut out, &row).expect("write compiler policy report");
    out.write_all(b"\n")
        .expect("finish compiler policy report row");
}

pub fn start() {
    if !enabled() {
        return;
    }
    std::fs::write(std::env::var_os("INTERNAL_READ_REPORT").unwrap(), b"")
        .expect("reset compiler policy report");
    emit(json!({"kind":"start","compiler":"88d9e12ae178fab0fb5cc050a94da85685d449ea"}));
}

pub fn span(sess: &Session, sp: Span) -> Value {
    let sm = sess.source_map();
    let lo = sm.lookup_char_pos(sp.lo());
    let hi = sm.lookup_char_pos(sp.hi());
    let file = lo.file.name.prefer_local_unconditionally().to_string();
    let root = std::env::var("INTERNAL_READ_ROOT").unwrap_or_default();
    let file = Path::new(&file)
        .strip_prefix(&root)
        .map_or(file.clone(), |p| p.to_string_lossy().into_owned());
    json!({"file":file,"lo":sp.lo().0 - lo.file.start_pos.0,"hi":sp.hi().0-hi.file.start_pos.0,"line":lo.line,"column":lo.col.0+1,"end_line":hi.line,"end_column":hi.col.0+1})
}

fn region_identity(tcx: TyCtxt<'_>, region: ty::Region<'_>) -> String {
    match region.kind() {
        ty::ReEarlyParam(p) => format!("'L{}", p.index),
        ty::ReBound(ty::BoundVarIndexKind::Bound(depth), p) => {
            format!("'B{}:{}", depth.as_u32(), p.var.as_u32())
        }
        ty::ReLateParam(p) => {
            let index = match p.kind {
                ty::LateParamRegionKind::Anon(index)
                | ty::LateParamRegionKind::NamedAnon(index, _) => index,
                ty::LateParamRegionKind::Named(id) => tcx
                    .generics_of(p.scope)
                    .param_def_id_to_index(tcx, id)
                    .or_else(|| {
                        let scope = p.scope.as_local()?;
                        tcx.hir_get_generics(scope)?
                            .params
                            .iter()
                            .position(|param| param.def_id.to_def_id() == id)
                            .map(|i| i as u32)
                    })
                    .expect("late lifetime parameter has a declaration binder index"),
                ty::LateParamRegionKind::ClosureEnv => return "'closure_env".into(),
            };
            format!("'LP{index}")
        }
        ty::ReStatic => "'static".into(),
        ty::ReErased => "'_".into(),
        other => panic!("unsupported canonical region identity {other:?}"),
    }
}

fn const_identity(value: ty::Const<'_>) -> String {
    match value.kind() {
        ty::ConstKind::Param(p) => format!("C{}", p.index),
        ty::ConstKind::Bound(ty::BoundVarIndexKind::Bound(depth), p) => {
            format!("CB{}:{}", depth.as_u32(), p.var.as_u32())
        }
        ty::ConstKind::Value(_) => format!("{value}"),
        other => panic!("unsupported canonical const identity {other:?}"),
    }
}

fn args(tcx: TyCtxt<'_>, args: ty::GenericArgsRef<'_>) -> String {
    if args.is_empty() {
        return String::new();
    }
    let values: Vec<String> = args
        .iter()
        .map(|arg| match arg.kind() {
            ty::GenericArgKind::Type(t) => type_identity(tcx, t),
            ty::GenericArgKind::Lifetime(r) => region_identity(tcx, r),
            ty::GenericArgKind::Const(c) => const_identity(c),
        })
        .collect();
    format!("<{}>", values.join(","))
}

fn type_identity(tcx: TyCtxt<'_>, t: Ty<'_>) -> String {
    match t.kind() {
        ty::Adt(def, a) => format!("{}{}", identity(tcx, def.did()), args(tcx, a)),
        ty::Ref(r, inner, mutbl) => format!(
            "&{} {}{}",
            region_identity(tcx, *r),
            if mutbl.is_mut() { "mut " } else { "" },
            type_identity(tcx, *inner)
        ),
        ty::RawPtr(inner, mutbl) => format!(
            "*{} {}",
            if mutbl.is_mut() { "mut" } else { "const" },
            type_identity(tcx, *inner)
        ),
        ty::Tuple(ts) => format!(
            "({})",
            ts.iter()
                .map(|t| type_identity(tcx, t))
                .collect::<Vec<_>>()
                .join(",")
        ),
        ty::Slice(inner) => format!("[{}]", type_identity(tcx, *inner)),
        ty::Array(inner, n) => format!("[{};{}]", type_identity(tcx, *inner), const_identity(*n)),
        ty::Param(p) => format!("T{}", p.index),
        ty::Alias(_, a) => {
            let id = match a.kind {
                ty::AliasTyKind::Projection { def_id }
                | ty::AliasTyKind::Inherent { def_id }
                | ty::AliasTyKind::Opaque { def_id }
                | ty::AliasTyKind::Free { def_id } => def_id,
            };
            format!("{}{}", identity(tcx, id), args(tcx, a.args))
        }
        ty::Bool | ty::Char | ty::Int(_) | ty::Uint(_) | ty::Float(_) | ty::Str | ty::Never => {
            format!("{t}")
        }
        ty::FnDef(id, a) => format!("{}{}", identity(tcx, *id), args(tcx, a)),
        ty::FnPtr(signature, header) => {
            let signature = signature.with(*header).skip_binder();
            format!(
                "fn{:?}({})->{}",
                header,
                signature
                    .inputs()
                    .iter()
                    .map(|t| type_identity(tcx, *t))
                    .collect::<Vec<_>>()
                    .join(","),
                type_identity(tcx, signature.output())
            )
        }
        ty::Foreign(id) => identity(tcx, *id),
        other => panic!("unsupported canonical type identity {other:?}"),
    }
}

/// Structural defining paths; never the compiler's visible-path rendering.
pub fn identity(tcx: TyCtxt<'_>, id: DefId) -> String {
    if matches!(tcx.def_kind(id), DefKind::Impl { .. }) {
        let self_ty = tcx.type_of(id).instantiate_identity().skip_norm_wip();
        return if matches!(tcx.def_kind(id), DefKind::Impl { of_trait: true }) {
            let tr = tcx
                .impl_trait_ref(id)
                .instantiate_identity()
                .skip_norm_wip();
            format!(
                "<{} as {}{}>",
                type_identity(tcx, self_ty),
                identity(tcx, tr.def_id),
                args(tcx, tr.args)
            )
        } else {
            format!("<{}>", type_identity(tcx, self_ty))
        };
    }
    let key = tcx.def_key(id);
    let parent = key.parent.map(|index| {
        identity(
            tcx,
            DefId {
                krate: id.krate,
                index,
            },
        )
    });
    match key.disambiguated_data.data {
        DefPathData::CrateRoot => tcx.crate_name(id.krate).to_string(),
        DefPathData::TypeNs(name)
        | DefPathData::ValueNs(name)
        | DefPathData::MacroNs(name)
        | DefPathData::LifetimeNs(name) => format!("{}::{name}", parent.unwrap()),
        DefPathData::Ctor => parent.unwrap(),
        DefPathData::ForeignMod
        | DefPathData::Closure
        | DefPathData::AnonConst
        | DefPathData::OpaqueTy
        | DefPathData::SyntheticCoroutineBody => parent.unwrap(),
        other => panic!("unsupported canonical definition shape {other:?}"),
    }
}

// DefIds remain transient. Distinct named definitions must not silently share
// one serialized identity after removing source-order disambiguators.
static OBSERVED_IDENTITIES: Mutex<std::collections::BTreeMap<(&'static str, String), DefId>> =
    Mutex::new(std::collections::BTreeMap::new());
fn observed_identity(tcx: TyCtxt<'_>, kind: &'static str, id: DefId, canonical: String) -> String {
    let mut observed = OBSERVED_IDENTITIES.lock().unwrap();
    let key = (kind, canonical.clone());
    if let Some(previous) = observed.get(&key) {
        if *previous != id {
            tcx.dcx()
                .err(format!("canonical {kind} identity collision: {canonical}"));
        }
    } else {
        observed.insert(key, id);
    }
    canonical
}

pub fn owner(tcx: TyCtxt<'_>, mut id: DefId) -> String {
    while matches!(
        tcx.def_kind(id),
        DefKind::Closure
            | DefKind::AnonConst
            | DefKind::OpaqueTy
            | DefKind::Use
            | DefKind::ExternCrate
            | DefKind::GlobalAsm
    ) {
        id = tcx.parent(id);
    }
    observed_identity(tcx, "owner", id, identity(tcx, id))
}

fn leaf(tcx: TyCtxt<'_>, hir: HirId) -> (Span, bool) {
    match tcx.hir_node(hir) {
        Node::LetStmt(n) => (n.span, false),
        Node::Expr(n) => (
            n.span,
            matches!(
                n.kind,
                rustc_hir::ExprKind::Block(..) | rustc_hir::ExprKind::Closure(..)
            ),
        ),
        Node::Stmt(n) => (n.span, false),
        Node::Ty(n) => (n.span, false),
        Node::Item(n) => (
            n.span,
            !matches!(
                n.kind,
                rustc_hir::ItemKind::Use(..) | rustc_hir::ItemKind::TyAlias(..)
            ),
        ),
        _ => (tcx.hir_span(hir), true),
    }
}

fn approved_leaf(
    tcx: TyCtxt<'_>,
    hir: HirId,
    reason: Option<rustc_span::Symbol>,
    attribute: Span,
) -> (Span, bool, bool) {
    if let Some(reason) = reason {
        let candidates = SOURCE_LEAVES
            .lock()
            .unwrap()
            .iter()
            .filter(|leaf| {
                leaf.active && leaf.reason == reason.as_str() && leaf.attribute.contains(attribute)
            })
            .cloned()
            .collect::<Vec<_>>();
        if candidates.len() > 1 {
            tcx.dcx().span_err(
                attribute,
                "ambiguous compiler-selected source leaf for expectation",
            );
        }
        if let Some(leaf) = candidates.first() {
            return (leaf.leaf, leaf.broad || self::leaf(tcx, hir).1, true);
        }
    }
    let (span, broad) = leaf(tcx, hir);
    (span, broad, false)
}

pub fn normalized_leaf(sess: &Session, sp: Span) -> String {
    let src = sess
        .source_map()
        .span_to_snippet(sp)
        .expect("leaf source must be available");
    src.parse::<proc_macro2::TokenStream>()
        .expect("leaf must tokenize")
        .to_string()
}

pub fn leaf_digest(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn enclosing_statement(tcx: TyCtxt<'_>, hir: HirId) -> (Span, &'static str) {
    for (_, node) in std::iter::once((hir, tcx.hir_node(hir))).chain(tcx.hir_parent_iter(hir)) {
        match node {
            Node::LetStmt(n) => return (n.span, "let"),
            Node::Stmt(n) => return (n.span, "statement"),
            Node::Item(n) if matches!(n.kind, rustc_hir::ItemKind::Use(..)) => {
                return (n.span, "use");
            }
            Node::Item(n) if matches!(n.kind, rustc_hir::ItemKind::TyAlias(..)) => {
                return (n.span, "type");
            }
            Node::Item(n) => return (n.span, "item"),
            Node::ImplItem(n) => return (n.span, "impl_item"),
            Node::TraitItem(n) => return (n.span, "trait_item"),
            _ => {}
        }
    }
    (tcx.hir_span(hir), "other")
}

fn operation_span(tcx: TyCtxt<'_>, hir: HirId) -> Span {
    if let Node::Item(item) = tcx.hir_node(hir) {
        return item.span;
    }
    if let Node::Expr(expr) = tcx.hir_node(hir)
        && matches!(expr.kind, rustc_hir::ExprKind::Path(..))
    {
        if let Some((_, Node::Expr(parent))) = tcx.hir_parent_iter(hir).next()
            && matches!(parent.kind, rustc_hir::ExprKind::Call(..))
        {
            return parent.span;
        }
    }
    tcx.hir_span(hir)
}

pub fn operation(
    cx: &LateContext<'_>,
    id: DefId,
    configured_path: &str,
    rule_reason: Option<&str>,
    lint: &'static Lint,
    hir: HirId,
    sp: Span,
) {
    if !enabled() {
        return;
    }
    let mut row = json!({"kind":"operation","lint":lint.name_lower(),"owner":owner(cx.tcx,hir.owner.def_id.to_def_id()),"resolved":observed_identity(cx.tcx,"operation",id,identity(cx.tcx,id)),"configured_path":configured_path,"rule_reason":rule_reason,"span":span(cx.sess(),sp),"node_span":span(cx.sess(),operation_span(cx.tcx,hir)),"reason":null,"broad":false});
    let (statement, statement_kind) = enclosing_statement(cx.tcx, hir);
    row["enclosing_stmt_span"] = span(cx.sess(), statement);
    row["enclosing_stmt_kind"] = json!(statement_kind);
    for (_, node) in cx.tcx.hir_parent_iter(hir) {
        if let Node::Block(block) = node {
            row["enclosing_block_span"] = span(cx.sess(), block.span);
            row["enclosing_block_rules"] = json!(format!("{:?}", block.rules));
            break;
        }
    }
    for (_, node) in cx.tcx.hir_parent_iter(hir) {
        let control = match node {
            Node::Arm(arm) => Some(arm.span),
            Node::Expr(expr)
                if matches!(
                    expr.kind,
                    rustc_hir::ExprKind::If(..)
                        | rustc_hir::ExprKind::Match(..)
                        | rustc_hir::ExprKind::Loop(..)
                        | rustc_hir::ExprKind::Closure(..)
                ) =>
            {
                Some(expr.span)
            }
            _ => None,
        };
        if let Some(control) = control {
            row["enclosing_control_span"] = span(cx.sess(), control);
            break;
        }
    }
    let spec = cx.tcx.lint_level_spec_at_node(lint, hir);
    if let Some(expect_id) = spec.lint_id() {
        let ex = cx
            .tcx
            .lint_expectations(())
            .iter()
            .find(|(candidate, _)| *candidate == expect_id)
            .expect("lookup expectation id");
        let (sp, broad, source_observed) =
            approved_leaf(cx.tcx, expect_id.hir_id, ex.1.reason, ex.1.emission_span);
        let text = normalized_leaf(cx.sess(), sp);
        row["source_leaf_observed"] = json!(source_observed);
        if source_observed {
            row["source_leaf_span"] = span(cx.sess(), sp);
        }
        row["reason"] = json!(ex.1.reason.map(|r| r.to_string()));
        row["broad"] = json!(broad);
        row["leaf"] = json!(text);
        row["leaf_digest"] = json!(leaf_digest(&text));
        row["leaf_span"] = span(cx.sess(), sp);
        row["expectation_span"] = span(cx.sess(), ex.1.emission_span);
    }
    emit(row);
}

pub fn finish(tcx: TyCtxt<'_>) {
    if !enabled() {
        return;
    }
    if !SYNTAX_SEEN.load(Ordering::Relaxed) {
        tcx.dcx()
            .err("missing compiler pre-expansion syntax adapter report");
    }
    if !EXPANSION_SEEN.load(Ordering::Relaxed) {
        tcx.dcx()
            .err("missing completed compiler expansion traversal");
    }
    let allowed_path = config()["allowed_extern_module"]
        .as_str()
        .expect("one allowed extern module");
    let allowed: Vec<_> = tcx
        .hir_crate_items(())
        .free_items()
        .filter_map(|id| {
            let it = tcx.hir_item(id);
            (matches!(it.kind, rustc_hir::ItemKind::Mod(..))
                && identity(tcx, it.owner_id.def_id.to_def_id()) == allowed_path)
                .then_some(it.owner_id.def_id)
        })
        .collect();
    if tcx.crate_name(LOCAL_CRATE).as_str() == allowed_path.split("::").next().unwrap()
        && allowed.len() != 1
    {
        tcx.dcx()
            .err("N2 configured foreign-module identity is missing or ambiguous");
    }
    let allowed = allowed.first().copied();
    // Map raw loaded syntax to the compiler's own enclosing module ranges.
    // No module declaration or pathname is interpreted here.
    let mut module_ranges = vec![(
        tcx.hir_root_module().spans.inner_span,
        rustc_hir::def_id::CRATE_DEF_ID,
    )];
    for id in tcx.hir_crate_items(()).free_items() {
        let item = tcx.hir_item(id);
        if let rustc_hir::ItemKind::Mod(_, module) = item.kind {
            module_ranges.push((module.spans.inner_span, item.owner_id.def_id));
        }
    }
    for (raw, detail, ast_module_span) in RAW_N2.lock().unwrap().drain(..) {
        let mut candidates = module_ranges
            .iter()
            .filter(|(sp, _)| sp.contains(raw))
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(sp, _)| sp.hi().0 - sp.lo().0);
        let mut exact = candidates
            .first()
            .copied()
            .filter(|(sp, _)| {
                candidates
                    .iter()
                    .filter(|(other, _)| other.hi().0 - other.lo().0 == sp.hi().0 - sp.lo().0)
                    .count()
                    == 1
            })
            .map(|(_, module)| *module);
        if let Some(ast_span) = ast_module_span {
            let matching_modules = tcx
                .hir_crate_items(())
                .free_items()
                .filter_map(|id| {
                    let item = tcx.hir_item(id);
                    (matches!(item.kind, rustc_hir::ItemKind::Mod(..))
                        && item.span.lo() == ast_span.lo()
                        && item.span.hi() == ast_span.hi())
                    .then_some(item.owner_id.def_id)
                })
                .collect::<Vec<_>>();
            exact = if matching_modules.len() == 1 {
                Some(matching_modules[0])
            } else {
                None
            };
        }
        if exact.is_none() || exact != allowed {
            emit(
                json!({"kind":"violation","policy":"N2","detail":detail,"span":span(tcx.sess,raw)}),
            );
            tcx.dcx().span_err(raw, format!("N2: {detail}"));
        }
    }
    for id in tcx.hir_crate_items(()).free_items() {
        let item = tcx.hir_item(id);
        if matches!(item.kind, rustc_hir::ItemKind::ForeignMod { .. }) {
            let module = tcx.parent_module_from_def_id(item.owner_id.def_id);
            let ok = Some(module.to_local_def_id()) == allowed;
            emit(
                json!({"kind":"foreign_block","owner":identity(tcx,module.to_def_id()),"allowed":ok,"span":span(tcx.sess,item.span)}),
            );
            if !ok {
                tcx.dcx().span_err(
                    item.span,
                    "N2 foreign block outside the reviewed exact module",
                );
            }
        }
    }
    for own in tcx.hir_crate_items(()).owners() {
        for (_, attrs) in tcx.hir_attr_map(own).map.iter() {
            for attr in *attrs {
                if let rustc_hir::Attribute::Parsed(rustc_hir::attrs::AttributeKind::LinkName {
                    span: sp,
                    ..
                }) = attr
                {
                    let module = tcx.parent_module_from_def_id(own.def_id);
                    let ok = Some(module.to_local_def_id()) == allowed;
                    emit(
                        json!({"kind":"link_name","owner":identity(tcx,module.to_def_id()),"allowed":ok,"span":span(tcx.sess,*sp)}),
                    );
                    if !ok {
                        tcx.dcx()
                            .span_err(*sp, "N2 link_name outside the reviewed exact module");
                    }
                }
            }
        }
    }
    emit(json!({"kind":"hir_complete"}));
    let mut seen_expectations = std::collections::HashSet::new();
    for (id, ex) in tcx.lint_expectations(()) {
        if !seen_expectations.insert((*id, ex.reason)) {
            continue;
        }
        if let Some(reason) = ex.reason
            && reason.as_str().starts_with("internal-read:v1 ")
        {
            let (sp, broad, source_observed) =
                approved_leaf(tcx, id.hir_id, ex.reason, ex.emission_span);
            let text = normalized_leaf(tcx.sess, sp);
            emit(
                json!({"kind":"expectation","active":true,"source_leaf_observed":source_observed,"source_leaf_span":if source_observed{span(tcx.sess,sp)}else{Value::Null},"owner":owner(tcx,id.hir_id.owner.def_id.to_def_id()),"reason":reason.to_string(),"broad":broad,"leaf":text,"leaf_digest":leaf_digest(&text),"span":span(tcx.sess,sp)}),
            );
        }
    }
    emit(
        json!({"kind":"complete","success":tcx.dcx().has_errors().is_none(),"crate":tcx.crate_name(LOCAL_CRATE).to_string(),"syntax_complete":SYNTAX_SEEN.load(Ordering::Relaxed),"expanded_complete":EXPANSION_SEEN.load(Ordering::Relaxed),"hir_complete":true}),
    );
}

pub fn invocation_owner(tcx: TyCtxt<'_>, call: Span) -> HirId {
    let mut found = (u32::MAX, rustc_hir::CRATE_HIR_ID);
    for own in tcx.hir_crate_items(()).owners() {
        let id = tcx.local_def_id_to_hir_id(own.def_id);
        let sp = match tcx.hir_node(id) {
            Node::Item(item) => item.span,
            Node::ImplItem(item) => item.span,
            Node::TraitItem(item) => item.span,
            _ => tcx.hir_span(id),
        };
        if sp.contains(call) && sp.hi().0 - sp.lo().0 < found.0 {
            found = (sp.hi().0 - sp.lo().0, id);
        }
    }
    found.1
}

pub fn repository_callsite(tcx: TyCtxt<'_>, mut expansion: rustc_span::ExpnId) -> Span {
    let mut call = expansion.expn_data().call_site;
    while expansion != rustc_span::ExpnId::root() {
        let data = expansion.expn_data();
        let candidate = span(tcx.sess, data.call_site);
        if candidate["file"]
            .as_str()
            .is_some_and(|p| !Path::new(p).is_absolute())
        {
            call = data.call_site;
        }
        expansion = data.parent;
    }
    call
}

pub fn include_exception(
    cx: &LateContext<'_>,
    id: DefId,
    path: &str,
    rule_reason: Option<&str>,
    call: Span,
    hir: HirId,
) -> bool {
    if !enabled() {
        return false;
    }
    if !matches!(path, "std::include" | "core::include") {
        return false;
    }
    let file = span(cx.sess(), call)["file"].as_str().unwrap().to_owned();
    let owning = owner(cx.tcx, hir.owner.def_id.to_def_id());
    let exceptions = config()["include_exceptions"]
        .as_array()
        .expect("include exception list");
    for ex in exceptions {
        if ex["file"] == file && ex["item"] == owning {
            let reason = ex["reason"]
                .as_str()
                .filter(|s| !s.trim().is_empty())
                .expect("reviewed include reason");
            emit(
                json!({"kind":"include_exception","owner":owning,"reason":reason,"resolved":observed_identity(cx.tcx,"operation",id,identity(cx.tcx,id)),"configured_path":path,"rule_reason":rule_reason,"span":span(cx.sess(),call)}),
            );
            return true;
        }
    }
    false
}
