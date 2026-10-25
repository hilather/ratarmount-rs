//! N2–N4 operate on the compiler's pre-expansion AST callbacks. Rustc invokes
//! this pass both for the crate and immediately after loading each external
//! module, before configuring its children. We never load source modules.
use rustc_ast::{self as ast, AttrKind, HasAttrs, ItemKind, StmtKind};
use rustc_ast_pretty::pprust;
use rustc_lint::{EarlyContext, EarlyLintPass, LintContext, LintStore};
use rustc_session::{Session, impl_lint_pass};
use rustc_span::{Span, Symbol};
use serde_json::json;
use std::collections::BTreeSet;
use syn::{Meta, Token, parse::Parser, punctuated::Punctuated};

use crate::internal_read_grammar::{
    audit_macro, audit_macro_payload, inventory_attribute, target_attribute, target_predicate,
};

pub fn register(_: &Session, store: &mut LintStore) {
    store.register_pre_expansion_lint_pass(Box::new(|| Box::<Syntax>::default()));
}

#[derive(Clone, Copy, PartialEq)]
enum Truth {
    False,
    True,
    Unknown,
}
impl Truth {
    fn not(self) -> Self {
        match self {
            Self::False => Self::True,
            Self::True => Self::False,
            Self::Unknown => Self::Unknown,
        }
    }
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }
    fn or(self, other: Self) -> Self {
        self.not().and(other.not()).not()
    }
}
fn name(path: &syn::Path) -> String {
    path.segments
        .last()
        .map(|s| s.ident.to_string().trim_start_matches("r#").to_owned())
        .unwrap_or_default()
}
fn parts(tokens: proc_macro2::TokenStream) -> Vec<Meta> {
    Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(tokens)
        .map(|p| p.into_iter().collect())
        .unwrap_or_default()
}
fn eval(meta: &Meta, sess: &Session, target_unknown: bool) -> Truth {
    let ident = name(meta.path());
    if target_unknown
        && (ident == "windows"
            || ident == "unix"
            || ident.starts_with("target_")
            || ident == "internal_read_inventory")
    {
        return Truth::Unknown;
    }
    match meta {
        Meta::Path(_) => {
            if sess.config.contains(&(Symbol::intern(&ident), None)) {
                Truth::True
            } else {
                Truth::False
            }
        }
        Meta::NameValue(v) => {
            let value = match &v.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) => Some(Symbol::intern(&s.value())),
                _ => None,
            };
            if sess.config.contains(&(Symbol::intern(&ident), value)) {
                Truth::True
            } else {
                Truth::False
            }
        }
        Meta::List(v) => {
            let p = parts(v.tokens.clone());
            match ident.as_str() {
                "all" => p
                    .iter()
                    .fold(Truth::True, |a, m| a.and(eval(m, sess, target_unknown))),
                "any" => p
                    .iter()
                    .fold(Truth::False, |a, m| a.or(eval(m, sess, target_unknown))),
                "not" if p.len() == 1 => eval(&p[0], sess, target_unknown).not(),
                _ => Truth::Unknown,
            }
        }
    }
}
fn attr_cfg(meta: &Meta, sess: &Session, target_unknown: bool) -> Truth {
    if let Meta::List(list) = meta {
        let p = parts(list.tokens.clone());
        match name(&list.path).as_str() {
            "cfg" if p.len() == 1 => eval(&p[0], sess, target_unknown),
            "cfg_attr" if !p.is_empty() => {
                let condition = eval(&p[0], sess, target_unknown);
                p[1..].iter().fold(Truth::True, |a, m| {
                    a.and(condition.not().or(attr_cfg(m, sess, target_unknown)))
                })
            }
            _ => Truth::True,
        }
    } else {
        Truth::True
    }
}
fn parsed(attr: &ast::Attribute) -> Option<Meta> {
    if !matches!(attr.kind, AttrKind::Normal(_)) {
        return None;
    }
    let text = pprust::attribute_to_string(attr);
    let inner = text
        .strip_prefix("#![")
        .or_else(|| text.strip_prefix("#["))?
        .strip_suffix(']')?;
    syn::parse_str(inner).ok()
}
fn contains_link_name(meta: &Meta) -> bool {
    if name(meta.path()) == "link_name" {
        return true;
    }
    matches!(meta,Meta::List(l) if name(&l.path)=="cfg_attr" && parts(l.tokens.clone()).iter().skip(1).any(contains_link_name))
}

#[derive(Default)]
struct Syntax {
    states: Vec<(bool, bool)>,
    emitted: BTreeSet<(u32, u32, String)>,
    leaf_emitted: BTreeSet<(u32, u32)>,
    targets: BTreeSet<(u32, u32)>,
    module_spans: Vec<Span>,
}
impl_lint_pass!(Syntax => []);
impl Syntax {
    fn state(&self) -> (bool, bool) {
        self.states.last().copied().unwrap_or((true, true))
    }
    fn report(&mut self, cx: &EarlyContext<'_>, span: Span, policy: &str, detail: &str) {
        if self
            .emitted
            .insert((span.lo().0, span.hi().0, format!("{policy}:{detail}")))
        {
            crate::internal_read::emit(
                json!({"schema":1,"kind":"syntax","policy":policy,"detail":detail,"span":crate::internal_read::span(cx.sess(),span)}),
            );
            cx.sess()
                .dcx()
                .span_err(span, format!("{policy}: {detail}"));
        }
    }
    fn file(&self, cx: &EarlyContext<'_>, span: Span) -> String {
        crate::internal_read::span(cx.sess(), span)["file"]
            .as_str()
            .unwrap_or("")
            .to_owned()
    }
    fn observe_target(&mut self, cx: &EarlyContext<'_>, span: Span) {
        if self.targets.insert((span.lo().0, span.hi().0)) {
            crate::internal_read::emit(
                json!({"kind":"target_predicate","allowed":!self.n4(cx,span),"span":crate::internal_read::span(cx.sess(),span)}),
            );
        }
    }
    fn n4(&self, cx: &EarlyContext<'_>, span: Span) -> bool {
        let cfg = crate::internal_read::config();
        let package = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
        let restricted = cfg["restricted_packages"]
            .as_array()
            .is_some_and(|p| p.iter().any(|p| p.as_str() == Some(&package)));
        let file = self.file(cx, span);
        let reviewed = cfg["reviewed_target_files"]
            .as_array()
            .is_some_and(|p| p.iter().any(|p| p["file"].as_str() == Some(&file)));
        restricted && !reviewed
    }
    fn leaf(
        &mut self,
        cx: &EarlyContext<'_>,
        attrs: &[ast::Attribute],
        span: Span,
        kind: &str,
        text: String,
    ) {
        if !self.state().0 {
            return;
        }
        for attr in attrs {
            let Some(meta) = parsed(attr) else {
                continue;
            };
            match inventory_attribute(&meta) {
                Ok(Some((lint, reason))) => {
                    if !self
                        .leaf_emitted
                        .insert((attr.span.lo().0, attr.span.hi().0))
                    {
                        continue;
                    }
                    crate::internal_read::register_leaf(
                        &reason,
                        attr.span,
                        span,
                        kind,
                        self.state().1,
                    );
                    let tokens = text
                        .parse::<proc_macro2::TokenStream>()
                        .map(|s| s.to_string())
                        .unwrap_or(text.clone());
                    crate::internal_read::emit(
                        json!({"schema":1,"kind":"expectation","reason":reason,"lint":lint,"span":crate::internal_read::span(cx.sess(),attr.span),"leaf":{"span":crate::internal_read::span(cx.sess(),span),"kind":kind,"tokens":tokens},"native_active":self.state().1}),
                    );
                    if matches!(kind, "fn" | "mod" | "impl" | "closure" | "block" | "item") {
                        self.report(
                            cx,
                            attr.span,
                            "EXPECT",
                            "inventory expectation must own a narrow statement/type leaf",
                        );
                    }
                }
                Err(detail) => self.report(cx, attr.span, "EXPECT", &detail),
                Ok(None) => {}
            }
        }
    }
}
impl EarlyLintPass for Syntax {
    fn check_crate(&mut self, cx: &EarlyContext<'_>, krate: &ast::Crate) {
        crate::internal_read::syntax_observed();
        let package = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
        if !package.is_empty()
            && !crate::internal_read::config()["classified_packages"]
                .as_array()
                .is_some_and(|p| p.iter().any(|p| p.as_str() == Some(&package)))
        {
            self.report(
                cx,
                krate.spans.inner_span,
                "N4",
                "package requires explicit reviewed matrix classification",
            );
        }
        crate::internal_read::emit(
            json!({"kind":"syntax_loaded","scope":"crate","span":crate::internal_read::span(cx.sess(),krate.spans.inner_span)}),
        );
        let valid = krate.attrs.iter().any(|a| {
            let Some(Meta::List(l)) = parsed(a) else {
                return false;
            };
            l.path.is_ident("forbid")
                && l.path.segments[0].ident.to_string() == "forbid"
                && parts(l.tokens)
                    .iter()
                    .any(|m| matches!(m,Meta::Path(p) if name(p)=="unused_macros"))
        });
        if !valid {
            self.report(
                cx,
                krate.spans.inner_span,
                "N3",
                "production root missing unconditional forbid(unused_macros)",
            );
        }
    }
    fn check_attributes(&mut self, cx: &EarlyContext<'_>, attrs: &[ast::Attribute]) {
        let (parent_scan, parent_active) = self.state();
        let metas = attrs.iter().filter_map(parsed).collect::<Vec<_>>();
        let scan = parent_scan
            && metas
                .iter()
                .all(|m| attr_cfg(m, cx.sess(), true) != Truth::False);
        let active = parent_active
            && metas
                .iter()
                .all(|m| attr_cfg(m, cx.sess(), false) != Truth::False);
        self.states.push((scan, active));
        if !scan {
            return;
        }
        for attr in attrs {
            let Some(meta) = parsed(attr) else {
                continue;
            };
            if let Err(detail) = inventory_attribute(&meta) {
                self.report(cx, attr.span, "EXPECT", &detail);
            }
            if contains_link_name(&meta) {
                crate::internal_read::n2_raw_pending(
                    attr.span,
                    "link_name outside reviewed module",
                    self.module_spans.last().copied(),
                );
            }
            if target_attribute(&meta) {
                self.observe_target(cx, attr.span);
                if self.n4(cx, attr.span) {
                    self.report(
                        cx,
                        attr.span,
                        "N4",
                        "target predicate outside reviewed file",
                    );
                }
            }
        }
    }
    fn check_attributes_post(&mut self, _: &EarlyContext<'_>, _: &[ast::Attribute]) {
        self.states.pop();
    }
    fn check_item(&mut self, cx: &EarlyContext<'_>, item: &ast::Item) {
        if !self.state().0 {
            return;
        }
        let kind = match &item.kind {
            ItemKind::Fn(_) => "fn",
            ItemKind::Mod(..) => "mod",
            ItemKind::Impl(_) => "impl",
            ItemKind::Use(_) => "use",
            ItemKind::TyAlias(_) => "type",
            _ => "item",
        };
        self.leaf(
            cx,
            &item.attrs,
            item.span,
            kind,
            pprust::item_to_string(item),
        );
        if matches!(item.kind, ItemKind::Mod(..)) {
            self.module_spans.push(item.span);
        }
        if matches!(item.kind, ItemKind::ForeignMod(_)) {
            crate::internal_read::n2_raw_pending(
                item.span,
                "extern block outside reviewed module",
                self.module_spans.last().copied(),
            );
        }
    }
    fn check_item_post(&mut self, _: &EarlyContext<'_>, item: &ast::Item) {
        if self.state().0 && matches!(item.kind, ItemKind::Mod(..)) {
            self.module_spans.pop();
        }
    }
    fn check_stmt(&mut self, cx: &EarlyContext<'_>, stmt: &ast::Stmt) {
        let kind = match stmt.kind {
            StmtKind::Let(_) => "let",
            StmtKind::Expr(_) | StmtKind::Semi(_) => "statement",
            _ => return,
        };
        self.leaf(
            cx,
            stmt.attrs(),
            stmt.span,
            kind,
            pprust::stmt_to_string(stmt),
        );
    }
    fn check_expr(&mut self, cx: &EarlyContext<'_>, expr: &ast::Expr) {
        let kind = match expr.kind {
            ast::ExprKind::Block(..) => "block",
            ast::ExprKind::Closure(..) => "closure",
            _ => "expression",
        };
        self.leaf(
            cx,
            &expr.attrs,
            expr.span,
            kind,
            pprust::expr_to_string(expr),
        );
    }
    fn check_mac_def(&mut self, cx: &EarlyContext<'_>, def: &ast::MacroDef) {
        if !self.state().0 || !def.macro_rules {
            return;
        }
        let text = pprust::tts_to_string(&def.body.tokens);
        match audit_macro(&text) {
            Ok(findings) => {
                for (policy, detail) in findings {
                    if policy == "N2" {
                        crate::internal_read::n2_raw_pending(
                            def.body.dspan.entire(),
                            &detail,
                            self.module_spans.last().copied(),
                        );
                    } else {
                        self.report(cx, def.body.dspan.entire(), &policy, &detail);
                    }
                }
            }
            Err(detail) => self.report(
                cx,
                def.body.dspan.entire(),
                "N3",
                &format!("macro token grammar parse failed: {detail}"),
            ),
        }
    }
    fn check_mac(&mut self, cx: &EarlyContext<'_>, mac: &ast::MacCall) {
        if !self.state().0 {
            return;
        }
        let macro_tokens = pprust::tts_to_string(&mac.args.tokens);
        // Invocation tokens are otherwise opaque: only literal nested macro
        // definitions have Rust matcher/transcriber grammar at this stage.
        // Inspect them before expansion can erase cfg-gated transcribers.
        match audit_macro_payload(&macro_tokens) {
            Ok(findings) => {
                for (policy, detail) in findings {
                    if policy == "N2" {
                        crate::internal_read::n2_raw_pending(
                            mac.span(),
                            &detail,
                            self.module_spans.last().copied(),
                        );
                    } else {
                        self.report(cx, mac.span(), &policy, &detail);
                    }
                }
            }
            Err(detail) => self.report(
                cx,
                mac.span(),
                "N3",
                &format!("macro payload token grammar parse failed: {detail}"),
            ),
        }
        fn reserved(tokens: proc_macro2::TokenStream) -> bool {
            tokens.into_iter().any(|token| match token {
                proc_macro2::TokenTree::Ident(id) => {
                    id.to_string().trim_start_matches("r#") == "internal_read_inventory"
                }
                proc_macro2::TokenTree::Group(group) => reserved(group.stream()),
                _ => false,
            })
        }
        if macro_tokens.parse().is_ok_and(reserved) {
            self.report(
                cx,
                mac.span(),
                "EXPECT",
                "reserved activation cfg in macro payload",
            );
        }
        let path = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.name.as_str().to_string())
            .unwrap_or_default();
        if path == "cfg" {
            if let Ok(tokens) = pprust::tts_to_string(&mac.args.tokens).parse() {
                if target_predicate(tokens) {
                    self.observe_target(cx, mac.span());
                    if self.n4(cx, mac.span()) {
                        self.report(cx, mac.span(), "N4", "target cfg! outside reviewed file");
                    }
                }
            }
        }
    }
}
