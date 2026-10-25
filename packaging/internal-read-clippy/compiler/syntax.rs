//! N2–N4 operate on the compiler's pre-expansion AST callbacks. Rustc invokes
//! this pass both for the crate and immediately after loading each external
//! module, before configuring its children. We never load source modules.
use rustc_ast::{self as ast, AttrKind, HasAttrs, ItemKind, StmtKind};
use rustc_ast_pretty::pprust;
use rustc_lint::{EarlyContext, EarlyLintPass, LintContext, LintStore};
use rustc_session::{Session, impl_lint_pass};
use rustc_span::Span;
use serde_json::json;
use std::collections::BTreeSet;
use syn::{Meta, Token, parse::Parser, punctuated::Punctuated};

use crate::internal_read_grammar::{
    audit_macro_payload_with_lints, audit_macro_with_lints, audit_raw_tokens, clippy_attribute,
    inventory_attribute, suppression_attribute_with_lints, target_attribute,
};

pub fn register(_: &Session, store: &mut LintStore) {
    let mut protected_lints = BTreeSet::from([
        "clippy::disallowed_methods".to_owned(),
        "clippy::disallowed_types".to_owned(),
    ]);
    let protected_ids = protected_lints
        .iter()
        .flat_map(|name| {
            store
                .find_lints(name)
                .expect("protected Clippy lint must be registered")
        })
        .copied()
        .collect::<Vec<_>>();
    // Rustc owns lint-group membership. Do not maintain another spelling table
    // that can miss an allow(clippy::all/style) lowering of the protected lint.
    for (name, ids, _) in store.get_lint_groups() {
        if ids.iter().any(|id| protected_ids.contains(id)) {
            protected_lints.insert(name.to_owned());
        }
    }
    store.register_pre_expansion_lint_pass(Box::new(move || {
        Box::new(Syntax {
            protected_lints: protected_lints.clone(),
            ..Syntax::default()
        })
    }));
}

fn name(path: &syn::Path) -> String {
    path.segments
        .last()
        .map(|s| s.ident.to_string().trim_start_matches("r#").to_owned())
        .unwrap_or_default()
}
fn parts(tokens: proc_macro2::TokenStream) -> syn::Result<Vec<Meta>> {
    Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(tokens)
        .map(|p| p.into_iter().collect())
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
    matches!(meta,Meta::List(l) if name(&l.path)=="cfg_attr" && parts(l.tokens.clone()).is_ok_and(|parts| parts.iter().skip(1).any(contains_link_name)))
}

#[derive(Default)]
struct Syntax {
    protected_lints: BTreeSet<String>,
    emitted: BTreeSet<(u32, u32, String)>,
    leaf_emitted: BTreeSet<(u32, u32)>,
    targets: BTreeSet<(u32, u32)>,
    module_spans: Vec<Span>,
    source_owners: Vec<(String, Span)>,
}
impl_lint_pass!(Syntax => []);
impl Syntax {
    fn child_owner(&self, name: &str) -> String {
        match self.source_owners.last() {
            Some((parent, _)) if !parent.is_empty() => format!("{parent}::{name}"),
            _ => name.to_owned(),
        }
    }
    fn raw_attribute(&mut self, cx: &EarlyContext<'_>, attr: &ast::Attribute) {
        self.raw_tokens(cx, attr.span, &pprust::attribute_to_string(attr));
    }
    fn raw_tokens(&mut self, cx: &EarlyContext<'_>, span: Span, text: &str) {
        if self.restricted() {
            match audit_raw_tokens(text) {
                Ok(findings) => {
                    for (policy, detail) in findings {
                        self.report(cx, span, &policy, &detail);
                    }
                }
                Err(detail) => {
                    self.report(cx, span, "N3", &format!("raw token parse failed: {detail}"))
                }
            }
        }
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
    fn restricted(&self) -> bool {
        let cfg = crate::internal_read::config();
        let package = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
        cfg["restricted_packages"]
            .as_array()
            .is_some_and(|p| p.iter().any(|p| p.as_str() == Some(&package)))
    }
    fn n4(&self, cx: &EarlyContext<'_>, span: Span) -> bool {
        let cfg = crate::internal_read::config();
        let file = self.file(cx, span);
        let reviewed = cfg["reviewed_target_files"]
            .as_array()
            .is_some_and(|p| p.iter().any(|p| p["file"].as_str() == Some(&file)));
        self.restricted() && !reviewed
    }
    fn leaf(&mut self, cx: &EarlyContext<'_>, attrs: &[ast::Attribute], span: Span, kind: &str) {
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
                    let (owner, owner_span) = self
                        .source_owners
                        .last()
                        .cloned()
                        .unwrap_or_else(|| (String::new(), span));
                    let scope_span = self
                        .source_owners
                        .first()
                        .map(|(_, span)| *span)
                        .unwrap_or(owner_span);
                    crate::internal_read::register_leaf(
                        &reason,
                        attr.span,
                        span,
                        kind,
                        owner_span,
                        scope_span,
                        &owner,
                        &self.source_owners,
                    );
                    // The compiler leaf span excludes its attributes. Use that
                    // same token source in both pre-expansion and HIR reports.
                    let tokens = crate::internal_read::normalized_leaf(cx.sess(), span);
                    crate::internal_read::emit(
                        json!({"schema":1,"kind":"expectation","source_lexical_owner":owner,"owner_span":crate::internal_read::span(cx.sess(),owner_span),"reason":reason,"lint":lint,"span":crate::internal_read::span(cx.sess(),attr.span),"leaf":{"span":crate::internal_read::span(cx.sess(),span),"kind":kind,"tokens":tokens},"source":true}),
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
        // Rustc supplies pre-configured root attributes to check_attributes,
        // but the crate AST still has their original cfg_attr spelling here.
        // Audit that compiler-owned syntax before conditional lint attributes
        // can become indistinguishable from direct approvals.
        for attr in &krate.attrs {
            self.raw_attribute(cx, attr);
            let Some(meta) = parsed(attr) else { continue };
            if contains_link_name(&meta) {
                crate::internal_read::n2_raw_pending(
                    attr.span,
                    "link_name outside reviewed module",
                    None,
                );
            }
            if self.restricted() {
                if let Err(detail) = suppression_attribute_with_lints(&meta, &self.protected_lints)
                {
                    self.report(cx, attr.span, "EXPECT", &detail);
                }
                match clippy_attribute(&meta) {
                    Ok(true) => self.report(
                        cx,
                        attr.span,
                        "N4",
                        "clippy cfg predicate hides code from native Clippy",
                    ),
                    Err(detail) => self.report(cx, attr.span, "N4", &detail),
                    Ok(false) => {}
                }
            }
            match inventory_attribute(&meta) {
                Ok(Some(_)) => self.report(
                    cx,
                    attr.span,
                    "EXPECT",
                    "inventory expectation must own a narrow statement/type leaf",
                ),
                Err(detail) => self.report(cx, attr.span, "EXPECT", &detail),
                Ok(None) => {}
            }
            match target_attribute(&meta) {
                Ok(true) => {
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
                Err(detail) if self.restricted() => self.report(cx, attr.span, "N4", &detail),
                Ok(false) | Err(_) => {}
            }
        }
    }
    fn check_attributes(&mut self, cx: &EarlyContext<'_>, attrs: &[ast::Attribute]) {
        for attr in attrs {
            self.raw_attribute(cx, attr);
        }
        if self.restricted() {
            for attr in attrs {
                let Some(meta) = parsed(attr) else {
                    continue;
                };
                match clippy_attribute(&meta) {
                    Ok(true) => self.report(
                        cx,
                        attr.span,
                        "N4",
                        "clippy cfg predicate hides code from native Clippy",
                    ),
                    Err(detail) => self.report(cx, attr.span, "N4", &detail),
                    Ok(false) => {}
                }
            }
        }
        // Audit every compiler-loaded node structurally, including inactive
        // inline bodies. HIR events, rather than a second cfg evaluator, tell
        // the manifest which expectations have compiled operations.
        for attr in attrs {
            let Some(meta) = parsed(attr) else {
                continue;
            };
            if self.restricted() {
                if let Err(detail) = suppression_attribute_with_lints(&meta, &self.protected_lints)
                {
                    self.report(cx, attr.span, "EXPECT", &detail);
                }
            }
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
            match target_attribute(&meta) {
                Ok(true) => {
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
                Err(detail) if self.restricted() => self.report(cx, attr.span, "N4", &detail),
                Ok(false) | Err(_) => {}
            }
        }
    }
    fn check_attributes_post(&mut self, cx: &EarlyContext<'_>, attrs: &[ast::Attribute]) {
        // Every protected attribute must have been claimed by a supported
        // compiler leaf callback. Unclaimed subjects (fields, parameters, etc.)
        // cannot disappear from review merely because their cfg is inactive.
        for attr in attrs {
            let Some(meta) = parsed(attr) else {
                continue;
            };
            if matches!(inventory_attribute(&meta), Ok(Some(_)))
                && !self
                    .leaf_emitted
                    .contains(&(attr.span.lo().0, attr.span.hi().0))
            {
                self.report(
                    cx,
                    attr.span,
                    "EXPECT",
                    "inventory expectation must own a narrow statement/type leaf",
                );
            }
        }
    }
    fn check_item(&mut self, cx: &EarlyContext<'_>, item: &ast::Item) {
        // This pass is recreated for each compiler-loaded external module.
        // Keep an AST-declared suffix relative to this traversal root; HIR
        // module spans provide the canonical scope after expansion.
        let owner = match item.kind.ident() {
            Some(ident) => self.child_owner(ident.name.as_str()),
            None if matches!(item.kind, ItemKind::Impl(_)) => self.child_owner("<unresolved-impl>"),
            None => self
                .source_owners
                .last()
                .map(|(name, _)| name.clone())
                .unwrap_or_default(),
        };
        self.source_owners.push((owner, item.span));
        let kind = match &item.kind {
            ItemKind::Fn(_) => "fn",
            ItemKind::Mod(..) => "mod",
            ItemKind::Impl(_) => "impl",
            ItemKind::Use(_) => "use",
            ItemKind::TyAlias(_) => "type",
            _ => "item",
        };
        self.leaf(cx, &item.attrs, item.span, kind);
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
        self.source_owners.pop();
        if matches!(item.kind, ItemKind::Mod(..)) {
            self.module_spans.pop();
        }
    }
    fn check_impl_item(&mut self, _: &EarlyContext<'_>, item: &ast::AssocItem) {
        let owner = item
            .kind
            .ident()
            .map(|ident| self.child_owner(ident.name.as_str()))
            .unwrap_or_else(|| {
                self.source_owners
                    .last()
                    .map(|(name, _)| name.clone())
                    .unwrap_or_default()
            });
        self.source_owners.push((owner, item.span));
    }
    fn check_impl_item_post(&mut self, _: &EarlyContext<'_>, _: &ast::AssocItem) {
        self.source_owners.pop();
    }
    fn check_trait_item(&mut self, cx: &EarlyContext<'_>, item: &ast::AssocItem) {
        self.check_impl_item(cx, item);
    }
    fn check_trait_item_post(&mut self, cx: &EarlyContext<'_>, item: &ast::AssocItem) {
        self.check_impl_item_post(cx, item);
    }
    fn check_stmt(&mut self, cx: &EarlyContext<'_>, stmt: &ast::Stmt) {
        let kind = match stmt.kind {
            StmtKind::Let(_) => "let",
            StmtKind::Expr(_) | StmtKind::Semi(_) => "statement",
            _ => return,
        };
        self.leaf(cx, stmt.attrs(), stmt.span, kind);
    }
    fn check_expr(&mut self, cx: &EarlyContext<'_>, expr: &ast::Expr) {
        let kind = match expr.kind {
            ast::ExprKind::Block(..) => "block",
            ast::ExprKind::Closure(..) => "closure",
            _ => "expression",
        };
        self.leaf(cx, &expr.attrs, expr.span, kind);
    }
    fn check_mac_def(&mut self, cx: &EarlyContext<'_>, def: &ast::MacroDef) {
        let text = pprust::tts_to_string(&def.body.tokens);
        if !def.macro_rules {
            self.raw_tokens(cx, def.body.dspan.entire(), &text);
            return;
        }
        match audit_macro_with_lints(&text, self.restricted(), &self.protected_lints) {
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
        let macro_tokens = pprust::tts_to_string(&mac.args.tokens);
        // Inspect every invocation payload before expansion, even if the macro
        // discards it. Restricted raw streams cannot construct new definitions.
        match audit_macro_payload_with_lints(
            &macro_tokens,
            self.restricted(),
            &self.protected_lints,
        ) {
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
        // cfg! yields a boolean; both branches remain type-checked and linted.
        // Its spelling, nesting and aliases do not create N4 obligations.
    }
}
