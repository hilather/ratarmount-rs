//! N2/N3 grammar checks over compiler-provided macro token streams.
//! No operation names, imports, reexports, pathname resolution or flags are interpreted.
use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use std::collections::BTreeSet;

#[derive(Default)]
struct Audit {
    findings: BTreeSet<(usize, String, String)>,
}

fn normalized_ident(id: &proc_macro2::Ident) -> String {
    id.to_string().trim_start_matches("r#").to_string()
}

fn is_ident(token: &TokenTree, name: &str) -> bool {
    matches!(token, TokenTree::Ident(id) if normalized_ident(id) == name)
}

fn contains_dollar(tokens: TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Punct(p) => p.as_char() == '$',
        TokenTree::Group(g) => contains_dollar(g.stream()),
        _ => false,
    })
}

fn contains_target_cfg(tokens: TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(id) => {
            let name = normalized_ident(&id);
            name == "windows" || name == "unix" || name.starts_with("target_")
        }
        TokenTree::Group(g) => contains_target_cfg(g.stream()),
        _ => false,
    })
}

fn contains_ident(tokens: TokenStream, name: &str) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(id) => normalized_ident(&id) == name,
        TokenTree::Group(g) => contains_ident(g.stream(), name),
        _ => false,
    })
}

impl Audit {
    fn emit(&mut self, span: Span, policy: &str, detail: &str) {
        self.findings
            .insert((span.start().line, policy.into(), detail.into()));
    }

    // Token inspection here is restricted to Rust grammar constructs. There is
    // no operation-name, filesystem-symbol, alias, or path-resolution policy.
    fn tokens(&mut self, tokens: TokenStream, macro_body: bool, transcriber: bool) {
        let tokens: Vec<_> = tokens.into_iter().collect();
        for (i, token) in tokens.iter().enumerate() {
            if is_ident(token, "macro_rules")
                && matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!')
                && matches!(tokens.get(i + 2), Some(TokenTree::Ident(_)))
            {
                if let Some(TokenTree::Group(body)) = tokens.get(i + 3) {
                    self.macro_rules(body.stream());
                }
            }
            if macro_body
                && transcriber
                && matches!(token, TokenTree::Punct(p) if p.as_char() == '$')
                && matches!(tokens.get(i + 1), Some(TokenTree::Ident(_)))
            {
                let mut next = i + 2;
                if matches!(tokens.get(next), Some(TokenTree::Literal(_))) {
                    next += 1;
                } else if matches!(tokens.get(next), Some(TokenTree::Punct(p)) if p.as_char() == '$')
                    && matches!(tokens.get(next + 1), Some(TokenTree::Ident(_)))
                {
                    next += 2;
                }
                // ABI may be emitted through an optional/repeated macro fragment.
                // This is conservative grammar recognition, never a symbol lookup.
                while matches!(tokens.get(next), Some(TokenTree::Punct(p)) if p.as_char() == '$')
                    && matches!(tokens.get(next + 1), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis)
                {
                    next += 2;
                    if matches!(tokens.get(next), Some(TokenTree::Punct(p)) if !matches!(p.as_char(), '?' | '*' | '+'))
                    {
                        next += 1;
                    }
                    if matches!(tokens.get(next), Some(TokenTree::Punct(p)) if matches!(p.as_char(), '?' | '*' | '+'))
                    {
                        next += 1;
                    }
                }
                let item_head = i == 0
                    || matches!(tokens.get(i.wrapping_sub(1)), Some(TokenTree::Punct(p)) if p.as_char() == ';')
                    || matches!(tokens.get(i.wrapping_sub(1)), Some(TokenTree::Group(g)) if matches!(g.delimiter(), Delimiter::Brace | Delimiter::Bracket))
                    || tokens
                        .get(i.wrapping_sub(1))
                        .is_some_and(|t| is_ident(t, "unsafe"));
                if (next != i + 2 || item_head)
                    && matches!(tokens.get(next), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace)
                {
                    self.emit(
                        token.span(),
                        "N2",
                        "undecidable substituted extern keyword position",
                    );
                }
            }

            if macro_body && (is_ident(token, "cfg") || is_ident(token, "cfg_attr")) {
                self.emit(token.span(), "N3", "cfg/cfg_attr token in macro_rules body");
            }
            if is_ident(token, "extern") {
                // An extern block has a brace group immediately after `extern`
                // or after an optional ABI string. `extern crate` and function
                // declarations/types do not match this grammar.
                let next = match tokens.get(i + 1) {
                    Some(TokenTree::Literal(_)) => tokens.get(i + 2),
                    other => other,
                };
                if matches!(next, Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace) {
                    self.emit(token.span(), "N2", "extern block outside reviewed module");
                }
                if macro_body
                    && transcriber
                    && matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '$')
                {
                    self.emit(
                        token.span(),
                        "N2",
                        "substituted extern ABI outside reviewed module",
                    );
                }
            }
            if matches!(token, TokenTree::Punct(p) if p.as_char() == '#') {
                let attr_index = i
                    + 1
                    + usize::from(
                        matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!'),
                    );
                if let Some(TokenTree::Group(group)) = tokens.get(attr_index) {
                    if group.delimiter() == Delimiter::Bracket {
                        let inner: Vec<_> = group.stream().into_iter().collect();
                        if inner.first().is_some_and(|t| is_ident(t, "link_name"))
                            || (inner.first().is_some_and(|t| is_ident(t, "cfg_attr"))
                                && contains_ident(group.stream(), "link_name"))
                        {
                            self.emit(token.span(), "N2", "link_name outside reviewed module");
                        }
                        if macro_body && transcriber && contains_dollar(group.stream()) {
                            self.emit(token.span(), "N3", "metavariable transcriber attribute");
                        }
                    }
                }
            }
            if let TokenTree::Group(group) = token {
                // A literal nested definition starts a new matcher/transcriber
                // grammar. It was audited above; the enclosing transcriber
                // must not reinterpret its generic attribute matcher.
                let nested_definition = i >= 3
                    && is_ident(&tokens[i - 3], "macro_rules")
                    && matches!(&tokens[i - 2], TokenTree::Punct(p) if p.as_char() == '!')
                    && matches!(&tokens[i - 1], TokenTree::Ident(_));
                if !nested_definition {
                    self.tokens(group.stream(), macro_body, transcriber);
                }
            }
        }
    }

    fn macro_rules(&mut self, tokens: TokenStream) {
        // Parse the outer macro arm grammar, preserving delimiters. Matching
        // #[$attr] in a matcher is permitted; emitting it is refused.
        let tokens: Vec<_> = tokens.clone().into_iter().collect();
        self.tokens(tokens.iter().cloned().collect(), true, false);
        for window in tokens.windows(3) {
            if matches!(&window[0], TokenTree::Punct(p) if p.as_char() == '=')
                && matches!(&window[1], TokenTree::Punct(p) if p.as_char() == '>')
            {
                if let TokenTree::Group(body) = &window[2] {
                    self.tokens(body.stream(), true, true);
                }
            }
        }
    }
}

/// Audit one compiler-observed `macro_rules!` body. N2 findings remain pending
/// until the adapter applies the single exact compiler-module exception.
pub fn audit_macro(source: &str) -> Result<Vec<(String, String)>, String> {
    let tokens = source.parse::<TokenStream>().map_err(|e| e.to_string())?;
    let mut audit = Audit::default();
    audit.macro_rules(tokens);
    Ok(audit
        .findings
        .into_iter()
        .map(|(_, policy, detail)| (policy, detail))
        .collect())
}

/// Inspect only a syntactic cfg expression, recursively normalizing raw identifiers.
pub fn target_predicate(tokens: TokenStream) -> bool {
    contains_target_cfg(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policies(source: &str) -> Vec<String> {
        audit_macro(source)
            .unwrap()
            .into_iter()
            .map(|(policy, _)| policy)
            .collect()
    }
    #[test]
    fn regression_substituted_transcriber_attributes() {
        for src in [
            "($guard:meta) => { #[$guard] fn hidden() {} };",
            "($($guard:meta),*) => { $(#[$guard])* fn hidden() {} };",
        ] {
            assert!(policies(src).iter().any(|p| p == "N3"), "{src}");
        }
        assert!(policies("(#[$guard:meta]) => { pub fn fine() {} };").is_empty());
        assert!(policies(
            "() => { macro_rules! inner { (#[$guard:meta]) => { pub fn fine() {} }; } };"
        )
        .is_empty());
    }
    #[test]
    fn regression_cfg_matcher_transcriber_raw_and_nested_macro() {
        for src in [
            "(#[cfg(unix)]) => {};",
            "() => { #[r#cfg_attr(all(), allow(dead_code))] fn f() {} };",
            "() => { macro_rules! inner { () => { #[cfg(unix)] fn f() {} } } };",
        ] {
            assert!(policies(src).iter().any(|p| p == "N3"), "{src}");
        }
    }
    #[test]
    fn regression_extern_optional_abi_and_arbitrary_foreign_names() {
        for src in [
            "($keyword:ident $($abi:literal)?) => { $keyword $($abi)? { fn arbitrary(); } };",
            "($keyword:ident) => { $keyword { fn arbitrary(); } };",
            "($keyword:ident) => { #[allow(dead_code)] $keyword { fn arbitrary(); } };",
            "() => { unsafe extern { fn arbitrary(); } };",
            r#"() => { unsafe extern "C" { #[link_name="not_a_symbol_policy"] fn arbitrary(); } };"#,
        ] {
            assert!(policies(src).iter().any(|p| p == "N2"), "{src}");
        }
        assert!(policies(r#"() => { pub extern "C" fn callback() {} type Callback = extern "C" fn(); extern crate std; };"#).is_empty());
    }
    #[test]
    fn regression_all_target_predicates() {
        for src in [
            "not(unix)",
            "windows",
            r#"all(feature="x", target_os="macos")"#,
            r#"r#target_arch="aarch64""#,
        ] {
            assert!(target_predicate(src.parse().unwrap()));
        }
        assert!(!target_predicate(r#"feature="windows""#.parse().unwrap()));
    }
}

/// Exact reserved activation protocol. This parses metadata, never operations.
pub fn inventory_attribute(meta: &syn::Meta) -> Result<Option<(String, String)>, String> {
    use syn::{parse::Parser, punctuated::Punctuated, Expr, Lit, Token};
    fn named(path: &syn::Path, name: &str) -> bool {
        path.leading_colon.is_none() && path.segments.len() == 1 && path.segments[0].ident == name
    }
    let rendered = quote_meta(meta);
    if !contains_ident(rendered.clone(), "internal_read_inventory") {
        return Ok(None);
    }
    let syn::Meta::List(outer) = meta else {
        return Err("reserved activation outside exact cfg_attr(expect)".into());
    };
    if !named(&outer.path, "cfg_attr") {
        return Err("reserved activation outside exact cfg_attr(expect)".into());
    }
    let parts = Punctuated::<syn::Meta, Token![,]>::parse_terminated
        .parse2(outer.tokens.clone())
        .map_err(|e| e.to_string())?;
    if parts.len() != 2 {
        return Err("inventory cfg_attr requires exactly predicate and expect".into());
    }
    let mut parts = parts.into_iter();
    if !matches!(parts.next(), Some(syn::Meta::Path(path)) if named(&path,"internal_read_inventory"))
    {
        return Err("reserved activation predicate must be literal internal_read_inventory".into());
    }
    let Some(syn::Meta::List(expect)) = parts.next() else {
        return Err("inventory cfg_attr must contain expect".into());
    };
    if !named(&expect.path, "expect") {
        return Err("inventory activation permits expect only".into());
    }
    let args = Punctuated::<syn::Meta, Token![,]>::parse_terminated
        .parse2(expect.tokens)
        .map_err(|e| e.to_string())?;
    if args.len() != 2 {
        return Err("inventory expect requires one lint and one literal reason".into());
    }
    let mut args = args.into_iter();
    let Some(syn::Meta::Path(lint)) = args.next() else {
        return Err("missing inventory lint".into());
    };
    let lint = lint
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::");
    if !matches!(
        lint.as_str(),
        "clippy::disallowed_methods" | "clippy::disallowed_types"
    ) {
        return Err("invalid inventory lint".into());
    }
    let Some(syn::Meta::NameValue(reason)) = args.next() else {
        return Err("missing inventory reason".into());
    };
    if !named(&reason.path, "reason") {
        return Err("missing inventory reason".into());
    }
    let Expr::Lit(syn::ExprLit {
        lit: Lit::Str(reason),
        ..
    }) = reason.value
    else {
        return Err("inventory reason must be a literal string".into());
    };
    let reason = reason.value();
    if !reason.starts_with("internal-read:v1 ") {
        return Err("invalid inventory reason namespace".into());
    }
    Ok(Some((lint, reason)))
}

fn quote_meta(meta: &syn::Meta) -> TokenStream {
    use quote::ToTokens;
    meta.to_token_stream()
}

/// Find target predicates in cfg/cfg_attr grammar only. A nested ordinary
/// attribute named target_feature is not itself a cfg predicate.
pub fn target_attribute(meta: &syn::Meta) -> bool {
    use syn::{parse::Parser, punctuated::Punctuated, Token};
    let syn::Meta::List(list) = meta else {
        return false;
    };
    let name = list
        .path
        .segments
        .last()
        .map(|s| s.ident.to_string().trim_start_matches("r#").to_owned())
        .unwrap_or_default();
    match name.as_str() {
        "cfg" => target_predicate(list.tokens.clone()),
        "cfg_attr" => {
            let Ok(parts) =
                Punctuated::<syn::Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone())
            else {
                return false;
            };
            let mut parts = parts.iter();
            parts
                .next()
                .is_some_and(|predicate| target_predicate(quote_meta(predicate)))
                || parts.any(target_attribute)
        }
        _ => false,
    }
}

#[cfg(test)]
mod cfg_attribute_tests {
    use super::*;
    #[test]
    fn regression_target_attribute_names_are_not_predicates() {
        let ordinary: syn::Meta =
            syn::parse_str(r#"cfg_attr(feature="simd",target_feature(enable="sse2"))"#).unwrap();
        assert!(!target_attribute(&ordinary));
        for source in [
            r#"cfg_attr(unix, target_feature(enable="sse2"))"#,
            r#"cfg_attr(all(),cfg_attr(all(),cfg(not(windows))))"#,
        ] {
            assert!(target_attribute(&syn::parse_str(source).unwrap()));
        }
    }
}
