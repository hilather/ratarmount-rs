//! N2/N3 grammar checks over compiler-provided macro token streams.
//! No operation names, imports, reexports, pathname resolution or flags are interpreted.
use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use std::collections::BTreeSet;

#[derive(Default)]
struct Audit {
    restricted: bool,
    suppression_lint_names: BTreeSet<String>,
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

// Only token-tree fragments can substitute a raw `#`, `!` or bracket group.
// Typed fragments are opaque to the transcriber, including empty `vis` fragments.
fn matcher_fragments(
    tokens: TokenStream,
    fragments: &mut std::collections::BTreeMap<String, String>,
) {
    let tokens: Vec<_> = tokens.into_iter().collect();
    for window in tokens.windows(4) {
        if matches!(&window[0], TokenTree::Punct(p) if p.as_char() == '$')
            && matches!(&window[2], TokenTree::Punct(p) if p.as_char() == ':')
        {
            if let (TokenTree::Ident(name), TokenTree::Ident(kind)) = (&window[1], &window[3]) {
                fragments.insert(normalized_ident(name), normalized_ident(kind));
            }
        }
    }
    for token in tokens {
        if let TokenTree::Group(group) = token {
            matcher_fragments(group.stream(), fragments);
        }
    }
}

// A non-repeated capture denotes one opaque token. Repeated captures are
// unknown: the same name can supply different punctuation in each iteration.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CaptureIdentity {
    Single(String),
    Repeated,
}
type AttributeStates = BTreeSet<(u8, Option<CaptureIdentity>, Option<CaptureIdentity>)>;

fn same_single_capture(identity: &Option<CaptureIdentity>, name: &str, repeated: bool) -> bool {
    !repeated && matches!(identity, Some(CaptureIdentity::Single(captured)) if captured == name)
}

fn whole_payload_forwarding(tokens: &[TokenTree]) -> bool {
    matches!(tokens, [TokenTree::Punct(dollar), TokenTree::Group(body), TokenTree::Punct(quantifier)]
        if dollar.as_char() == '$'
            && body.delimiter() == Delimiter::Parenthesis
            && matches!(quantifier.as_char(), '*' | '+' | '?')
            && matches!(body.stream().into_iter().collect::<Vec<_>>().as_slice(),
                [TokenTree::Punct(capture), TokenTree::Ident(_)] if capture.as_char() == '$'))
}

fn no_attribute_prefix() -> AttributeStates {
    BTreeSet::from([(0, None, None)])
}

impl Audit {
    fn emit(&mut self, span: Span, policy: &str, detail: &str) {
        self.findings
            .insert((span.start().line, policy.into(), detail.into()));
    }

    // Inspect every raw stream recursively, without interpreting an invocation's
    // payload or generated grammar. The adapter supplies literal definitions as
    // bodies, so only their already-audited outer `macro_rules` head is absent.
    fn raw_tokens(&mut self, tokens: TokenStream) {
        if !self.restricted {
            return;
        }
        let tokens: Vec<_> = tokens.into_iter().collect();
        for (i, token) in tokens.iter().enumerate() {
            if is_ident(token, "macro_rules") {
                self.emit(
                    token.span(),
                    "N3",
                    "macro_rules token outside literal definition",
                );
            }
            if matches!(token, TokenTree::Punct(p) if p.as_char() == '$')
                && matches!(tokens.get(i + 1), Some(TokenTree::Ident(_)))
                && matches!(tokens.get(i + 2), Some(TokenTree::Punct(p)) if p.as_char() == '!')
            {
                self.emit(token.span(), "N3", "metavariable macro invocation head");
            }
            if let TokenTree::Group(group) = token {
                self.raw_tokens(group.stream());
            }
        }
    }

    // Token inspection here is restricted to Rust grammar constructs. There is
    // no operation-name, filesystem-symbol, alias, or path-resolution policy.
    fn tokens(
        &mut self,
        tokens: TokenStream,
        macro_body: bool,
        transcriber: bool,
        fragments: &std::collections::BTreeMap<String, String>,
    ) {
        if transcriber {
            self.attribute_tokens(tokens.clone(), no_attribute_prefix(), fragments, false);
        }
        let tokens: Vec<_> = tokens.into_iter().collect();
        for (i, token) in tokens.iter().enumerate() {
            if is_ident(token, "macro")
                && !matches!(tokens.get(i.wrapping_sub(1)), Some(TokenTree::Punct(p)) if p.as_char() == '$')
            {
                self.emit(token.span(), "N3", "unsupported macro definition grammar");
            }
            if transcriber
                && is_ident(token, "macro_rules")
                && matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!')
                && !self.restricted
                && matches!(tokens.get(i + 2), Some(TokenTree::Ident(_)))
            {
                if let Some(TokenTree::Group(body)) = tokens.get(i + 3) {
                    self.macro_rules(body.stream(), fragments);
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

            let boolean_cfg = is_ident(token, "cfg")
                && matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!');
            if macro_body && !boolean_cfg && (is_ident(token, "cfg") || is_ident(token, "cfg_attr"))
            {
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
                if macro_body
                    && transcriber
                    && matches!(tokens.get(attr_index), Some(TokenTree::Punct(p)) if p.as_char() == '$')
                {
                    self.emit(
                        token.span(),
                        "N3",
                        "metavariable transcriber attribute delimiter",
                    );
                }
                if let Some(TokenTree::Group(group)) = tokens.get(attr_index) {
                    if group.delimiter() == Delimiter::Bracket {
                        let inner: Vec<_> = group.stream().into_iter().collect();
                        if self.restricted && macro_body && transcriber {
                            if let Ok(meta) = syn::parse2::<syn::Meta>(group.stream()) {
                                if let Err(detail) = suppression_attribute_with_lints(
                                    &meta,
                                    &self.suppression_lint_names,
                                ) {
                                    self.emit(token.span(), "EXPECT", &detail);
                                }
                            }
                        }
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
                // Restricted transcribers refuse nested definitions above.
                // Other packages audit the literal nested grammar separately.
                // Neither case reinterprets its matcher as emitted attributes.
                let nested_definition = (i >= 3
                    && is_ident(&tokens[i - 3], "macro_rules")
                    && matches!(&tokens[i - 2], TokenTree::Punct(p) if p.as_char() == '!')
                    && matches!(&tokens[i - 1], TokenTree::Ident(_)))
                    || (i >= 4
                        && is_ident(&tokens[i - 4], "macro_rules")
                        && matches!(&tokens[i - 3], TokenTree::Punct(p) if p.as_char() == '!')
                        && matches!(&tokens[i - 2], TokenTree::Punct(p) if p.as_char() == '$')
                        && matches!(&tokens[i - 1], TokenTree::Ident(_)));
                if !nested_definition || !transcriber {
                    self.tokens(group.stream(), macro_body, transcriber, fragments);
                }
            }
        }
    }

    fn macro_payload(&mut self, tokens: TokenStream) {
        let tokens: Vec<_> = tokens.into_iter().collect();
        let mut i = 0;
        while i < tokens.len() {
            if is_ident(&tokens[i], "macro")
                && !matches!(tokens.get(i.wrapping_sub(1)), Some(TokenTree::Punct(p)) if p.as_char() == '$')
            {
                self.emit(
                    tokens[i].span(),
                    "N3",
                    "unsupported macro definition grammar",
                );
            }
            // Invocation grammar is opaque: forwarding an attributed expression
            // can strip it before Clippy sees it. Refuse every cfg/cfg_attr
            // attribute, even in discarded or nested payloads, without trying
            // to evaluate the predicate or model the receiving macro.
            if matches!(&tokens[i], TokenTree::Punct(p) if p.as_char() == '#') {
                let attr_index = i
                    + 1
                    + usize::from(
                        matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!'),
                    );
                if let Some(TokenTree::Group(group)) = tokens.get(attr_index) {
                    if group.delimiter() == Delimiter::Bracket
                        && group
                            .stream()
                            .into_iter()
                            .next()
                            .is_some_and(|t| is_ident(&t, "cfg") || is_ident(&t, "cfg_attr"))
                    {
                        self.emit(
                            tokens[i].span(),
                            "N3",
                            "cfg/cfg_attr attribute in macro invocation payload",
                        );
                    }
                }
            }
            if is_ident(&tokens[i], "macro_rules")
                && matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!')
                && matches!(tokens.get(i + 2), Some(TokenTree::Ident(_)))
            {
                if let Some(TokenTree::Group(body)) = tokens.get(i + 3) {
                    self.macro_rules(body.stream(), &Default::default());
                    i += 4;
                    continue;
                }
            }
            if let TokenTree::Group(group) = &tokens[i] {
                self.macro_payload(group.stream());
            }
            i += 1;
        }
    }

    fn macro_rules(
        &mut self,
        tokens: TokenStream,
        inherited: &std::collections::BTreeMap<String, String>,
    ) {
        // Preserve each arm's matcher/transcriber boundary and fragment kinds.
        // Matching #[$attr] is permitted; emitting it is refused.
        let tokens: Vec<_> = tokens.into_iter().collect();
        self.tokens(tokens.iter().cloned().collect(), true, false, inherited);
        for window in tokens.windows(4) {
            if matches!(&window[1], TokenTree::Punct(p) if p.as_char() == '=')
                && matches!(&window[2], TokenTree::Punct(p) if p.as_char() == '>')
            {
                if let (TokenTree::Group(matcher), TokenTree::Group(body)) =
                    (&window[0], &window[3])
                {
                    let mut fragments = inherited.clone();
                    matcher_fragments(matcher.stream(), &mut fragments);
                    self.tokens(body.stream(), true, true, &fragments);
                }
            }
        }
    }

    // Recognize the attribute prefix grammar, independent of its subject.
    // States retain `#`/`#!` and the identities of substituted punctuation.
    // Repetitions compose these finite states, including nullable boundaries.
    fn attribute_token(&mut self, token: &TokenTree, states: &AttributeStates) -> AttributeStates {
        if matches!(token, TokenTree::Punct(p) if p.as_char() == '#') {
            return BTreeSet::from([(1, None, None)]);
        }
        if matches!(token, TokenTree::Punct(p) if p.as_char() == '!') {
            return states
                .iter()
                .map(|(prefix, hash, _)| {
                    if *prefix == 1 {
                        (2, hash.clone(), None)
                    } else {
                        (0, None, None)
                    }
                })
                .collect();
        }
        if let TokenTree::Group(group) = token {
            if group.delimiter() == Delimiter::Bracket {
                let substituted = contains_dollar(group.stream());
                if states.iter().any(|(prefix, hash, bang)| {
                    *prefix != 0 && (hash.is_some() || bang.is_some() || substituted)
                }) {
                    self.emit(
                        token.span(),
                        "N3",
                        "metavariable transcriber attribute prefix",
                    );
                }
            }
        }
        no_attribute_prefix()
    }

    fn attribute_tokens(
        &mut self,
        tokens: TokenStream,
        mut states: AttributeStates,
        fragments: &std::collections::BTreeMap<String, String>,
        repeated_capture: bool,
    ) -> AttributeStates {
        let tokens: Vec<_> = tokens.into_iter().collect();
        let mut i = 0;
        while i < tokens.len() {
            // An opaque trailing payload has no fixed suffix to hide. Preserve
            // whole-item and macro-argument forwarding only outside an active
            // attribute prefix or an enclosing unknown repetition.
            if !repeated_capture
                && states == no_attribute_prefix()
                && whole_payload_forwarding(&tokens[i..])
            {
                return no_attribute_prefix();
            }
            if matches!(&tokens[i], TokenTree::Punct(p) if p.as_char() == '$') {
                if let Some(TokenTree::Ident(name)) = tokens.get(i + 1) {
                    let name = normalized_ident(name);
                    match fragments.get(&name).map(String::as_str) {
                        Some("tt") | None if name != "crate" => {
                            let mut possible = no_attribute_prefix();
                            let identity = if repeated_capture {
                                CaptureIdentity::Repeated
                            } else {
                                CaptureIdentity::Single(name.clone())
                            };
                            possible.insert((1, Some(identity.clone()), None));
                            for (prefix, hash, bang) in &states {
                                // A single capture cannot be both punctuation
                                // and a bracket group. Repetition is unknown.
                                if *prefix != 0
                                    && !same_single_capture(hash, &name, repeated_capture)
                                    && !same_single_capture(bang, &name, repeated_capture)
                                {
                                    self.emit(
                                        tokens[i].span(),
                                        "N3",
                                        "metavariable transcriber attribute prefix",
                                    );
                                }
                                if *prefix == 1
                                    && !same_single_capture(hash, &name, repeated_capture)
                                {
                                    possible.insert((2, hash.clone(), Some(identity.clone())));
                                }
                            }
                            states = possible;
                        }
                        _ => {
                            states = no_attribute_prefix();
                        }
                    }
                    i += 2;
                    continue;
                }
                if let Some(TokenTree::Group(body)) = tokens.get(i + 1) {
                    if body.delimiter() == Delimiter::Parenthesis {
                        let mut end = i + 2;
                        let separator = match tokens.get(end) {
                            Some(TokenTree::Punct(p)) if matches!(p.as_char(), '?' | '*' | '+') => {
                                None
                            }
                            Some(token) => {
                                end += 1;
                                Some(token)
                            }
                            None => None,
                        };
                        if let Some(TokenTree::Punct(quantifier)) = tokens.get(end) {
                            if matches!(quantifier.as_char(), '?' | '*' | '+') {
                                let mut repeated = self.attribute_tokens(
                                    body.stream(),
                                    states.clone(),
                                    fragments,
                                    true,
                                );
                                if quantifier.as_char() != '?' {
                                    let mut reached = repeated.clone();
                                    loop {
                                        if let Some(separator) = separator {
                                            repeated = self.attribute_token(separator, &repeated);
                                        }
                                        repeated = self.attribute_tokens(
                                            body.stream(),
                                            repeated,
                                            fragments,
                                            true,
                                        );
                                        let previous = reached.len();
                                        reached.extend(repeated.iter().cloned());
                                        if reached.len() == previous {
                                            break;
                                        }
                                    }
                                    repeated = reached;
                                }
                                if quantifier.as_char() != '+' {
                                    repeated.extend(states);
                                }
                                states = repeated;
                                i = end + 1;
                                continue;
                            }
                        }
                    }
                }
            }
            states = self.attribute_token(&tokens[i], &states);
            i += 1;
        }
        states
    }
}

/// Audit a raw attribute stream in a restricted crate without assigning it
/// matcher/transcriber grammar. Literals remain opaque token trees.
pub fn audit_raw_tokens(source: &str) -> Result<Vec<(String, String)>, String> {
    let mut audit = Audit {
        restricted: true,
        ..Audit::default()
    };
    audit.raw_tokens(source.parse::<TokenStream>().map_err(|e| e.to_string())?);
    Ok(audit
        .findings
        .into_iter()
        .map(|(_, policy, detail)| (policy, detail))
        .collect())
}

/// Audit one compiler-observed `macro_rules!` body. N2 findings remain pending
/// until the adapter applies the single exact compiler-module exception.
pub fn audit_macro(source: &str) -> Result<Vec<(String, String)>, String> {
    audit_macro_scoped(source, false)
}

/// Apply restricted-package lint-level refusals to literal transcriber attributes.
pub fn audit_macro_scoped(source: &str, restricted: bool) -> Result<Vec<(String, String)>, String> {
    audit_macro_with_lints(source, restricted, &BTreeSet::new())
}

/// Lint groups are provided by the compiler's registered lint store.
pub fn audit_macro_with_lints(
    source: &str,
    restricted: bool,
    protected_lints: &BTreeSet<String>,
) -> Result<Vec<(String, String)>, String> {
    let tokens = source.parse::<TokenStream>().map_err(|e| e.to_string())?;
    let mut audit = Audit {
        restricted,
        suppression_lint_names: protected_lints.clone(),
        ..Audit::default()
    };
    audit.raw_tokens(tokens.clone());
    audit.macro_rules(tokens, &Default::default());
    Ok(audit
        .findings
        .into_iter()
        .map(|(_, policy, detail)| (policy, detail))
        .collect())
}

/// Audit literal nested definitions in a compiler-observed invocation payload.
/// Restricted packages also refuse macro-generation tokens in every raw stream,
/// even when an invocation discards them rather than expanding them as Rust.
pub fn audit_macro_payload(source: &str) -> Result<Vec<(String, String)>, String> {
    audit_macro_payload_scoped(source, false)
}

/// Preserve package scope for literal definitions nested in invocation payloads.
pub fn audit_macro_payload_scoped(
    source: &str,
    restricted: bool,
) -> Result<Vec<(String, String)>, String> {
    audit_macro_payload_with_lints(source, restricted, &BTreeSet::new())
}

/// Keep compiler-provided lint identities and refuse stripping attributes at
/// every depth in invocation payloads, including expressions forwarded by vec!.
pub fn audit_macro_payload_with_lints(
    source: &str,
    restricted: bool,
    protected_lints: &BTreeSet<String>,
) -> Result<Vec<(String, String)>, String> {
    let tokens = source.parse::<TokenStream>().map_err(|e| e.to_string())?;
    let mut audit = Audit {
        restricted,
        suppression_lint_names: protected_lints.clone(),
        ..Audit::default()
    };
    audit.raw_tokens(tokens.clone());
    audit.macro_payload(tokens);
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
    /// Regression: make!($) changes a generated macro's attribute grammar after
    /// the pre-expansion audit. Restricted transcribers cannot define macros.
    #[test]
    fn regression_macro_generating_macros_are_refused() {
        for source in [
            "($d:tt) => { macro_rules! hidden { ($d h:tt $d a:tt) => { $d h $d a pub fn hidden() { let _=std::fs::read(\"x\"); } } } };",
            "() => { macro_rules! inner { (#[$g:meta]) => { pub fn visible() {} } } };",
            "() => { pub fn visible() { macro_rules! inner { () => { 7 } } let _ = inner!(); } };",
            "($name:ident) => { macro_rules! $name { () => { 7 } } };",
        ] {
            assert!(
                audit_macro_scoped(source, true)
                    .unwrap()
                    .iter()
                    .any(|(policy, detail)| policy == "N3"
                        && detail == "macro_rules token outside literal definition"),
                "{source}"
            );
            let payload = format!("macro_rules! outer {{ {source} }}");
            assert!(
                audit_macro_payload_scoped(&payload, true)
                    .unwrap()
                    .iter()
                    .any(|(policy, detail)| policy == "N3"
                        && detail == "macro_rules token outside literal definition"),
                "{source}"
            );
        }
        let harmless = "() => { macro_rules! inner { () => { 7 } } };";
        assert!(audit_macro_scoped(harmless, false).unwrap().is_empty());
        assert!(audit_macro_scoped("() => { pub fn visible() {} };", true)
            .unwrap()
            .is_empty());
    }
    /// Regression: callers could substitute the macro_rules keyword and create
    /// unaudited definitions. Every raw token stream now fails closed.
    #[test]
    fn regression_raw_macro_generation_tokens() {
        for source in [
            "macro_rules",
            "(macro_rules $)",
            "r#macro_rules",
            "ignore! { nested!(macro_rules) }",
            "($kw:ident $d:tt) => { $kw! hidden { ($d h:tt $d a:tt) => { $d h $d a } } }",
            "$head ! ()",
        ] {
            for findings in [
                audit_macro_scoped(source, true).unwrap(),
                audit_macro_payload_scoped(source, true).unwrap(),
            ] {
                assert!(
                    findings.iter().any(|(policy, _)| policy == "N3"),
                    "{source}"
                );
            }
        }
        for source in ["() => { 7 }", "stringify!(\"macro_rules $head!\")"] {
            assert!(
                audit_macro_scoped(source, true).unwrap().is_empty(),
                "{source}"
            );
            assert!(
                audit_macro_payload_scoped(source, true).unwrap().is_empty(),
                "{source}"
            );
        }
    }
    /// Regression: substituted attribute delimiters/prefixes hid target-gated reads.
    #[test]
    fn regression_substituted_attribute_delimiters_and_prefixes() {
        for src in [
            "($attr:tt) => { # $attr pub fn hidden() {} };",
            "($attr:tt) => { mod hidden { #! $attr pub fn read() {} } };",
            "($($attr:tt)*) => { $(# $attr)* pub fn hidden() {} };",
            "($hash:tt $attr:meta) => { $hash [$attr] pub fn hidden() {} };",
            "($hash:tt $attr:meta) => { mod hidden { $hash ! [$attr] pub fn read() {} } };",
            "($hash:tt) => { $hash [allow(dead_code)] pub fn hidden() {} };",
        ] {
            assert!(policies(src).iter().any(|p| p == "N3"), "{src}");
        }
        for src in [
            "(# $attr:tt) => { pub fn fine() {} };",
            "(#! $attr:tt) => { pub fn fine() {} };",
            "($hash:tt [$attr:meta]) => { pub fn fine() {} };",
            "() => { macro_rules! inner { (# $attr:tt) => { pub fn fine() {} }; } };",
            "($array:expr, $index:expr) => { $array[$index] };",
            "($array:expr, $index:expr) => { let value = $array[$index]; value };",
            "($array:expr, $index:expr) => { $array[$index] + 1 };",
            "($macro:ident) => { $macro![tokens]; pub fn fine() {} };",
        ] {
            assert!(policies(src).is_empty(), "{src}");
        }
    }
    /// Regression: substituted attributes hid reads before non-keyword subjects
    /// or across nullable repetition boundaries.
    #[test]
    fn regression_substituted_attribute_grammar() {
        for src in [
            // both-substituted-item
            "($h:tt $a:tt) => { $h $a pub fn hidden() { let _ = std::fs::read(\"x\"); } }",
            // substituted-statement
            "($h:tt $a:meta) => { pub fn visible() { $h [$a] std::fs::read(\"x\").unwrap(); } }",
            // substituted-block
            "($h:tt $a:meta) => { pub fn visible() { $h [$a] { let _ = std::fs::read(\"x\"); } } }",
            // substituted-return
            "($h:tt $a:meta) => { pub fn visible() { $h [$a] return { let _ = std::fs::read(\"x\"); }; } }",
            // substituted-if
            "($h:tt $a:meta) => { pub fn visible() { $h [$a] if true { let _ = std::fs::read(\"x\"); } } }",
            // repeated-substituted-statement
            "($($h:tt $a:meta)*) => { pub fn visible() { $($h [$a])* std::fs::read(\"x\").unwrap(); } }",
            // substituted-field
            "($h:tt $a:meta) => { pub struct Visible { $h [$a] value: [u8; { let _ = std::fs::read(\"x\"); 1 }] } }",
            // substituted-variant
            "($h:tt $a:meta) => { pub enum Visible { Present, $h [$a] Hidden = { let _ = std::fs::read(\"x\"); 1 }, } }",
            // optional-hash
            "($($h:tt)?; $a:meta) => { $($h)? [$a] pub fn hidden() { let _=std::fs::read(\"x\"); } }",
            // optional-bracket
            "($h:tt; $($a:tt)?) => { $h $($a)? pub fn hidden() { let _=std::fs::read(\"x\"); } }",
            // optional-both
            "($($h:tt)?; $($a:tt)?) => { $($h)? $($a)? pub fn hidden() { let _=std::fs::read(\"x\"); } }",
            // optional-hash-inner
            "($($h:tt)?; $a:meta) => { mod nested { $($h)? ! [$a] pub fn hidden() { let _=std::fs::read(\"x\"); } } }",
            // optional-between
            "($h:tt; $(($b:tt))?; $a:meta) => { $h $($b)? [$a] pub fn hidden() { let _=std::fs::read(\"x\"); } }",
        ] {
            assert!(policies(src).iter().any(|p| p == "N3"), "{src}");
        }
        for src in [
            "($($tokens:tt)*) => { $($tokens)* };",
            "($token:tt) => { $token $token };",
            "($e:expr) => { macro_rules! inner { () => { $e[0] } } };",
            "($name:ident) => { $name[0] };",
        ] {
            assert!(policies(src).is_empty(), "{src}");
        }
        // A tt prefix cannot distinguish a hash from an indexed expression.
        // Use an expr/ident matcher for the latter, without a subject heuristic.
        assert!(policies("($array:tt) => { $array[0] };")
            .iter()
            .any(|p| p == "N3"));
    }
    /// Regression: different repetition iterations assembled an attribute that
    /// pruned a fixed read, while same-name capture identities hid the prefix.
    #[test]
    fn regression_repeated_capture_attribute_prefix() {
        for src in [
            "($($a:tt)*) => { pub fn visible() { $($a)* std::fs::read(\"x\").unwrap(); } }",
            "($($a:tt)+) => { pub fn visible() { $($a)+ std::fs::read(\"x\").unwrap(); } }",
            "($(($($a:tt)*))?) => { pub fn visible() { $($($a)*)? std::fs::read(\"x\").unwrap(); } }",
            "($($a:tt)?) => { $($a)? [allow(dead_code)] pub fn visible() {} }",
            "($($a:tt)*) => { # $($a)* }",
        ] {
            assert!(policies(src).iter().any(|p| p == "N3"), "{src}");
        }
        for src in [
            "($($a:tt),*) => { pub fn values() -> [u8; 2] { [$($a),*] } }",
            "($($a:tt)*) => { pub fn values() { $(let _ = $a;)* } }",
            r#"($($a:tt)*) => { pub fn values() -> String { format!("prefix {}", $($a)*) } }"#,
            "($($a:tt)*) => { $($a)* }",
            "($($a:tt)+) => { $($a)+ }",
            "($($a:tt)?) => { $($a)? }",
        ] {
            assert!(policies(src).is_empty(), "{src}");
        }
    }
    /// Regression: forwarding payloads concealed literal nested macro definitions.
    #[test]
    fn regression_literal_definitions_in_invocation_payloads() {
        for src in [
            "macro_rules! hidden { () => { #[cfg(windows)] pub fn read() {} }; } hidden!();",
            "mod nested { macro_rules! hidden { () => { #[cfg_attr(all(), cfg(windows))] pub fn read() {} }; } hidden!(); }",
            "forward! { macro_rules! hidden { ($attr:tt) => { # $attr pub fn read() {} }; } }",
        ] {
            let findings = audit_macro_payload(src).unwrap();
            assert!(findings.iter().any(|(policy, _)| policy == "N3"), "{src}");
        }
        for src in [
            "unsafe extern { fn payload_data(); }",
            "macro_rules! inner { (#[$attr:meta]) => { pub fn fine() {} }; }",
            "let text = \"macro_rules! hidden { () => { #[cfg(windows)] fn f() {} }; }\";",
        ] {
            assert!(audit_macro_payload(src).unwrap().is_empty(), "{src}");
        }
        assert!(audit_macro_payload(
            "macro_rules! ffi { () => { unsafe extern { fn arbitrary(); } }; }"
        )
        .unwrap()
        .iter()
        .any(|(policy, _)| policy == "N2"));
    }
    /// Regression: attributed vec! elements disappeared before Clippy linting.
    #[test]
    fn regression_stripping_attributes_in_invocation_payloads() {
        for source in [
            "#[cfg(not(clippy))] std::fs::read(\"x\")",
            "#[cfg_attr(clippy, cfg(any()))] std::fs::read(\"x\")",
            "nested!({ [#[r#cfg(all())] 1] })",
            "mod hidden { #![cfg_attr(false, allow(dead_code))] }",
            "#[cfg_attr(all(), cfg_attr(clippy, cfg(any())))] 1",
            "#[cfg(windows)] pub fn payload_data() {}",
        ] {
            for restricted in [false, true] {
                assert!(
                    audit_macro_payload_scoped(source, restricted)
                        .unwrap()
                        .iter()
                        .any(|(policy, detail)| policy == "N3"
                            && detail == "cfg/cfg_attr attribute in macro invocation payload"),
                    "{source}"
                );
            }
        }
        for source in [
            "#[allow(unused)] 1",
            "#[derive(Clone)] pub struct Visible;",
            "#[doc = \"#[cfg(not(clippy))]\"] pub fn visible() {}",
            "cfg!(windows)",
            "r###\"#[cfg(not(clippy))]\"###",
        ] {
            assert!(
                audit_macro_payload_scoped(source, true).unwrap().is_empty(),
                "{source}"
            );
        }
    }
    /// Regression: opaque payloads and transcribers hid unsupported definitions.
    #[test]
    fn regression_unsupported_macro_definition_payloads() {
        for source in [
            "pub macro hidden() {}",
            "nested! { #[cfg(any())] pub macro hidden() { unsafe extern { fn f(); } } }",
        ] {
            for restricted in [false, true] {
                assert!(
                    audit_macro_payload_scoped(source, restricted)
                        .unwrap()
                        .iter()
                        .any(|(policy, detail)| policy == "N3"
                            && detail == "unsupported macro definition grammar"),
                    "{source}"
                );
                let definition = format!("() => {{ {source} }};");
                assert!(
                    audit_macro_scoped(&definition, restricted)
                        .unwrap()
                        .iter()
                        .any(|(policy, detail)| policy == "N3"
                            && detail == "unsupported macro definition grammar"),
                    "{source}"
                );
            }
        }
    }
    #[test]
    fn regression_cfg_matcher_transcriber_raw_and_nested_macro() {
        for src in [
            "(#[cfg(unix)]) => {};",
            "(macro_rules! inner { () => { #[cfg(unix)] fn f() {} } }) => {};",
            "() => { #[r#cfg_attr(all(), allow(dead_code))] fn f() {} };",
            "() => { macro_rules! inner { () => { #[cfg(unix)] fn f() {} } } };",
        ] {
            assert!(policies(src).iter().any(|p| p == "N3"), "{src}");
        }
    }
    /// Regression: cfg! in a macro body yields a bool and removes no code.
    #[test]
    fn regression_cfg_macro_in_macro_rules_body_is_allowed() {
        for source in [
            "() => { pub fn platform() -> bool { cfg!(windows) } };",
            r#"() => { pub fn platform() -> String { format!("{}", cfg!(windows)) } };"#,
            "() => { macro_rules! inner { () => { cfg!(windows) }; } };",
        ] {
            assert!(policies(source).is_empty(), "{source}");
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

fn attribute_named(path: &syn::Path, name: &str) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == 1
        && path.segments[0].ident.to_string().trim_start_matches("r#") == name
}

fn lint_name(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|part| part.ident.to_string().trim_start_matches("r#").to_owned())
        .collect::<Vec<_>>()
        .join("::")
}

fn inventory_lint(path: &syn::Path) -> bool {
    matches!(
        lint_name(path).as_str(),
        "clippy::disallowed_methods" | "clippy::disallowed_types"
    )
}

fn meta_parts(tokens: TokenStream) -> Result<Vec<syn::Meta>, String> {
    use syn::{parse::Parser, punctuated::Punctuated, Token};
    Punctuated::<syn::Meta, Token![,]>::parse_terminated
        .parse2(tokens)
        .map(|parts| parts.into_iter().collect())
        .map_err(|error| error.to_string())
}

fn direct_expect(meta: &syn::Meta) -> Result<Option<(String, String)>, String> {
    use syn::{Expr, Lit};
    let syn::Meta::List(expect) = meta else {
        return Ok(None);
    };
    if !attribute_named(&expect.path, "expect") {
        return Ok(None);
    }
    let args = meta_parts(expect.tokens.clone())?;
    if !args
        .iter()
        .any(|arg| matches!(arg, syn::Meta::Path(path) if inventory_lint(path)))
    {
        return Ok(None);
    }
    if args.len() != 2 {
        return Err("disallowed lint requires direct expect with literal reason".into());
    }
    let syn::Meta::Path(lint) = &args[0] else {
        return Err("disallowed lint requires direct expect with literal reason".into());
    };
    if !inventory_lint(lint) {
        return Err("disallowed lint requires direct expect with literal reason".into());
    }
    let syn::Meta::NameValue(reason) = &args[1] else {
        return Err("disallowed lint requires direct expect with literal reason".into());
    };
    if !attribute_named(&reason.path, "reason") {
        return Err("disallowed lint requires direct expect with literal reason".into());
    }
    let Expr::Lit(syn::ExprLit {
        lit: Lit::Str(reason),
        ..
    }) = &reason.value
    else {
        return Err("disallowed lint requires direct expect with literal reason".into());
    };
    let lint = lint
        .segments
        .iter()
        .map(|part| part.ident.to_string().trim_start_matches("r#").to_owned())
        .collect::<Vec<_>>()
        .join("::");
    Ok(Some((lint, reason.value())))
}

/// Refuse source lint lowerings; Clippy continues to resolve every operation.
/// The reserved cfg is only an ordinary-build unfulfilled-expectation switch.
pub fn suppression_attribute(meta: &syn::Meta) -> Result<(), String> {
    suppression_attribute_with_lints(meta, &BTreeSet::new())
}

/// Refuse groups according to compiler-provided membership, without a spelling table.
pub fn suppression_attribute_with_lints(
    meta: &syn::Meta,
    protected_lints: &BTreeSet<String>,
) -> Result<(), String> {
    fn check(
        meta: &syn::Meta,
        conditional: bool,
        protected_lints: &BTreeSet<String>,
    ) -> Result<(), String> {
        let syn::Meta::List(list) = meta else {
            return Ok(());
        };
        if attribute_named(&list.path, "cfg_attr") {
            let parts = meta_parts(list.tokens.clone())
                .map_err(|_| "cfg_attr predicate or attributes could not be parsed".to_owned())?;
            for nested in parts.iter().skip(1) {
                check(nested, true, protected_lints)?;
            }
            return Ok(());
        }
        let lowering = attribute_named(&list.path, "allow") || attribute_named(&list.path, "warn");
        if !lowering && !attribute_named(&list.path, "expect") {
            return Ok(());
        }
        let parts = meta_parts(list.tokens.clone())?;
        if !parts.iter().any(|part| {
            matches!(part, syn::Meta::Path(path)
            if inventory_lint(path) || protected_lints.contains(&lint_name(path)))
        }) {
            return Ok(());
        }
        if conditional {
            return Err("cfg_attr-wrapped disallowed lint level is refused".into());
        }
        if lowering {
            return Err("allow/warn of disallowed lint is refused".into());
        }
        // A group expectation can hide several independent operations and
        // cannot be the required one-specific-lint approval protocol.
        if !parts
            .iter()
            .any(|part| matches!(part, syn::Meta::Path(path) if inventory_lint(path)))
        {
            return Err("disallowed lint requires direct expect with literal reason".into());
        }
        direct_expect(meta).map(|_| ())
    }
    check(meta, false, protected_lints)
}

fn dormant_expect_switch(meta: &syn::Meta) -> bool {
    let syn::Meta::List(list) = meta else {
        return false;
    };
    if !attribute_named(&list.path, "cfg_attr") {
        return false;
    }
    let Ok(parts) = meta_parts(list.tokens.clone()) else {
        return false;
    };
    let [syn::Meta::List(predicate), syn::Meta::List(level)] = parts.as_slice() else {
        return false;
    };
    attribute_named(&predicate.path, "not")
        && matches!(meta_parts(predicate.tokens.clone()).as_deref(), Ok([syn::Meta::Path(path)]) if attribute_named(path, "internal_read_inventory"))
        && attribute_named(&level.path, "allow")
        && matches!(meta_parts(level.tokens.clone()).as_deref(), Ok([syn::Meta::Path(path)]) if attribute_named(path, "unfulfilled_lint_expectations"))
}

/// Direct per-site approval metadata. This parses attributes, never operations.
pub fn inventory_attribute(meta: &syn::Meta) -> Result<Option<(String, String)>, String> {
    if contains_ident(quote_meta(meta), "internal_read_inventory") {
        return if dormant_expect_switch(meta) {
            Ok(None)
        } else {
            Err("reserved activation outside ordinary-build expectation switch".into())
        };
    }
    // Every protected-lint expectation enters manifest validation, including
    // inactive alternatives and ordinary journal reasons. Only explicit
    // reviewed manifest flags can exempt independent journal operations.
    direct_expect(meta)
}

fn quote_meta(meta: &syn::Meta) -> TokenStream {
    use quote::ToTokens;
    meta.to_token_stream()
}

/// Inspect only stripping attributes. Unrecognized cfg_attr grammar is a
/// refusal, never evidence that the attribute has no restricted predicate.
fn attribute_predicate(
    meta: &syn::Meta,
    predicate: fn(TokenStream) -> bool,
) -> Result<bool, String> {
    use syn::{parse::Parser, punctuated::Punctuated, Token};
    let syn::Meta::List(list) = meta else {
        return Ok(false);
    };
    let name = list
        .path
        .segments
        .last()
        .map(|s| s.ident.to_string().trim_start_matches("r#").to_owned())
        .unwrap_or_default();
    match name.as_str() {
        "cfg" => Ok(predicate(list.tokens.clone())),
        "cfg_attr" => {
            let parts = Punctuated::<syn::Meta, Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .map_err(|_| "cfg_attr predicate or attributes could not be parsed".to_owned())?;
            let mut parts = parts.iter();
            let first = parts
                .next()
                .ok_or_else(|| "cfg_attr predicate or attributes could not be parsed".to_owned())?;
            let mut found = predicate(quote_meta(first));
            for attribute in parts {
                found |= attribute_predicate(attribute, predicate)?;
            }
            Ok(found)
        }
        _ => Ok(false),
    }
}

/// Find target predicates in cfg/cfg_attr grammar only. A nested ordinary
/// attribute named target_feature is not itself a cfg predicate.
pub fn target_attribute(meta: &syn::Meta) -> Result<bool, String> {
    attribute_predicate(meta, target_predicate)
}

/// Clippy-specific stripping cannot be exempted by a reviewed target file:
/// it prevents the native lint from observing the item on every operating system.
pub fn clippy_attribute(meta: &syn::Meta) -> Result<bool, String> {
    attribute_predicate(meta, |tokens| contains_ident(tokens, "clippy"))
}

#[cfg(test)]
mod cfg_attribute_tests {
    use super::*;
    #[test]
    fn regression_target_attribute_names_are_not_predicates() {
        let ordinary: syn::Meta =
            syn::parse_str(r#"cfg_attr(feature="simd",target_feature(enable="sse2"))"#).unwrap();
        assert!(!target_attribute(&ordinary).unwrap());
        for source in [
            r#"cfg_attr(unix, target_feature(enable="sse2"))"#,
            r#"cfg_attr(all(),cfg_attr(all(),cfg(not(windows))))"#,
        ] {
            assert!(target_attribute(&syn::parse_str(source).unwrap()).unwrap());
        }
    }
    /// Regression: a syn parse failure previously hid stable boolean cfg_attr.
    #[test]
    fn regression_cfg_attr_parse_failure_is_refused() {
        for source in [
            "cfg_attr(true, cfg(windows))",
            "cfg_attr(false, cfg(windows))",
            "cfg_attr(true, cfg(not(clippy)))",
            "cfg_attr(all(), cfg_attr(true, cfg(windows)))",
            "cfg_attr()",
        ] {
            let meta = syn::parse_str(source).unwrap();
            assert!(target_attribute(&meta).is_err(), "{source}");
            assert!(clippy_attribute(&meta).is_err(), "{source}");
        }
    }
    /// Regression: Clippy-specific cfg strips code on every native runner.
    #[test]
    fn regression_clippy_stripping_predicates() {
        for source in [
            "cfg(clippy)",
            "cfg(not(clippy))",
            "cfg_attr(not(clippy), cfg(windows))",
            "cfg_attr(all(), cfg_attr(all(), cfg(not(clippy))))",
        ] {
            assert!(
                clippy_attribute(&syn::parse_str(source).unwrap()).unwrap(),
                "{source}"
            );
        }
        for source in [
            r#"cfg(feature="clippy")"#,
            "cfg_attr(all(), allow(clippy::style))",
        ] {
            assert!(
                !clippy_attribute(&syn::parse_str(source).unwrap()).unwrap(),
                "{source}"
            );
        }
    }
}

#[cfg(test)]
mod expectation_attribute_tests {
    use super::*;

    /// Regression: approvals are direct attributes, without conditional activation.
    #[test]
    fn regression_direct_expect_protocol() {
        let direct = r#"expect(clippy::disallowed_methods, reason="internal-read:v1 {}")"#;
        assert_eq!(
            inventory_attribute(&syn::parse_str(direct).unwrap()).unwrap(),
            Some((
                "clippy::disallowed_methods".into(),
                "internal-read:v1 {}".into()
            ))
        );
        for source in [
            r#"cfg_attr(internal_read_inventory, expect(clippy::disallowed_methods, reason="internal-read:v1 {}"))"#,
            "cfg(internal_read_inventory)",
            "cfg(r#internal_read_inventory)",
        ] {
            assert!(
                inventory_attribute(&syn::parse_str(source).unwrap()).is_err(),
                "{source}"
            );
        }
        assert!(inventory_attribute(
            &syn::parse_str(
                "cfg_attr(not(internal_read_inventory), allow(unfulfilled_lint_expectations))"
            )
            .unwrap()
        )
        .unwrap()
        .is_none());
    }

    /// Regression: reason text cannot discard an inactive protected expectation.
    #[test]
    fn regression_all_protected_reasons_require_manifest_review() {
        for lint in ["disallowed_methods", "disallowed_types"] {
            for reason in [
                "Reviewed independent journal operation",
                "ordinary review",
                "",
            ] {
                let source = format!("expect(clippy::{lint}, reason={reason:?})");
                assert_eq!(
                    inventory_attribute(&syn::parse_str(&source).unwrap()).unwrap(),
                    Some((format!("clippy::{lint}"), reason.to_owned()))
                );
            }
        }
    }

    /// Regression: -D must not be lowered through local lint-level attributes.
    #[test]
    fn regression_disallowed_lint_suppressions_are_refused() {
        for source in [
            "allow(clippy::disallowed_methods)",
            "allow(dead_code, clippy::disallowed_types)",
            "warn(clippy::disallowed_methods)",
            r#"cfg_attr(all(), expect(clippy::disallowed_methods, reason="review"))"#,
            "cfg_attr(all(), warn(clippy::disallowed_methods))",
            "cfg_attr(all(), allow(clippy::disallowed_methods))",
            r#"cfg_attr(all(), cfg_attr(all(), expect(clippy::disallowed_types, reason="review")))"#,
            r#"cfg_attr(false, expect(clippy::disallowed_methods, reason="review"))"#,
            "expect(clippy::disallowed_methods)",
            r#"expect(clippy::disallowed_methods, clippy::disallowed_types, reason="review")"#,
            "expect(clippy::disallowed_methods, reason=concat!(\"review\"))",
        ] {
            assert!(
                suppression_attribute(&syn::parse_str(source).unwrap()).is_err(),
                "{source}"
            );
        }
        for source in [
            r#"expect(clippy::disallowed_methods, reason="review")"#,
            r#"expect(clippy::disallowed_types, reason="review")"#,
            "allow(clippy::needless_return)",
            "deny(clippy::disallowed_methods)",
            "forbid(clippy::disallowed_methods)",
            "cfg_attr(all(), allow(dead_code))",
            "cfg_attr(not(internal_read_inventory), allow(unfulfilled_lint_expectations))",
        ] {
            assert!(
                suppression_attribute(&syn::parse_str(source).unwrap()).is_ok(),
                "{source}"
            );
        }
    }

    /// Regression: group membership comes from the compiler, not a fixed table.
    #[test]
    fn regression_compiler_provided_lint_groups_cannot_lower_inventory() {
        let protected = BTreeSet::from(["synthetic::approved_group".to_owned()]);
        for source in [
            "allow(synthetic::approved_group)",
            "warn(synthetic::approved_group)",
            r#"expect(synthetic::approved_group, reason="review")"#,
            r#"cfg_attr(all(), expect(synthetic::approved_group, reason="review"))"#,
        ] {
            let meta = syn::parse_str(source).unwrap();
            assert!(suppression_attribute(&meta).is_ok(), "{source}");
            assert!(
                suppression_attribute_with_lints(&meta, &protected).is_err(),
                "{source}"
            );
        }
        for source in [
            "allow(synthetic::unrelated)",
            r#"expect(synthetic::unrelated, reason="review")"#,
            r#"expect(clippy::disallowed_methods, reason="review")"#,
        ] {
            assert!(
                suppression_attribute_with_lints(&syn::parse_str(source).unwrap(), &protected)
                    .is_ok(),
                "{source}"
            );
        }
        let body = "() => { #[allow(synthetic::approved_group)] pub fn load() {} };";
        assert!(audit_macro_scoped(body, true).unwrap().is_empty());
        assert!(audit_macro_with_lints(body, true, &protected)
            .unwrap()
            .iter()
            .any(|(policy, _)| policy == "EXPECT"));
        assert!(audit_macro_with_lints(body, false, &protected)
            .unwrap()
            .is_empty());
        let payload = format!("macro_rules! load {{ {body} }}");
        assert!(audit_macro_payload_with_lints(&payload, true, &protected)
            .unwrap()
            .iter()
            .any(|(policy, _)| policy == "EXPECT"));
    }

    /// Regression: a literal transcriber allow must not lower native -D either.
    #[test]
    fn regression_macro_suppression_refusal_keeps_package_scope() {
        let body = "() => { #[allow(clippy::disallowed_methods)] pub fn load() {} };";
        assert!(audit_macro(body).unwrap().is_empty());
        assert!(audit_macro_scoped(body, true)
            .unwrap()
            .iter()
            .any(|(policy, detail)| policy == "EXPECT"
                && detail == "allow/warn of disallowed lint is refused"));
        let payload = format!("macro_rules! load {{ {body} }}");
        assert!(audit_macro_payload_scoped(&payload, true)
            .unwrap()
            .iter()
            .any(|(policy, _)| policy == "EXPECT"));
        assert!(audit_macro_payload_scoped(&payload, false)
            .unwrap()
            .is_empty());
    }
}
