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
            if transcriber
                && is_ident(token, "macro_rules")
                && matches!(tokens.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!')
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

/// Audit one compiler-observed `macro_rules!` body. N2 findings remain pending
/// until the adapter applies the single exact compiler-module exception.
pub fn audit_macro(source: &str) -> Result<Vec<(String, String)>, String> {
    let tokens = source.parse::<TokenStream>().map_err(|e| e.to_string())?;
    let mut audit = Audit::default();
    audit.macro_rules(tokens, &Default::default());
    Ok(audit
        .findings
        .into_iter()
        .map(|(_, policy, detail)| (policy, detail))
        .collect())
}

/// Audit literal nested definitions in a compiler-observed invocation payload.
/// Other payload tokens are data: only discovered `macro_rules!` definitions
/// enter the N2/N3 grammar audit, with their own matcher/transcriber boundaries.
pub fn audit_macro_payload(source: &str) -> Result<Vec<(String, String)>, String> {
    let tokens = source.parse::<TokenStream>().map_err(|e| e.to_string())?;
    let mut audit = Audit::default();
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
            "#[cfg(windows)] pub fn payload_data() {}",
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
