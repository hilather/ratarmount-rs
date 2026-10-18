//! Credential redaction for base URLs that are stored or printed.
//!
//! What is covered, by input form:
//!
//! | Form | Redacted |
//! |------|----------|
//! | `http(s)`, `ftp(s)`, `s3`, `gs`, `az`, `ssh`, `sftp`, `scp`, `smb`, `webdav(s)`, `dropbox`, `ipfs`, `ipns`, `oci`, `docker`, `ghcr`, `hf`, `torrent`, and tracker `udp`/`ws`/`wss` URLs | userinfo, query, fragment; a tracker `announce`/`scrape` path segment drops the path before it (`/PASSKEY/announce` becomes `/announce`) |
//! | `magnet:?…` | everything but `xt` and `dn` (trackers, `xs`, `as`, `x.pe`) |
//! | `rclone://…`, `rclone+…` | `user:pass@` userinfo; in a connection string (`:sftp,host=h,pass=X:/p` or `remote,token=X:/p`) every parameter whose name contains `pass`, `secret`, `token`, `key`, `auth`, `cred`, `sas`, `sig`, `private` or `session` |
//! | `restic:…` | a nested `scheme://` URL (`restic:rest:https://u:p@h/`, `restic://s3://b/r`) as above; `sftp:user@host:/path` and `rest:`/`b2:`/`azure:`/`gs:`/`swift:` forms lose `user@` |
//! | `file://`, `hf-cache://`, local paths, `git:///…?copy.git#HEAD` | unchanged |
//!
//! Known limit: userinfo holding `/`, `?` or `#` is stripped only when the
//! text before the first `/?#` is not a valid `host[:port]` (a non-numeric
//! port) or the authority ends at `?`/`#`. `http://user/x@host/` is read as host
//! `user`, path `/x@host/`, as RFC 3986 does.

/// Remote schemes redacted by [`redact_base_url`]: userinfo, query and fragment
/// for URL schemes, and the special `rclone` and `restic` forms above.
/// Kept in sync with `ratarmount_remote::REMOTE_SCHEMES` by a test there.
pub const REDACTED_SCHEMES: &[&str] = &[
    "http", "https", "ftp", "ftps", "s3", "gs", "az", "azure", "ssh", "sftp", "scp", "smb",
    "webdav", "webdavs", "dropbox", "ipfs", "ipns", "oci", "docker", "ghcr", "hf", "magnet",
    "rclone", "restic", "torrent",
];

/// Schemes left unchanged: local paths, or formats where `user@` and `?` are
/// path syntax rather than credentials.
pub const UNREDACTED_SCHEMES: &[&str] = &["file", "hf-cache"];

/// Tracker and websocket schemes that are not inbound remotes but can appear
/// in text (a magnet's `tr=` once decoded, a library error) with a passkey.
const TRACKER_SCHEMES: &[&str] = &["udp", "ws", "wss"];

/// Strip credentials from a base URL before it is stored or printed.
///
/// Remote schemes lose userinfo, query and fragment; a magnet URI keeps only
/// `xt` and `dn`; `rclone` and `restic` forms lose inline credentials (module
/// docs). Everything else (local paths, `git:///…?copy.git#HEAD`, `file://`)
/// is returned unchanged.
pub fn redact_base_url(input: &str) -> String {
    if starts_with_ci(input, "magnet:") {
        return redact_magnet(input);
    }
    if starts_with_ci(input, "rclone+") {
        let (prefix, rest) = input.split_at(7);
        return format!("{prefix}{}", redact_rclone_spec(rest));
    }
    if starts_with_ci(input, "restic:") {
        return redact_restic(input);
    }
    let Some((scheme, rest)) = input.split_once("://") else {
        return input.to_owned();
    };
    let lower = scheme.to_ascii_lowercase();
    if lower == "rclone" {
        return format!("{scheme}://{}", redact_rclone_spec(rest));
    }
    if !REDACTED_SCHEMES.contains(&lower.as_str()) && !TRACKER_SCHEMES.contains(&lower.as_str()) {
        return input.to_owned();
    }
    let (host, tail) = split_authority(rest);
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let path = tracker_path(&tail[..path_end]);
    format!("{scheme}://{host}{path}")
}

fn starts_with_ci(input: &str, prefix: &str) -> bool {
    input
        .get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

/// Split `rest` (after `scheme://`) into the host and everything after it,
/// dropping userinfo. The RFC authority ends at the first `/?#`; userinfo that
/// itself contains one of those leaves a non-numeric "port" or an authority
/// cut short by `?`/`#`, and then the last `@` ends the userinfo.
fn split_authority(rest: &str) -> (&str, &str) {
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if let Some((_, host)) = authority.rsplit_once('@') {
        return (host, &rest[end..]);
    }
    let bogus_port = !authority.starts_with('[')
        && authority
            .rsplit_once(':')
            .is_some_and(|(_, port)| !port.is_empty() && !port.bytes().all(|b| b.is_ascii_digit()));
    let cut_short = rest[end..].starts_with(['?', '#']);
    if bogus_port || cut_short {
        if let Some(at) = rest.rfind('@') {
            let after = &rest[at + 1..];
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            return after.split_at(end);
        }
    }
    rest.split_at(end)
}

/// A tracker URL carries its passkey in the path (`/PASSKEY/announce`,
/// `/announce/PASSKEY`): keep only the `announce`/`scrape` segment.
fn tracker_path(path: &str) -> String {
    path.split('/')
        .find(|seg| seg.eq_ignore_ascii_case("announce") || seg.eq_ignore_ascii_case("scrape"))
        .map_or_else(|| path.to_owned(), |seg| format!("/{seg}"))
}

fn sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "pass", "secret", "token", "key", "auth", "cred", "sas", "sig", "private", "session",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

/// `remote:path`, `remote/path`, `user:pass@host/path` or a connection string
/// (`:backend,k=v,…:path`, `remote,k=v:path`) after `rclone://` / `rclone+`.
fn redact_rclone_spec(rest: &str) -> String {
    let (lead, body) = rest.strip_prefix(':').map_or(("", rest), |b| (":", b));
    let mut quote = None;
    let mut span_end = body.len();
    for (i, c) in body.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, ':') => {
                span_end = i;
                break;
            }
            _ => {}
        }
    }
    let (span, tail) = body.split_at(span_end);
    let Some((name, params)) = span.split_once(',') else {
        if lead.is_empty() {
            // `user:pass@host/path`: userinfo is before the first `/`.
            let segment_end = rest.find('/').unwrap_or(rest.len());
            if let Some(at) = rest[..segment_end].rfind('@') {
                return rest[at + 1..].to_owned();
            }
        }
        return rest.to_owned();
    };
    let mut kept = vec![name.to_owned()];
    let mut quote = None;
    let mut start = 0;
    let mut pieces = Vec::new();
    for (i, c) in params.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, ',') => {
                pieces.push(&params[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    pieces.push(&params[start..]);
    for piece in pieces {
        let key = piece.split('=').next().unwrap_or("");
        if !sensitive_key(key) {
            kept.push(piece.to_owned());
        }
    }
    format!("{lead}{}{tail}", kept.join(","))
}

/// `restic:` followed by a path, a nested `scheme://` URL, or a
/// `scheme:user@host:/path` backend spec.
fn redact_restic(input: &str) -> String {
    let (prefix, rest) = input.split_at(7);
    let body = rest.trim_start_matches('/');
    let (slashes, _) = rest.split_at(rest.len() - body.len());
    if let Some(at) = body.find("://") {
        let start = body[..at]
            .char_indices()
            .rev()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |(i, c)| i + c.len_utf8());
        let (head, url) = body.split_at(start);
        return format!("{prefix}{slashes}{head}{}", redact_base_url(url));
    }
    if let Some((scheme, tail)) = body.split_once(':') {
        let known = ["sftp", "rest", "b2", "azure", "gs", "swift"];
        if known.contains(&scheme.to_ascii_lowercase().as_str()) {
            let segment_end = tail.find('/').unwrap_or(tail.len());
            if let Some(at) = tail[..segment_end].rfind('@') {
                return format!("{prefix}{slashes}{scheme}:{}", &tail[at + 1..]);
            }
        }
    }
    input.to_owned()
}

/// [`redact_base_url`] applied to every URL-looking token (`scheme://…` or
/// `magnet:?…`) inside free-form text such as an error message, so a URL that
/// a library rewrote (`webdav://` to `http://`) or echoed with extra context is
/// redacted even though it no longer equals the base the user typed.
pub fn redact_urls_in_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        // The next token start: a scheme (letters, digits, `+-.`) before `://`,
        // or `magnet:`.
        let hit = rest
            .match_indices("://")
            .map(|(at, _)| {
                rest[..at]
                    .char_indices()
                    .rev()
                    .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
                    .map_or(0, |(i, c)| i + c.len_utf8())
            })
            .next();
        let lowered = rest.to_ascii_lowercase();
        let special = ["magnet:?", "rclone+", "restic:"]
            .iter()
            .filter_map(|needle| lowered.find(needle))
            .min();
        let start = match (hit, special) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => break,
        };
        out.push_str(&rest[..start]);
        let token = &rest[start..];
        let end = token_end(token);
        // Trailing sentence punctuation is not part of the URL.
        let url = token[..end].trim_end_matches(['.', ',', ';', ':', ')', ']', '}']);
        out.push_str(&redact_base_url(url));
        out.push_str(&token[url.len()..end]);
        rest = &token[end..];
    }
    out.push_str(rest);
    out
}

/// End of the URL-looking token at the start of `token`. A rclone connection
/// string may carry a quoted parameter value (`token='a b'`) that holds quotes,
/// whitespace and delimiters, so for those the end is found outside any quote
/// that opens right after `=`.
fn token_end(token: &str) -> usize {
    let ends = |c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`');
    let rclone = starts_with_ci(token, "rclone");
    let mut quote = None;
    let mut previous = ' ';
    let mut chars = token.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    // A doubled quote is an escaped quote and the value goes on
                    // (<https://rclone.org/docs/#connection-strings>).
                    if chars.peek().is_some_and(|&(_, next)| next == q) {
                        chars.next();
                    } else {
                        quote = None;
                    }
                }
            }
            None if rclone && previous == '=' && matches!(c, '"' | '\'') => quote = Some(c),
            None if ends(c) => return i,
            None => {}
        }
        previous = c;
    }
    token.len()
}

/// [`redact_base_url`] for a path label that may be a remote URL (progress lines).
pub fn redacted_display(path: &std::path::Path) -> String {
    redact_base_url(&path.to_string_lossy())
}

fn redact_magnet(input: &str) -> String {
    let Some((_, query)) = input.split_once('?') else {
        return "magnet:".to_owned();
    };
    let query = query.split('#').next().unwrap_or("");
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let key = pair.split('=').next().unwrap_or("");
            key == "xt" || key == "dn"
        })
        .collect();
    format!("magnet:?{}", kept.join("&"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: an error naming a rewritten URL leaked its token.
    #[test]
    fn regression_redact_urls_in_text() {
        let cases = [
            (
                "error: webdav: http://127.0.0.1:1/f.tar?token=SECRET: status code 403",
                "error: webdav: http://127.0.0.1:1/f.tar: status code 403",
            ),
            (
                "GET \"https://u:p@h/b?X-Amz-Signature=abc\" failed.",
                "GET \"https://h/b\" failed.",
            ),
            (
                "see s3://bkt/k?sig=1, and ftp://u:p@h/x.",
                "see s3://bkt/k, and ftp://h/x.",
            ),
            ("no urls here: a/b?c", "no urls here: a/b?c"),
            ("file:///a/b?c#d stays", "file:///a/b?c#d stays"),
            (
                "magnet:?xt=urn:btih:H&tr=http://t/x%3Fp%3Ds",
                "magnet:?xt=urn:btih:H",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(redact_urls_in_text(input), want, "input {input}");
        }
    }

    /// Regression (R4-S10): a doubled quote is an escaped quote in an rclone
    /// connection string, so `pass='prefix''SECRET'` ended the token early and
    /// left `'SECRET'` in the logged text.
    #[test]
    fn regression_redact_rclone_doubled_quotes() {
        for (input, want) in [
            ("rclone+remote,pass='prefix''SECRET':p", "rclone+remote:p"),
            (
                "rclone+remote,pass=\"prefix\"\"SECRET\":p",
                "rclone+remote:p",
            ),
            (
                "failed: rclone+remote,pass='a'',b''c',x=1:p, retry",
                "failed: rclone+remote,x=1:p, retry",
            ),
            (
                "open rclone://:s3,secret_access_key='it''s S 3',region=eu:bkt/k now",
                "open rclone://:s3,region=eu:bkt/k now",
            ),
        ] {
            assert_eq!(redact_urls_in_text(input), want, "text {input}");
        }
        for (input, want) in [
            ("rclone+remote,pass='prefix''SECRET':p", "rclone+remote:p"),
            (
                "rclone+remote,pass=\"prefix\"\"SECRET\":p",
                "rclone+remote:p",
            ),
            ("rclone+remote,pass='a'',b''c',x=1:p", "rclone+remote,x=1:p"),
        ] {
            assert_eq!(redact_base_url(input), want, "url {input}");
        }
    }

    /// Regression (R4-S4): the text scanner ended an rclone token at the first
    /// quote, so `token='SECRET'` left the secret in logged error text.
    #[test]
    fn regression_redact_quoted_rclone_values() {
        for (input, want) in [
            ("rclone+remote,token='SECRET':p", "rclone+remote:p"),
            ("rclone+remote,token=\"SECRET\":p", "rclone+remote:p"),
            (
                "failed: rclone+remote,token='a b\"c':p, retry",
                "failed: rclone+remote:p, retry",
            ),
            (
                "open rclone://:s3,secret_access_key='S 3',region=eu:bkt/k now",
                "open rclone://:s3,region=eu:bkt/k now",
            ),
            (
                "open 'rclone+remote:bkt/k' now",
                "open 'rclone+remote:bkt/k' now",
            ),
        ] {
            assert_eq!(redact_urls_in_text(input), want, "text {input}");
            assert!(!redact_urls_in_text(input).contains("SECRET"));
        }
        assert_eq!(
            redact_base_url("rclone+remote,token='SECRET':p"),
            "rclone+remote:p"
        );
        assert_eq!(
            redact_base_url("rclone+remote,token=\"SECRET\":p"),
            "rclone+remote:p"
        );
    }

    #[test]
    fn regression_redact_base_url() {
        let cases = [
            (
                "magnet:?xt=urn:btih:HASH&dn=n&tr=http://t/announce%3Fpasskey%3Dsecret&xs=http://u:p@h/x",
                "magnet:?xt=urn:btih:HASH&dn=n",
            ),
            (
                "hf://datasets/a/b@main/snapshot.tar",
                "hf://datasets/a/b@main/snapshot.tar",
            ),
            (
                "http://user:s3cr3t@h/b.tar?X-Amz-Signature=deadbeef&X-Amz-Credential=AKIA#frag",
                "http://h/b.tar",
            ),
            ("s3://bkt/k.tar?X-Amz-Security-Token=tok", "s3://bkt/k.tar"),
            ("ftp://u:p@h/x", "ftp://h/x"),
            ("az://acct/c/b?sig=abc&se=1", "az://acct/c/b"),
            ("ssh://user@host/x", "ssh://host/x"),
            ("https://h/b.tar?versionId=3", "https://h/b.tar"),
            ("https://u:p@h?x=1", "https://h"),
            ("git:///srv/r.git#v1", "git:///srv/r.git#v1"),
            ("git:///srv/repo?copy.git#HEAD", "git:///srv/repo?copy.git#HEAD"),
            ("file:///a/b?c#d", "file:///a/b?c#d"),
            ("/local/path?x", "/local/path?x"),
            ("repo@rev", "repo@rev"),
            ("HTTP://U:P@H/x?q=1", "HTTP://H/x"),
        ];
        for (input, want) in cases {
            let got = redact_base_url(input);
            assert_eq!(got, want, "input {input}");
            for secret in ["s3cr3t", "deadbeef", "passkey", "tok", "sig=", "u:p"] {
                assert!(!got.contains(secret) || input.starts_with("git:"), "{got}");
            }
        }
    }

    /// Regression: rclone, restic and torrent inputs were passed through
    /// unredacted (`UNREDACTED_SCHEMES`), so inline credentials and tracker
    /// passkeys were stored and printed.
    #[test]
    fn regression_redact_rclone_restic_torrent() {
        let cases = [
            ("rclone://user:pw0rd@host/path", "rclone://host/path"),
            ("rclone://gdrive:bucket/path", "rclone://gdrive:bucket/path"),
            ("rclone://gdrive/path", "rclone://gdrive/path"),
            ("rclone://gdrive:a/b@c.txt", "rclone://gdrive:a/b@c.txt"),
            (
                "rclone://:sftp,host=h,user=bob,pass=SECRET1:/srv/x",
                "rclone://:sftp,host=h,user=bob:/srv/x",
            ),
            (
                "rclone+:s3,access_key_id=AKIA,secret_access_key=SECRET2,region=eu:bkt/k",
                "rclone+:s3,region=eu:bkt/k",
            ),
            (
                "rclone+remote,token='{\"a\":\"b:c,d\"}',x=1:p",
                "rclone+remote,x=1:p",
            ),
            ("rclone+gdrive:bucket/path", "rclone+gdrive:bucket/path"),
            ("RCLONE+gdrive://bucket/path", "RCLONE+gdrive://bucket/path"),
            (
                "restic:rest:https://admin:SECRET3@h:8000/repo?x=1",
                "restic:rest:https://h:8000/repo",
            ),
            (
                "restic://s3://bucket/repo?X-Amz-Signature=SECRET4",
                "restic://s3://bucket/repo",
            ),
            (
                "restic:sftp:backup@host:/srv/restic",
                "restic:sftp:host:/srv/restic",
            ),
            ("restic:/var/backup/a@b/repo", "restic:/var/backup/a@b/repo"),
            ("restic:///var/backup/repo", "restic:///var/backup/repo"),
            (
                "torrent://user:pw@tracker/x.torrent?passkey=SECRET5",
                "torrent://tracker/x.torrent",
            ),
            (
                "https://u:p@h/files/x.torrent?passkey=SECRET6",
                "https://h/files/x.torrent",
            ),
            (
                "https://tracker.example/SECRET7/announce?x=1",
                "https://tracker.example/announce",
            ),
            (
                "http://tracker.example/announce/SECRET8",
                "http://tracker.example/announce",
            ),
            (
                "udp://t:6969/announce?passkey=SECRET9",
                "udp://t:6969/announce",
            ),
            (
                "https://h/data/announce-notes.tar",
                "https://h/data/announce-notes.tar",
            ),
            ("x.torrent", "x.torrent"),
        ];
        for (input, want) in cases {
            let got = redact_base_url(input);
            assert_eq!(got, want, "input {input}");
            assert!(!got.contains("SECRET") && !got.contains("pw0rd"), "{got}");
        }
        // The same tokens inside an error message.
        assert_eq!(
            redact_urls_in_text(
                "open restic:rest:https://a:SECRET@h/r failed; rclone+:sftp,pass=SECRET:/x."
            ),
            "open restic:rest:https://h/r failed; rclone+:sftp:/x."
        );
        assert_eq!(
            redact_urls_in_text("restic: no repo found"),
            "restic: no repo found"
        );
    }

    /// Regression: userinfo containing `/`, `?` or `#` ended the authority
    /// early, so the password (and the `@`) stayed in the printed URL.
    #[test]
    fn regression_redact_userinfo_with_delimiters() {
        let cases = [
            ("http://user:pa/ss?w#rd@host/x", "http://host/x"),
            ("http://user:pa?ss@host/x?q=1", "http://host/x"),
            ("http://user:pa#ss@host/x", "http://host/x"),
            ("https://tok#en@host:8443/a/b", "https://host:8443/a/b"),
            ("ftp://u:p/q/r@h", "ftp://h"),
            ("http://üser:pä/ss?w#rd@hóst/x", "http://hóst/x"),
            ("http://日本:語/語?語#語@ホスト/y", "http://ホスト/y"),
            // Normal URLs stay as they were.
            ("http://h:8080/p@q/r?k=v", "http://h:8080/p@q/r"),
            ("https://h/@scope/pkg", "https://h/@scope/pkg"),
            (
                "hf://datasets/a/b@main/f.tar",
                "hf://datasets/a/b@main/f.tar",
            ),
            ("https://[::1]:80/a@b", "https://[::1]:80/a@b"),
            (
                "oci://reg:5000/repo@sha256:abc",
                "oci://reg:5000/repo@sha256:abc",
            ),
            ("https://h/x?e=a@b.c", "https://h/x"),
        ];
        for (input, want) in cases {
            assert_eq!(redact_base_url(input), want, "input {input}");
        }
    }

    /// Regression: `/tmp/éhttps://missing.tar` made the token scanner add one
    /// to the byte offset of the two-byte `é` and slice inside it (panic).
    #[test]
    fn regression_redact_urls_in_text_multibyte() {
        assert_eq!(
            redact_urls_in_text("/tmp/éhttps://missing.tar"),
            "/tmp/éhttps://missing.tar"
        );
        assert_eq!(
            redact_urls_in_text("файл→http://u:p@h/x?token=abc, 日本語ftp://h/y?k=v"),
            "файл→http://h/x, 日本語ftp://h/y"
        );
        for input in ["é://", "😀://x", "a😀magnet:?xt=1&tr=s", "ééé", "://é"] {
            let _ = redact_urls_in_text(input);
        }
    }
}
