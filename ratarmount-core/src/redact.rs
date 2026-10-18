//! Credential redaction for base URLs that are stored or printed.

/// Remote schemes whose userinfo, query and fragment may carry credentials.
/// Kept in sync with `ratarmount_remote::REMOTE_SCHEMES` by a test there.
pub const REDACTED_SCHEMES: &[&str] = &[
    "http", "https", "ftp", "ftps", "s3", "gs", "az", "azure", "ssh", "sftp", "scp", "smb",
    "webdav", "webdavs", "dropbox", "ipfs", "ipns", "oci", "docker", "ghcr", "hf", "magnet",
];

/// Schemes left unchanged: local paths, or formats where `user@` and `?` are
/// path syntax rather than credentials.
pub const UNREDACTED_SCHEMES: &[&str] = &["file", "hf-cache", "rclone", "restic", "torrent"];

/// Strip credentials from a base URL before it is stored or printed.
///
/// Remote schemes lose userinfo, query and fragment; a magnet URI keeps only
/// `xt` and `dn`. Everything else (local paths, `git:///…?copy.git#HEAD`,
/// `file://`) is returned unchanged.
pub fn redact_base_url(input: &str) -> String {
    if input
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("magnet:"))
    {
        return redact_magnet(input);
    }
    let Some((scheme, rest)) = input.split_once("://") else {
        return input.to_owned();
    };
    let lower = scheme.to_ascii_lowercase();
    if !REDACTED_SCHEMES.contains(&lower.as_str()) {
        return input.to_owned();
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    format!("{scheme}://{host}{}", &tail[..path_end])
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
}
