//! Scheme-prefix parser for `restic:` URLs (not WHATWG).

use std::path::PathBuf;

use crate::{ResticError, Result};

const S3_RESIDUAL: &str = "S3 restic repos residual; use a local cache copy";

/// Strip a case-insensitive `restic:` prefix.
pub fn strip_restic_scheme(input: &str) -> Result<&str> {
    if input.len() >= 7 && input[..7].eq_ignore_ascii_case("restic:") {
        Ok(&input[7..])
    } else {
        Err(ResticError::Msg(format!(
            "not a restic URL (expected restic:/abs/path): {input}"
        )))
    }
}

/// Parse `restic:` input into a local absolute repository path.
///
/// | Input | Result |
/// |-------|--------|
/// | `restic:/var/backup/repo` | `/var/backup/repo` |
/// | `restic:///var/backup/repo` | extra slashes tolerated |
/// | `restic:relative/path` | error (absolute path required) |
/// | `restic://s3://bucket/repo` | S3 residual error |
/// | `restic:s3://bucket/repo` | S3 residual error |
pub fn parse_restic_url(input: &str) -> Result<PathBuf> {
    let rest = strip_restic_scheme(input)?;
    if rest.is_empty() {
        return Err(ResticError::Msg(
            "restic URL requires an absolute local path".into(),
        ));
    }

    let trimmed = rest.trim_start_matches('/');
    if is_s3_remainder(trimmed) {
        return Err(ResticError::Msg(S3_RESIDUAL.into()));
    }
    if looks_like_remote_remainder(trimmed) {
        return Err(ResticError::Msg(format!(
            "{S3_RESIDUAL} (remote restic backends are residual)"
        )));
    }

    if !rest.starts_with('/') {
        return Err(ResticError::Msg(
            "restic URL requires an absolute local path (restic:/abs/path)".into(),
        ));
    }
    // `restic:///var/...` → `///var/...` → `/var/...`
    let path = format!("/{}", rest.trim_start_matches('/'));
    if path == "/" {
        return Err(ResticError::Msg(
            "restic URL requires an absolute local path".into(),
        ));
    }
    Ok(PathBuf::from(path))
}

fn is_s3_remainder(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("s3://") || lower.starts_with("s3:")
}

fn looks_like_remote_remainder(s: &str) -> bool {
    let Some((scheme, _)) = s.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_restic_url_table() {
        assert_eq!(
            parse_restic_url("restic:/var/backup/repo").unwrap(),
            PathBuf::from("/var/backup/repo")
        );
        assert_eq!(
            parse_restic_url("restic:///var/backup/repo").unwrap(),
            PathBuf::from("/var/backup/repo")
        );
        assert_eq!(
            parse_restic_url("RESTIC:/tmp/repo").unwrap(),
            PathBuf::from("/tmp/repo")
        );

        let rel = parse_restic_url("restic:relative/path")
            .unwrap_err()
            .to_string();
        assert!(
            rel.contains("absolute"),
            "relative path must error, got {rel}"
        );

        for s3 in [
            "restic://s3://bucket/repo",
            "restic:s3://bucket/repo",
            "restic:///s3://bucket/repo",
        ] {
            let err = parse_restic_url(s3).unwrap_err().to_string();
            assert!(
                err.contains("S3 restic repos residual"),
                "{s3} must be S3 residual, got {err}"
            );
            assert!(
                err.contains("local cache copy"),
                "{s3} must name the local-cache workaround, got {err}"
            );
        }
    }
}
