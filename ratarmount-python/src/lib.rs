#![forbid(unused_macros)]

//! URL classification shared by the optional Python extension and embedding rlib.

use std::path::PathBuf;

use ratarmount_session::SourceSpec;

#[cfg(feature = "python")]
mod embed;

/// Archive location stored in a `ratar://` URL.
///
/// A leading `ratar://` is stripped. The remainder is not split into a member
/// path: `ratar://s3://bucket/key.tar` is the archive URL `s3://bucket/key.tar`.
/// A `scheme://` remainder is [`SourceSpec::Url`]; anything else is a path.
pub fn split_ratar_url(input: &str) -> SourceSpec {
    let archive = input.strip_prefix("ratar://").unwrap_or(input);
    if is_archive_url(archive) || archive.to_ascii_lowercase().starts_with("restic:") {
        SourceSpec::Url(archive.to_string())
    } else {
        SourceSpec::Path(PathBuf::from(archive))
    }
}

fn is_archive_url(spec: &str) -> bool {
    let Some((scheme, _)) = spec.split_once("://") else {
        return false;
    };
    scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '.' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_ratar_url_table() {
        assert_eq!(
            split_ratar_url("ratar://./set.tar"),
            SourceSpec::Path(PathBuf::from("./set.tar"))
        );
        assert_eq!(
            split_ratar_url("ratar:///data/set.tar.zst"),
            SourceSpec::Path(PathBuf::from("/data/set.tar.zst"))
        );
        assert_eq!(
            split_ratar_url("ratar://s3://bucket/key.tar"),
            SourceSpec::Url("s3://bucket/key.tar".to_string())
        );
        assert_eq!(
            split_ratar_url("./set.tar"),
            SourceSpec::Path(PathBuf::from("./set.tar"))
        );
    }

    /// Regression: ratar://s3:// is the archive URL, not a member path.
    #[test]
    fn split_ratar_url_s3_is_archive_not_member() {
        match split_ratar_url("ratar://s3://bucket/key.tar") {
            SourceSpec::Url(url) => {
                assert_eq!(url, "s3://bucket/key.tar");
                assert_ne!(url, "bucket/key.tar");
                assert_ne!(url, "key.tar");
            }
            SourceSpec::Path(path) => panic!("archive became a path: {}", path.display()),
        }
        assert_eq!(
            split_ratar_url("ratar://s3://bucket/key.tar/nested/member.txt"),
            SourceSpec::Url("s3://bucket/key.tar/nested/member.txt".to_string()),
            "slashes after the archive name are still the archive URL"
        );
    }

    /// Regression: URL schemes pass through while local colon filenames stay paths.
    #[test]
    fn regression_url_schemes_and_local_colon_paths() {
        for input in [
            "https://host/a.tar",
            "http://host/a.tar",
            "s3://bucket/a.tar",
            "hf://org/repo/a.tar",
            "restic:/abs/repo",
            "docker://ubuntu:24.04",
            "git+https://host/repo",
            "gs://bucket/a.tar",
            "az://bucket/a.tar",
        ] {
            assert_eq!(split_ratar_url(input), SourceSpec::Url(input.into()));
            assert_eq!(
                split_ratar_url(&format!("ratar://{input}")),
                SourceSpec::Url(input.into())
            );
        }
        for input in [
            "local:archive.tar",
            "./http://local.tar",
            "1invalid://a",
            "C:\\data\\x.tar",
        ] {
            assert_eq!(split_ratar_url(input), SourceSpec::Path(input.into()));
        }
    }
}
