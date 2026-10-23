//! Creation metadata shared by mount startup and offline overlay writers.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_compositing::{ClassifiedBase, CreateOptions, OverlayError, WriteOverlay};
use ratarmount_core::MountSource;

/// Create on an already opened, classified and composed source. `composed` is
/// what is served (lower layers over the classified base); `options` carries
/// the digest request, lower records and exclusions. What the base IS comes
/// from `base`, never from the options.
/// `--base-digest none` is kind-only: the base's kind (and a remote's place)
/// is still checked; its content is not.
pub(crate) const NONE_DIGEST_WARNING: &str = "warning: --base-digest none checks only the kind of \
     the base for new overlays, not its content; an edited or swapped base of the same kind is \
     accepted";

pub fn create_overlay(
    base: &ClassifiedBase,
    composed: Arc<dyn MountSource>,
    dir: &Path,
    mut options: CreateOptions,
    inputs: &[PathBuf],
    has_source_binds: bool,
) -> Result<WriteOverlay, OverlayError> {
    use ratarmount_compositing::BaseDigestRequest;
    if options.base_digest == BaseDigestRequest::None {
        eprintln!("{NONE_DIGEST_WARNING}");
    }
    // A single remote base also records a cheap remote token (ETag, size);
    // a composite's token comes from the classified inputs.
    if inputs.len() == 1
        && !has_source_binds
        && options.base_digest == BaseDigestRequest::Compute
        && ratarmount_compositing::overlay_db_absent(dir)
    {
        let typed = inputs[0].to_string_lossy();
        if ratarmount_remote::is_remote_url(&typed) {
            options.remote_token = Some(
                super::overlay_cmd::remote_base_token(&typed)
                    .unwrap_or_else(|| format!("url:{}", ratarmount_core::redact_base_url(&typed))),
            );
        }
    }
    WriteOverlay::open(base, composed, dir, &options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_compositing::HIDDEN_DB;
    use ratarmount_core::MountSource;

    /// Regression (R6-G8): the warning said `none` disables identity
    /// verification, but the kind is still checked (a directory overlay is
    /// refused over an archive).
    #[test]
    fn regression_none_digest_warning_says_kind_is_checked() {
        assert!(NONE_DIGEST_WARNING.contains("only the kind"));
        assert!(!NONE_DIGEST_WARNING.contains("disables"));
    }

    fn token_for(inputs: &[&str], binds: bool) -> Option<String> {
        let dir = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let stack: Arc<dyn MountSource> =
            Arc::new(ratarmount_compositing::FolderMountSource::new(src.path()).unwrap());
        // Remote inputs cannot be opened offline: the fixture opener reports
        // exactly what the test says was served.
        let base = ClassifiedBase::open(&mut crate::base_identity::fixtures::FixtureOpener {
            source: stack.clone(),
            kind: ratarmount_compositing::ServedKind::Archive,
            inputs: inputs.iter().map(|s| (*s).to_owned()).collect(),
            location: Some(ratarmount_compositing::ServedLocation::Remote(
                inputs[0].to_owned(),
            )),
        })
        .unwrap();
        let paths: Vec<PathBuf> = inputs.iter().map(PathBuf::from).collect();
        let overlay = create_overlay(
            &base,
            stack,
            &dir.path().join("ov"),
            CreateOptions::default(),
            &paths,
            binds,
        )
        .unwrap();
        drop(overlay);
        let meta = ratarmount_compositing::OverlayMeta::read(dir.path().join("ov"))
            .unwrap()
            .unwrap();
        assert!(dir.path().join("ov").join(HIDDEN_DB).exists());
        for (key, value) in meta.values() {
            assert!(!value.contains("s3cr3t"), "{key} leaked: {value}");
            assert!(!value.contains("deadbeef"), "{key} leaked: {value}");
        }
        meta.get("base_remote_token").map(str::to_owned)
    }

    /// Regression (r17 skeptic #2, R7-E2 B12): a dangling symlink at the
    /// database path was read as a new overlay: a remote base was asked for a
    /// fresh token (a network HEAD) and the open created a database through
    /// the symlink. It is an existing, unreadable database: no request is made
    /// and the open is refused with nothing created at the target.
    #[cfg(unix)]
    #[test]
    fn regression_dangling_db_symlink_is_not_a_new_overlay() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let url = format!("http://127.0.0.1:{port}/b.tar");
        let dir = tempfile::tempdir().unwrap();
        let ov = dir.path().join("ov");
        std::fs::create_dir(&ov).unwrap();
        let target = dir.path().join("nowhere.sqlite");
        std::os::unix::fs::symlink(&target, ov.join(HIDDEN_DB)).unwrap();
        let src = tempfile::tempdir().unwrap();
        let stack: Arc<dyn MountSource> =
            Arc::new(ratarmount_compositing::FolderMountSource::new(src.path()).unwrap());
        let base = ClassifiedBase::open(&mut crate::base_identity::fixtures::FixtureOpener {
            source: stack.clone(),
            kind: ratarmount_compositing::ServedKind::Archive,
            inputs: vec![url.clone()],
            location: Some(ratarmount_compositing::ServedLocation::Remote(url.clone())),
        })
        .unwrap();
        let opened = create_overlay(
            &base,
            stack,
            &ov,
            CreateOptions::default(),
            &[PathBuf::from(&url)],
            false,
        );
        assert!(opened.is_err(), "a dangling database must be refused");
        assert!(!target.exists(), "nothing created through the symlink");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "no HEAD for an existing overlay"
        );
    }

    /// Regression: several inputs were stored as a raw JSON array, leaking credentials.
    #[test]
    fn regression_remote_token_redacts_each_input() {
        let token = token_for(
            &[
                "https://u:s3cr3t@h.example/b.tar?X-Amz-Signature=deadbeef",
                "git:///srv/repo?copy.git#HEAD",
            ],
            false,
        )
        .unwrap();
        let items: Vec<String> = serde_json::from_str(&token).unwrap();
        assert_eq!(
            items,
            ["https://h.example/b.tar", "git:///srv/repo?copy.git#HEAD"]
        );
    }
}
