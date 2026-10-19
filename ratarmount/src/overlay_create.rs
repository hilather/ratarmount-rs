//! Creation metadata shared by mount startup and offline overlay writers.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_compositing::{
    ClassifiedBase, CreateOptions, OverlayError, WriteOverlay, HIDDEN_DB,
};
use ratarmount_core::MountSource;

/// Create on an already opened, classified and composed source. `composed` is
/// what is served (lower layers over the classified base); `options` carries
/// the digest request, lower records and exclusions. What the base IS comes
/// from `base`, never from the options.
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
        eprintln!(
            "warning: --base-digest none disables base identity verification for new overlays"
        );
    }
    // A single remote base also records a cheap remote token (ETag, size);
    // a composite's token comes from the classified inputs.
    if inputs.len() == 1
        && !has_source_binds
        && options.base_digest == BaseDigestRequest::Compute
        && !dir.join(HIDDEN_DB).exists()
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
