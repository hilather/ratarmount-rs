//! Test-only stand-ins for the token-free entries that no longer exist
//! (`WriteOverlay::new`, `new_with_create_info`, the untokened `seal` and
//! `verify`): a fixture opener reports what the test says it served, so a
//! test that has no factory to run still goes through the classified-base API.

#![allow(dead_code)]

use std::io;
use std::path::Path;
use std::sync::Arc;

use ratarmount_compositing::{
    BaseDigestRequest, ClassifiedBase, CreateOptions, IndexProvenance, LowerLayerRecord, OpenBase,
    Opened, OverlayError, ServedKind, ServedLocation, WriteOverlay,
};
use ratarmount_core::MountSource;

pub struct FixtureOpener {
    pub source: Arc<dyn MountSource>,
    pub kind: ServedKind,
    pub inputs: Vec<String>,
    pub location: Option<ServedLocation>,
}

impl OpenBase for FixtureOpener {
    fn open_base(&mut self) -> Result<Opened, String> {
        let source_metadata = match &self.location {
            Some(ServedLocation::Local(path)) => std::fs::metadata(path).ok(),
            _ => None,
        };
        Ok(Opened {
            source: self.source.clone(),
            kind: self.kind.clone(),
            inputs: self.inputs.clone(),
            location: self.location.clone(),
            index: IndexProvenance::None,
            sidecar_candidate: None,
            read_only_index: false,
            fetched: false,
            source_metadata,
            keep_alive: Box::new(()),
        })
    }
}

/// A token over `source` that reports a local folder with no typed input.
pub fn folder_token(source: Arc<dyn MountSource>) -> ClassifiedBase {
    ClassifiedBase::open(&mut FixtureOpener {
        source,
        kind: ServedKind::Folder,
        inputs: Vec::new(),
        location: None,
    })
    .expect("fixture token")
}

/// Drop-in for `WriteOverlay::new(base, dir)`: records no digest.
pub fn new_overlay(
    base: Arc<dyn MountSource>,
    dir: impl AsRef<Path>,
) -> Result<WriteOverlay, OverlayError> {
    let token = folder_token(base.clone());
    WriteOverlay::open(
        &token,
        base,
        dir,
        &CreateOptions {
            base_digest: BaseDigestRequest::None,
            ..Default::default()
        },
    )
}

/// Drop-in for `new_with_create_info` with `base_url`: a directory is a local
/// folder, a file a local archive, anything else a remote archive.
pub fn overlay_over(
    source: Arc<dyn MountSource>,
    dir: impl AsRef<Path>,
    base_url: &str,
    lower_layers: Vec<LowerLayerRecord>,
) -> Result<WriteOverlay, OverlayError> {
    let path = Path::new(base_url);
    let (kind, location) = if path.is_dir() {
        (
            ServedKind::Folder,
            ServedLocation::Local(path.to_path_buf()),
        )
    } else if path.is_file() {
        (
            ServedKind::Archive,
            ServedLocation::Local(path.to_path_buf()),
        )
    } else {
        (
            ServedKind::Archive,
            ServedLocation::Remote(base_url.to_owned()),
        )
    };
    let token = ClassifiedBase::open(&mut FixtureOpener {
        source: source.clone(),
        kind,
        inputs: vec![base_url.to_owned()],
        location: Some(location),
    })
    .map_err(OverlayError::Msg)?;
    WriteOverlay::open(
        &token,
        source,
        dir,
        &CreateOptions {
            lower_layers,
            ..Default::default()
        },
    )
}

/// Drop-in for `overlay_seal::seal(dir, view)`.
pub fn seal(
    dir: &Path,
    view: Arc<dyn MountSource>,
) -> io::Result<ratarmount_compositing::overlay_seal::SealOutcome> {
    let token = folder_token(view.clone());
    ratarmount_compositing::overlay_seal::seal(dir, &token, view)
}

/// A token that reports `path` as the typed input and served place.
pub struct ClassifiedBaseOver;

impl ClassifiedBaseOver {
    pub fn folder(source: Arc<dyn MountSource>, path: &Path) -> ClassifiedBase {
        Self::at(source, ServedKind::Folder, path)
    }

    pub fn archive(source: Arc<dyn MountSource>, path: &Path) -> ClassifiedBase {
        Self::at(source, ServedKind::Archive, path)
    }

    pub fn git(source: Arc<dyn MountSource>, path: &Path, tree: &str) -> ClassifiedBase {
        Self::at(
            source,
            ServedKind::Git {
                tree: tree.to_owned(),
            },
            path,
        )
    }

    fn at(source: Arc<dyn MountSource>, kind: ServedKind, path: &Path) -> ClassifiedBase {
        ClassifiedBase::open(&mut FixtureOpener {
            source,
            kind,
            inputs: vec![path.to_string_lossy().into_owned()],
            location: Some(ServedLocation::Local(path.to_path_buf())),
        })
        .expect("fixture token")
    }
}
