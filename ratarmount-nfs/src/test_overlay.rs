//! Test-only: open an overlay over a token that reports `base` as a local
//! folder (what the token-free `WriteOverlay::new` used to do), so the
//! protocol tests keep exercising the overlay without a mounted base.

use std::path::Path;
use std::sync::Arc;

use ratarmount_compositing::{
    BaseDigestRequest, ClassifiedBase, CreateOptions, IndexProvenance, OpenBase, Opened,
    OverlayError, ServedKind, WriteOverlay,
};
use ratarmount_core::MountSource;

struct FixtureOpener(Arc<dyn MountSource>);

impl OpenBase for FixtureOpener {
    fn open_base(&mut self) -> Result<Opened, String> {
        Ok(Opened {
            source: self.0.clone(),
            kind: ServedKind::Folder,
            inputs: Vec::new(),
            location: None,
            index: IndexProvenance::None,
            sidecar_candidate: None,
            read_only_index: false,
            fetched: false,
            keep_alive: Box::new(()),
        })
    }
}

pub(crate) fn new_overlay(
    base: Arc<dyn MountSource>,
    dir: impl AsRef<Path>,
) -> Result<WriteOverlay, OverlayError> {
    let token =
        ClassifiedBase::open(&mut FixtureOpener(base.clone())).map_err(OverlayError::Msg)?;
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
