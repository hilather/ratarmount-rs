//! Creation metadata shared by mount startup and offline overlay writers.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_compositing::{OverlayCreateInfo, OverlayError, WriteOverlay, HIDDEN_DB};
use ratarmount_core::MountSource;

/// Create on an already opened, pinned and composed source. `info` carries the
/// original positional, digest request, lower records, index path and Git tree.
pub fn create_overlay(
    stack: Arc<dyn MountSource>,
    dir: &Path,
    mut info: OverlayCreateInfo,
    inputs: &[PathBuf],
    has_source_binds: bool,
) -> Result<WriteOverlay, OverlayError> {
    use ratarmount_compositing::BaseDigestRequest;
    if info.base_digest == BaseDigestRequest::None {
        eprintln!(
            "warning: --base-digest none disables base identity verification for new overlays"
        );
    }
    if inputs.len() > 1 || has_source_binds {
        info.remote_token = Some(serde_json::to_string(inputs).expect("input paths"));
    } else if info.base_digest == BaseDigestRequest::Compute
        && !dir.join(HIDDEN_DB).exists()
        && ratarmount_remote::is_remote_url(&info.base_url)
    {
        info.remote_token = Some(
            super::overlay_cmd::remote_base_token(&info.base_url)
                .unwrap_or_else(|| format!("url:{}", info.base_url)),
        );
    }
    if inputs.len() == 1
        && !has_source_binds
        && info.git_tree.is_none()
        && !ratarmount_remote::is_remote_url(&info.base_url)
    {
        info.local_path = Some(inputs[0].clone());
    }
    WriteOverlay::new_with_create_info(stack, dir, &info)
}
