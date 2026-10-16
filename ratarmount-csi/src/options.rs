use crate::csi::{volume_capability, NodePublishVolumeRequest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Component, Path};
use tonic::Status;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountSpec {
    pub volume_id: String,
    pub target: String,
    pub args: Vec<String>,
    pub access_mode: i32,
    pub readonly: bool,
}

pub fn validate_target(target: &str) -> Result<(), Status> {
    let path = Path::new(target);
    if !path.is_absolute()
        || path.parent().is_none()
        || target.contains('\0')
        || target
            .split('/')
            .skip(1)
            .any(|p| p.is_empty() || p == "." || p == "..")
        || path
            .components()
            .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
    {
        return Err(Status::invalid_argument(
            "target_path must be an absolute normalized non-root path",
        ));
    }
    Ok(())
}

fn boolean(value: Option<&String>) -> Result<bool, Status> {
    match value.map(String::as_str) {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        _ => Err(Status::invalid_argument(
            "boolean attributes must be true or false",
        )),
    }
}

pub(crate) fn size(value: &str) -> Result<u64, Status> {
    let digits = value.trim_end_matches(['K', 'M', 'G', 'T', 'k', 'm', 'g', 't']);
    if value.len() - digits.len() > 1
        || digits.is_empty()
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Status::invalid_argument(
            "size must be bytes or an integer with K/M/G/T suffix",
        ));
    }
    let shift = match value.as_bytes().last() {
        Some(b'K' | b'k') => 10,
        Some(b'M' | b'm') => 20,
        Some(b'G' | b'g') => 30,
        Some(b'T' | b't') => 40,
        _ => 0,
    };
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(1u64 << shift))
        .ok_or_else(|| Status::invalid_argument("size overflows u64"))
}

pub fn secret_env(
    secrets: &std::collections::HashMap<String, String>,
) -> Result<BTreeMap<String, String>, Status> {
    // Exact names prevent AWS_CONFIG_FILE / RATARMOUNT_* configuration injection.
    const ALLOWED: &[&str] = &[
        "HF_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "RESTIC_PASSWORD",
        "RATARMOUNT_HTTP_USER",
        "RATARMOUNT_HTTP_PASSWORD",
        "RATARMOUNT_HTTP_COOKIE",
    ];
    if secrets
        .iter()
        .any(|(key, value)| !ALLOWED.contains(&key.as_str()) || value.contains('\0'))
    {
        return Err(Status::invalid_argument(
            "unsupported secret environment name or NUL value",
        ));
    }
    Ok(secrets
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect())
}

pub fn parse(request: &NodePublishVolumeRequest) -> Result<MountSpec, Status> {
    if request.volume_id.is_empty() || request.volume_id.contains('\0') {
        return Err(Status::invalid_argument("volume_id is required"));
    }
    validate_target(&request.target_path)?;
    secret_env(&request.secrets)?;
    let cap = request
        .volume_capability
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("volume_capability is required"))?;
    let Some(volume_capability::AccessType::Mount(mount)) = &cap.access_type else {
        return Err(Status::invalid_argument(
            "only filesystem mount capabilities are supported",
        ));
    };
    if !mount.fs_type.is_empty()
        || !mount.mount_flags.is_empty()
        || !mount.volume_mount_group.is_empty()
    {
        return Err(Status::invalid_argument(
            "fs_type, mount_flags and volume_mount_group are unsupported; use volume_context",
        ));
    }
    let mode = cap
        .access_mode
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("access_mode is required"))?
        .mode;
    let context = &request.volume_context;
    for (key, value) in context {
        if !matches!(
            key.as_str(),
            "source"
                | "overlay"
                | "readonlyGlobs"
                | "quota"
                | "uid"
                | "gid"
                | "umask"
                | "recursive"
                | "gitSyntheticHead"
                | "passthrough"
                | "csi.storage.k8s.io/pod.name"
                | "csi.storage.k8s.io/pod.namespace"
                | "csi.storage.k8s.io/pod.uid"
                | "csi.storage.k8s.io/serviceAccount.name"
                | "csi.storage.k8s.io/ephemeral"
        ) || value.contains('\0')
        {
            return Err(Status::invalid_argument(
                "unsupported volume_context attribute or NUL value",
            ));
        }
    }
    if context
        .get("csi.storage.k8s.io/ephemeral")
        .is_some_and(|s| s != "false")
    {
        return Err(Status::invalid_argument(
            "only static persistent volumes are supported",
        ));
    }
    let source = context
        .get("source")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Status::invalid_argument("volume_context.source is required"))?;
    if source.contains("://") {
        let url =
            url::Url::parse(source).map_err(|_| Status::invalid_argument("invalid source URL"))?;
        if !url.username().is_empty() || url.password().is_some() || url.query().is_some() {
            return Err(Status::invalid_argument(
                "source URL credentials/query strings are forbidden; use nodePublishSecretRef",
            ));
        }
    } else if !Path::new(source).is_absolute() {
        return Err(Status::invalid_argument("local source must be absolute"));
    }
    let overlay = context.get("overlay").map(String::as_str).unwrap_or("none");
    let writable = overlay != "none";
    let mut args = vec!["--foreground".into()];
    match overlay {
        "none" => {}
        "tmpfs" => args.push("--overlay-tmpfs".into()),
        s if s.starts_with("tmpfs:") => {
            size(&s[6..])?;
            args.push(format!("--overlay-tmpfs={}", &s[6..]));
        }
        _ => {
            return Err(Status::invalid_argument(
                "overlay must be none or tmpfs[:SIZE]",
            ))
        }
    }
    use volume_capability::access_mode::Mode;
    let supported = match Mode::try_from(mode) {
        Ok(Mode::MultiNodeReaderOnly | Mode::SingleNodeReaderOnly) => !writable || request.readonly,
        Ok(Mode::SingleNodeWriter | Mode::MultiNodeMultiWriter) => writable || request.readonly,
        _ => false,
    };
    if !supported {
        return Err(Status::invalid_argument(
            "access mode incompatible with overlay/read-only policy",
        ));
    }
    // Reader-only capabilities are read-only even when a caller forgets the flag.
    let readonly = request.readonly || !writable;
    for (key, flag) in [
        ("readonlyGlobs", "--overlay-readonly"),
        ("quota", "--overlay-quota"),
    ] {
        if let Some(value) = context.get(key) {
            if !writable || value.is_empty() {
                return Err(Status::invalid_argument(
                    "overlay policy requires tmpfs and a nonempty value",
                ));
            }
            if key == "quota" {
                size(value)?;
            }
            args.push(format!("{flag}={value}"));
        }
    }
    let mut fuse = if readonly {
        "allow_other,ro".to_string()
    } else {
        "allow_other,rw".to_string()
    };
    for key in ["uid", "gid", "umask"] {
        if let Some(value) = context.get(key) {
            let valid = if key == "umask" {
                !value.is_empty()
                    && value.len() <= 4
                    && value.bytes().all(|c| (b'0'..=b'7').contains(&c))
                    && u32::from_str_radix(value, 8).is_ok_and(|n| n <= 0o777)
            } else {
                !value.is_empty()
                    && value.bytes().all(|c| c.is_ascii_digit())
                    && value.parse::<u32>().is_ok()
            };
            if !valid {
                return Err(Status::invalid_argument("invalid uid/gid/umask"));
            }
            fuse.push_str(&format!(",{key}={value}"));
        }
    }
    args.extend(["-o".into(), fuse]);
    if boolean(context.get("recursive"))? {
        args.push("--recursive".into());
    }
    if boolean(context.get("gitSyntheticHead"))? {
        if !writable {
            return Err(Status::invalid_argument(
                "gitSyntheticHead requires tmpfs overlay",
            ));
        }
        args.push("--git-synthetic-head".into());
    }
    if let Some(value) = context.get("passthrough") {
        if !matches!(value.as_str(), "auto" | "on" | "off") {
            return Err(Status::invalid_argument(
                "passthrough must be auto, on or off",
            ));
        }
        args.push(format!("--passthrough={value}"));
    }
    args.extend(["--".into(), source.clone(), request.target_path.clone()]);
    Ok(MountSpec {
        volume_id: request.volume_id.clone(),
        target: request.target_path.clone(),
        args,
        access_mode: mode,
        readonly,
    })
}
