use std::collections::BTreeMap;
use std::path::Path;

pub type Options = BTreeMap<String, String>;

fn boolean(opts: &Options, key: &str) -> Result<bool, String> {
    match opts.get(key).map(String::as_str) {
        None | Some("false" | "0") => Ok(false),
        Some("" | "true" | "1") => Ok(true),
        _ => Err(format!("{key} must be true or false")),
    }
}

fn size(value: &str) -> bool {
    let (digits, shift) = match value.as_bytes().last().map(u8::to_ascii_uppercase) {
        Some(b'K') => (&value[..value.len() - 1], 10),
        Some(b'M') => (&value[..value.len() - 1], 20),
        Some(b'G') => (&value[..value.len() - 1], 30),
        Some(b'T') => (&value[..value.len() - 1], 40),
        _ => (value, 0),
    };
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && digits
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(1 << shift))
            .is_some()
}

pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 128
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
    {
        return Err("Name must start with an ASCII letter or digit and contain only letters, digits, _, . or - (max 128)".into());
    }
    Ok(())
}

pub fn validate(opts: &Options) -> Result<(), String> {
    for (key, value) in opts {
        if ![
            "source",
            "overlay",
            "ro",
            "uid",
            "gid",
            "umask",
            "readonly_globs",
            "quota",
            "git_synthetic_head",
            "recursive",
            "passthrough",
        ]
        .contains(&key.as_str())
        {
            // Do not reflect unknown keys or values: they may contain credentials.
            return Err(
                "unsupported volume option; credentials must come from the plugin environment"
                    .into(),
            );
        }
        if value.chars().any(char::is_control) || value.len() > 16 * 1024 {
            return Err(format!("invalid {key} value"));
        }
    }
    let source = opts
        .get("source")
        .filter(|s| !s.is_empty())
        .ok_or("source is required")?;
    // The plugin cannot persist credential-bearing URLs safely. Let the remote
    // backend resolve and authenticate a clean URL using inherited environment.
    if let Some((_, rest)) = source.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.contains('@') || rest.contains(['?', '#']) {
            return Err("source URL must not contain userinfo, query parameters or fragments; use environment credentials".into());
        }
    }
    for key in ["ro", "recursive", "git_synthetic_head"] {
        boolean(opts, key)?;
    }
    if let Some(overlay) = opts.get("overlay") {
        if overlay == "tmpfs" {
        } else if let Some(cap) = overlay.strip_prefix("tmpfs:") {
            if !size(cap) {
                return Err("overlay tmpfs size must be bytes or an integer with K/M/G/T".into());
            }
        } else if !Path::new(overlay).is_absolute() {
            return Err("overlay must be tmpfs[:SIZE] or an absolute host directory".into());
        }
        if boolean(opts, "ro")? {
            return Err("ro=true conflicts with overlay".into());
        }
    }
    if (opts.contains_key("readonly_globs") || opts.contains_key("quota"))
        && !opts.contains_key("overlay")
    {
        return Err("readonly_globs and quota require overlay".into());
    }
    for key in ["uid", "gid"] {
        if let Some(value) = opts.get(key) {
            if value.is_empty()
                || !value.bytes().all(|c| c.is_ascii_digit())
                || value.parse::<u32>().is_err()
            {
                return Err(format!("{key} must be a u32"));
            }
        }
    }
    if let Some(value) = opts.get("umask") {
        if value.is_empty()
            || !value.bytes().all(|c| (b'0'..=b'7').contains(&c))
            || u32::from_str_radix(value, 8).map_or(true, |n| n > 0o777)
        {
            return Err("umask must be octal 000..777".into());
        }
    }
    if opts.get("quota").is_some_and(|v| !size(v)) {
        return Err("quota must be bytes or an integer with K/M/G/T".into());
    }
    if let Some(globs) = opts.get("readonly_globs") {
        for glob in globs.split(',') {
            let glob = glob.trim().trim_matches('/');
            if glob.is_empty()
                || glob
                    .split('/')
                    .any(|c| c.is_empty() || c == "." || c == ".." || c != "**" && c.contains("**"))
            {
                return Err(
                    "invalid readonly_globs: use root-relative paths; ** must be a whole component"
                        .into(),
                );
            }
        }
    }
    if opts
        .get("passthrough")
        .is_some_and(|v| !["auto", "on", "off"].contains(&v.as_str()))
    {
        return Err("passthrough must be auto, on or off".into());
    }
    Ok(())
}

/// Build argv without a shell. Environment credentials are inherited by Command.
pub fn mount_args(opts: &Options, mountpoint: &Path) -> Result<Vec<String>, String> {
    validate(opts)?;
    let mut args = vec!["--foreground".into()];
    let mut fuse = String::from("allow_other,noatime");
    if !opts.contains_key("overlay") {
        fuse.push_str(",ro");
    }
    for key in ["uid", "gid", "umask"] {
        if let Some(value) = opts.get(key) {
            fuse.push_str(&format!(",{key}={value}"));
        }
    }
    args.extend(["-o".into(), fuse]);
    if let Some(overlay) = opts.get("overlay") {
        if overlay == "tmpfs" {
            args.push("--overlay-tmpfs".into());
        } else if let Some(size) = overlay.strip_prefix("tmpfs:") {
            args.push(format!("--overlay-tmpfs={size}"));
        } else {
            args.extend(["-w".into(), overlay.clone()]);
        }
    }
    for (key, flag) in [
        ("readonly_globs", "--overlay-readonly"),
        ("quota", "--overlay-quota"),
        ("passthrough", "--passthrough"),
    ] {
        if let Some(value) = opts.get(key) {
            args.push(format!("{flag}={value}"));
        }
    }
    for (key, flag) in [
        ("recursive", "--recursive"),
        ("git_synthetic_head", "--git-synthetic-head"),
    ] {
        if boolean(opts, key)? {
            args.push(flag.into());
        }
    }
    args.extend([
        "--".into(),
        opts["source"].clone(),
        mountpoint
            .to_str()
            .ok_or("mountpoint must be UTF-8")?
            .into(),
    ]);
    Ok(args)
}
