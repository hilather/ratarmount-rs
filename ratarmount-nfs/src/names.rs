//! `filename3` / path conversion (UTF-8 lossy, NFSv3 255-byte cap).

use nfsserve::nfs::{filename3, nfsstat3};

/// RFC 1813 `NFS3ERR_NAMETOOLONG` threshold (bytes).
pub const MAX_NAME_LEN: usize = 255;

/// Decode an NFS filename. Empty → `INVAL`; `>255` bytes → `NAMETOOLONG`.
pub fn decode_filename(name: &filename3) -> Result<String, nfsstat3> {
    let bytes: &[u8] = name.as_ref();
    if bytes.is_empty() {
        return Err(nfsstat3::NFS3ERR_INVAL);
    }
    if bytes.len() > MAX_NAME_LEN {
        return Err(nfsstat3::NFS3ERR_NAMETOOLONG);
    }
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// Encode a `MountSource` name as `filename3` bytes.
pub fn encode_filename(name: &str) -> filename3 {
    filename3::from(name.as_bytes())
}

/// Join a parent archive path and a child name (`/` + name at root).
pub fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Parent of an archive path (`/` stays `/`).
pub fn parent_path(path: &str) -> String {
    if path == "/" {
        return "/".into();
    }
    match path.rfind('/') {
        None | Some(0) => "/".into(),
        Some(i) => path[..i].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nametoolong_and_empty() {
        let empty = filename3::from(&b""[..]);
        assert_eq!(
            decode_filename(&empty).unwrap_err() as u32,
            nfsstat3::NFS3ERR_INVAL as u32
        );
        let long = filename3::from(vec![b'a'; 256].as_slice());
        assert_eq!(
            decode_filename(&long).unwrap_err() as u32,
            nfsstat3::NFS3ERR_NAMETOOLONG as u32
        );
        let ok = filename3::from(&b"hello"[..]);
        assert_eq!(decode_filename(&ok).unwrap(), "hello");
    }

    #[test]
    fn lossy_non_utf8() {
        let raw = filename3::from(&[0xff, b'x'][..]);
        let s = decode_filename(&raw).unwrap();
        assert!(s.contains('x'));
        assert_eq!(encode_filename("ok").as_ref(), b"ok");
    }

    #[test]
    fn join_and_parent() {
        assert_eq!(join_path("/", "a"), "/a");
        assert_eq!(join_path("/a", "b"), "/a/b");
        assert_eq!(parent_path("/"), "/");
        assert_eq!(parent_path("/a"), "/");
        assert_eq!(parent_path("/a/b"), "/a");
    }
}
