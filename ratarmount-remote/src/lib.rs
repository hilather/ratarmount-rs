//! Remote URL access for Phase 10.
//!
//! - `file://` → local path
//! - `http(s)://` → fetch to temp (and optional range-capable reader)
//! - `s3://bucket/key` → GetObject to temp (AWS env credentials)
//! - `ssh://` / `sftp://` / `scp://` → SFTP download to temp
//! - other schemes → clear "not yet" errors

mod s3;
mod ssh;

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use log::debug;
use tempfile::NamedTempFile;
use thiserror::Error;
use url::Url;

pub use s3::{fetch_s3_to_temp, parse_s3_url, S3Location};
pub use ssh::{fetch_ssh_to_temp, parse_ssh_url, SshLocation};

#[derive(Debug, Error)]
pub enum RemoteError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("url: {0}")]
    Url(String),
    #[error("http: {0}")]
    Http(String),
    #[error("s3: {0}")]
    S3(String),
    #[error("ssh: {0}")]
    Ssh(String),
    #[error("unsupported remote scheme: {0}")]
    UnsupportedScheme(String),
}

pub type Result<T> = std::result::Result<T, RemoteError>;

/// True if `s` looks like a URL with a scheme (not a bare Windows path).
pub fn is_remote_url(s: &str) -> bool {
    if let Ok(u) = Url::parse(s) {
        match u.scheme() {
            "http" | "https" | "file" | "ftp" | "s3" | "ssh" | "sftp" | "scp" | "smb"
            | "webdav" => true,
            _ => false,
        }
    } else {
        false
    }
}

/// Resolve a path or URL to a local filesystem path suitable for openers.
/// Remote schemes download into a kept temp file; caller must keep [`RemoteLocal`] alive.
pub fn resolve_to_local(input: &str) -> Result<RemoteLocal> {
    if !is_remote_url(input) {
        return Ok(RemoteLocal::Local(PathBuf::from(input)));
    }
    let url = Url::parse(input).map_err(|e| RemoteError::Url(e.to_string()))?;
    match url.scheme() {
        "file" => {
            let path = url
                .to_file_path()
                .map_err(|_| RemoteError::Url(format!("invalid file URL: {input}")))?;
            Ok(RemoteLocal::Local(path))
        }
        "http" | "https" => {
            let (tmp, size) = fetch_http_to_temp(url.as_str())?;
            keep_fetched(input, tmp, size)
        }
        "s3" => {
            let (tmp, size) = fetch_s3_to_temp(input)?;
            keep_fetched(input, tmp, size)
        }
        "ssh" | "sftp" | "scp" => {
            let (tmp, size) = fetch_ssh_to_temp(input)?;
            keep_fetched(input, tmp, size)
        }
        other => Err(RemoteError::UnsupportedScheme(other.to_string())),
    }
}

fn keep_fetched(input: &str, tmp: NamedTempFile, size: u64) -> Result<RemoteLocal> {
    let path = tmp
        .into_temp_path()
        .keep()
        .map_err(|e| RemoteError::Io(e.error))?;
    debug!("fetched {input} -> {} ({size} bytes)", path.display());
    Ok(RemoteLocal::Fetched { path, size })
}

/// Local path plus optional lifetime for fetched remote bodies.
#[derive(Debug)]
pub enum RemoteLocal {
    Local(PathBuf),
    /// Downloaded remote object; path is deleted when dropped unless `persist`.
    Fetched { path: PathBuf, size: u64 },
}

impl RemoteLocal {
    pub fn path(&self) -> &Path {
        match self {
            Self::Local(p) | Self::Fetched { path: p, .. } => p,
        }
    }
}

impl Drop for RemoteLocal {
    fn drop(&mut self) {
        if let Self::Fetched { path, .. } = self {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Full GET download to a tempfile (works without Range support).
pub fn fetch_http_to_temp(url: &str) -> Result<(NamedTempFile, u64)> {
    let resp = ureq::get(url)
        .set("User-Agent", "ratarmount-rs/0.1")
        .call()
        .map_err(|e| RemoteError::Http(e.to_string()))?;
    if !(200..300).contains(&resp.status()) {
        return Err(RemoteError::Http(format!(
            "HTTP {} for {url}",
            resp.status()
        )));
    }
    let mut reader = resp.into_reader();
    let mut tmp = NamedTempFile::new()?;
    let n = io::copy(&mut reader, &mut tmp)?;
    tmp.flush()?;
    tmp.as_file().seek(SeekFrom::Start(0))?;
    Ok((tmp, n))
}

/// Seekable HTTP reader using Range requests when the server supports them.
/// Falls back to full download into memory if Content-Length is small or ranges fail.
pub struct HttpRangeFile {
    url: String,
    size: u64,
    pos: u64,
    /// Optional fully buffered body if ranges unavailable
    buffered: Option<Vec<u8>>,
}

impl HttpRangeFile {
    pub fn open(url: &str) -> Result<Self> {
        let head = ureq::head(url)
            .set("User-Agent", "ratarmount-rs/0.1")
            .call()
            .map_err(|e| RemoteError::Http(e.to_string()))?;
        let status = head.status();
        if !(200..300).contains(&status) && status != 405 {
            // Some servers reject HEAD
            debug!("HEAD {url} -> {status}, trying GET probe");
        }
        let len = head
            .header("Content-Length")
            .and_then(|s| s.parse::<u64>().ok());
        let accept_ranges = head
            .header("Accept-Ranges")
            .map(|s| s.to_ascii_lowercase().contains("bytes"))
            .unwrap_or(false);

        if accept_ranges {
            if let Some(size) = len {
                return Ok(Self {
                    url: url.to_string(),
                    size,
                    pos: 0,
                    buffered: None,
                });
            }
        }

        // Fallback: full download into memory (fine for test fixtures)
        let (mut tmp, size) = fetch_http_to_temp(url)?;
        let mut buf = Vec::with_capacity(size as usize);
        tmp.read_to_end(&mut buf)?;
        Ok(Self {
            url: url.to_string(),
            size: buf.len() as u64,
            pos: 0,
            buffered: Some(buf),
        })
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Read for HttpRangeFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        if let Some(data) = &self.buffered {
            let start = self.pos as usize;
            let end = (self.pos as usize + buf.len()).min(data.len());
            let n = end - start;
            buf[..n].copy_from_slice(&data[start..end]);
            self.pos += n as u64;
            return Ok(n);
        }
        let end = (self.pos + buf.len() as u64).min(self.size);
        if end <= self.pos {
            return Ok(0);
        }
        // Inclusive Range end
        let range = format!("bytes={}-{}", self.pos, end - 1);
        let resp = ureq::get(&self.url)
            .set("User-Agent", "ratarmount-rs/0.1")
            .set("Range", &range)
            .call()
            .map_err(|e| io::Error::other(e.to_string()))?;
        let status = resp.status();
        if status != 206 && status != 200 {
            return Err(io::Error::other(format!(
                "HTTP {status} for range {range} on {}",
                self.url
            )));
        }
        let mut reader = resp.into_reader();
        let mut chunk = vec![0u8; (end - self.pos) as usize];
        reader.read_exact(&mut chunk)?;
        let n = chunk.len().min(buf.len());
        buf[..n].copy_from_slice(&chunk[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for HttpRangeFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.size as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// Materialize any supported remote (or copy local path for uniform API).
pub fn materialize_input(input: &str) -> Result<RemoteLocal> {
    resolve_to_local(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_url_local() {
        let p = std::env::temp_dir().join("ratarmount-remote-test.txt");
        std::fs::write(&p, b"hi").unwrap();
        let url = Url::from_file_path(&p).unwrap().to_string();
        let local = resolve_to_local(&url).unwrap();
        assert_eq!(local.path(), p);
        assert_eq!(std::fs::read(local.path()).unwrap(), b"hi");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn detect_schemes() {
        assert!(is_remote_url("https://example.com/a.tar"));
        assert!(is_remote_url("file:///tmp/x"));
        assert!(is_remote_url("s3://bucket/key.tar"));
        assert!(is_remote_url("ssh://user@host/path.tar"));
        assert!(is_remote_url("sftp://user@host//abs/path.tar"));
        assert!(!is_remote_url("/tmp/x"));
        assert!(!is_remote_url("relative/path"));
    }

    #[test]
    fn unsupported_scheme_message() {
        let err = resolve_to_local("smb://server/share/a.tar").unwrap_err();
        assert!(err.to_string().contains("unsupported") || err.to_string().contains("smb"));
    }
}
