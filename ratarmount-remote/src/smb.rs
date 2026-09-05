//! SMB/CIFS access for `smb://` URLs.
//!
//! Live Range I/O uses the in-tree SMB 2.0.2 codec ([`crate::Smb2Client`]).
//! Dialect `STATUS_NOT_SUPPORTED` / non-2.x falls back to Samba `smbclient`
//! download-to-temp when that binary is on `PATH`. Missing both yields
//! `smb_fallback_clear_error` (install hint or dialect residual).
//!
//! Share / directory URLs (`smb://host/share/` or `smb://host/share/dir/`)
//! list via QUERY_DIRECTORY ([`open_smb_folder`] / [`SmbListing`]). Dialect
//! failure is a clear error, not an empty listing. `smbclient` listing is residual.

use std::io::{self, Read, Seek, SeekFrom};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use log::debug;
use ratarmount_core::{ArchiveRead, MountSource};
use tempfile::NamedTempFile;
use url::Url;

use crate::folder::{RemoteDirent, RemoteFolderMountSource, RemoteListing};
use crate::smb2_client::{
    Smb2Client, QUERY_DIR_ENTRY_CAP, STATUS_NOT_A_DIRECTORY, STATUS_NOT_SUPPORTED,
    STATUS_OBJECT_NAME_NOT_FOUND,
};
use crate::{RemoteError, Result};

const SMB_USER_ENV: &str = "RATARMOUNT_SMB_USER";
const SMB_PASSWORD_ENV: &str = "RATARMOUNT_SMB_PASSWORD";

/// Parsed SMB location (`smb://[user[:pass]@]host[:port]/share/path`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbLocation {
    pub host: String,
    /// SMB port (default 445).
    pub port: u16,
    /// Share name (first path segment after host).
    pub share: String,
    /// Path within the share (no leading slash; may be empty for share root).
    pub path: String,
    pub user: Option<String>,
    pub password: Option<String>,
    /// Optional Windows domain (from `DOMAIN;user` / `DOMAIN\user` userinfo).
    pub domain: Option<String>,
}

impl SmbLocation {
    /// UNC-style path for messaging: `//host/share/path`.
    pub fn unc_share(&self) -> String {
        format!("//{}/{}", self.host, self.share)
    }

    /// Path argument for `smbclient get` (forward slashes, no leading slash).
    pub fn remote_get_path(&self) -> &str {
        &self.path
    }
}

/// Parse `smb://[domain;]user[:pass]@host[:port]/share[/path…]`.
///
/// Path rules:
/// - First hierarchical segment after host is the **share**.
/// - Remaining segments are the path inside the share.
/// - Userinfo may encode a domain as `DOMAIN;user` or `DOMAIN\user` (URL-encoded
///   backslash is `%5C`).
pub fn parse_smb_url(url_str: &str) -> Result<SmbLocation> {
    let url = Url::parse(url_str).map_err(|e| RemoteError::Url(e.to_string()))?;
    if url.scheme() != "smb" {
        return Err(RemoteError::UnsupportedScheme(url.scheme().to_string()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| RemoteError::Url("smb URL missing host".into()))?
        .to_string();
    let port = url.port().unwrap_or(445);

    // `url` may leave `;` / `\` percent-encoded in userinfo (`%3B`, `%5C`).
    let raw_user = if url.username().is_empty() {
        None
    } else {
        Some(percent_decode_userinfo(url.username()))
    };
    let (user, domain) = split_user_domain(raw_user);
    let password = url.password().map(percent_decode_userinfo);

    // url.path() is `/share` or `/share/dir/file` (leading slash).
    let raw = url.path().trim_start_matches('/');
    if raw.is_empty() {
        return Err(RemoteError::Url(
            "smb URL missing share (expected smb://host/share[/path])".into(),
        ));
    }
    let (share, path) = match raw.split_once('/') {
        Some((share, rest)) => (share.to_string(), rest.to_string()),
        None => (raw.to_string(), String::new()),
    };
    if share.is_empty() {
        return Err(RemoteError::Url("smb URL missing share name".into()));
    }

    Ok(SmbLocation {
        host,
        port,
        share,
        path,
        user,
        password,
        domain,
    })
}

/// Minimal percent-decoder for userinfo (`%XX` → byte). Invalid sequences kept as-is.
fn percent_decode_userinfo(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Split `DOMAIN;user` / `DOMAIN\user` into (user, Some(domain)).
fn split_user_domain(username: Option<String>) -> (Option<String>, Option<String>) {
    let Some(raw) = username else {
        return (None, None);
    };
    if let Some((dom, user)) = raw.split_once(';') {
        if !dom.is_empty() && !user.is_empty() {
            return (Some(user.to_string()), Some(dom.to_string()));
        }
    }
    if let Some((dom, user)) = raw.split_once('\\') {
        if !dom.is_empty() && !user.is_empty() {
            return (Some(user.to_string()), Some(dom.to_string()));
        }
    }
    (Some(raw), None)
}

/// Build argv for `smbclient //host/share … -c 'get remote local'`.
///
/// Exposed for unit tests (mock runners compare against this shape).
pub fn smbclient_download_args(loc: &SmbLocation, dest: &Path) -> Vec<String> {
    let mut args = vec![loc.unc_share(), "-p".into(), loc.port.to_string()];

    // Auth: URL credentials, then env password, else guest (`-N`, no prompt).
    if let Some(user) = loc.user.as_deref() {
        // `user%` / `user%pass` avoids interactive password prompts.
        let cred = match loc.password.as_deref() {
            Some(pw) => format!("{user}%{pw}"),
            None => format!("{user}%"),
        };
        args.push("-U".into());
        args.push(cred);
    } else if let Ok(pw) = std::env::var(SMB_PASSWORD_ENV) {
        let user = std::env::var(SMB_USER_ENV)
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "guest".into());
        args.push("-U".into());
        args.push(format!("{user}%{pw}"));
    } else {
        args.push("-N".into());
    }

    if let Some(domain) = loc.domain.as_deref() {
        args.push("-W".into());
        args.push(domain.to_string());
    }

    // smbclient accepts forward slashes for the remote path.
    let remote = loc.path.replace('\\', "/");
    let dest_s = dest.to_string_lossy();
    let cmd = format!("get \"{remote}\" \"{dest_s}\"");
    args.push("-c".into());
    args.push(cmd);
    args
}

/// Locate `smbclient` on PATH.
pub fn find_smbclient() -> Option<PathBuf> {
    which_bin("smbclient")
}

fn which_bin(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            // On Unix, check executable bit lightly via metadata when possible.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = candidate.metadata() {
                    if meta.permissions().mode() & 0o111 == 0 {
                        continue;
                    }
                }
            }
            return Some(candidate);
        }
        // Windows: also try .exe
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{name}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

/// Download via `smbclient` into a tempfile.
pub fn fetch_smb_to_temp(url_str: &str) -> Result<(NamedTempFile, u64)> {
    let loc = parse_smb_url(url_str)?;
    fetch_smb_location_to_temp(&loc)
}

pub fn fetch_smb_location_to_temp(loc: &SmbLocation) -> Result<(NamedTempFile, u64)> {
    fetch_smb_location_to_temp_with(loc, run_smbclient_get)
}

/// Injectable runner for tests: write the remote file to `dest`, return byte count.
pub fn fetch_smb_location_to_temp_with<F>(
    loc: &SmbLocation,
    runner: F,
) -> Result<(NamedTempFile, u64)>
where
    F: FnOnce(&SmbLocation, &Path) -> Result<u64>,
{
    if loc.path.is_empty() {
        return Err(RemoteError::Smb(
            "smb URL must include a file path under the share (smb://host/share/path/to/file)"
                .into(),
        ));
    }
    let tmp = NamedTempFile::new()?;
    let dest = tmp.path().to_path_buf();
    // Runner writes via a separate open of `dest` (smbclient does the same).
    let reported = runner(loc, &dest)?;
    let size = std::fs::metadata(&dest)?.len();
    if reported != 0 && reported != size {
        debug!("smb runner reported {reported} bytes, file size is {size}");
    }
    Ok((tmp, size))
}

/// Default runner: invoke real `smbclient`.
pub fn run_smbclient_get(loc: &SmbLocation, dest: &Path) -> Result<u64> {
    let bin = find_smbclient().ok_or_else(|| {
        RemoteError::Smb(
            "smbclient not found on PATH; install Samba client tools \
             (e.g. `apt install smbclient` / `dnf install samba-client`) to fetch smb:// URLs"
                .into(),
        )
    })?;

    let args = smbclient_download_args(loc, dest);
    debug!(
        "smbclient {} {}",
        bin.display(),
        redact_smbclient_args(&args).join(" ")
    );

    let output = Command::new(&bin)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| RemoteError::Smb(format!("failed to spawn smbclient: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else {
            stdout.trim().to_string()
        };
        return Err(RemoteError::Smb(format!(
            "smbclient failed for {}/{}: {detail}",
            loc.unc_share(),
            loc.path
        )));
    }

    let meta = std::fs::metadata(dest).map_err(|e| {
        RemoteError::Smb(format!(
            "smbclient reported success but {} missing: {e}",
            dest.display()
        ))
    })?;
    if meta.len() == 0 {
        // Empty file may be valid; only error if stderr hints at NT status issues.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.to_ascii_lowercase().contains("nt_status") {
            return Err(RemoteError::Smb(format!(
                "smbclient empty result for {}/{}: {}",
                loc.unc_share(),
                loc.path,
                stderr.trim()
            )));
        }
    }
    Ok(meta.len())
}

/// Error when the in-tree SMB 2.x client cannot speak the server dialect
/// and `smbclient` is not on `PATH`. Names the install hint **or** the dialect residual.
pub(crate) fn smb_fallback_clear_error(cause: &RemoteError) -> RemoteError {
    RemoteError::Smb(format!(
        "{cause}; install Samba client tools (e.g. `apt install smbclient` / \
         `dnf install samba-client`) to fetch smb:// URLs, or use an SMB 2.0.2/2.1 share"
    ))
}

fn is_smb_dialect_unsupported(err: &RemoteError) -> bool {
    let RemoteError::Smb(msg) = err else {
        return false;
    };
    let lower = msg.to_ascii_lowercase();
    // Auth / transport must not silently materialize via smbclient.
    if lower.contains("connect ")
        || lower.contains("resolve ")
        || lower.contains("logon_failure")
        || lower.contains("access_denied")
        || lower.contains("signing_required")
    {
        return false;
    }
    lower.contains("not_supported")
        || lower.contains("dialect")
        || lower.contains("not smb2")
        || lower.contains("smb2 header truncated")
        || lower.contains("direct tcp type")
        || lower.contains("smb frame length")
        || msg.contains(&format!("{STATUS_NOT_SUPPORTED:#010x}"))
}

/// URL userinfo, then `RATARMOUNT_SMB_USER` / `RATARMOUNT_SMB_PASSWORD`, else guest.
fn smb_credentials(loc: &SmbLocation) -> Option<(String, String, String)> {
    if let Some(user) = loc.user.as_deref() {
        let password = loc
            .password
            .clone()
            .or_else(|| std::env::var(SMB_PASSWORD_ENV).ok())
            .unwrap_or_default();
        let domain = loc.domain.clone().unwrap_or_default();
        return Some((user.to_string(), domain, password));
    }
    let password = std::env::var(SMB_PASSWORD_ENV).ok()?;
    let user = std::env::var(SMB_USER_ENV)
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "guest".into());
    let domain = loc.domain.clone().unwrap_or_default();
    Some((user, domain, password))
}

fn resolve_smb_addr(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| RemoteError::Smb(format!("SMB resolve {host}:{port} failed: {e}")))?
        .next()
        .ok_or_else(|| RemoteError::Smb(format!("SMB resolve {host}:{port}: no addresses")))
}

fn require_smb_file_path(loc: &SmbLocation) -> Result<()> {
    if loc.path.is_empty() {
        Err(RemoteError::Smb(
            "smb URL must include a file path under the share (smb://host/share/path/to/file)"
                .into(),
        ))
    } else {
        Ok(())
    }
}

enum SmbRangeInner {
    Live {
        client: Smb2Client<TcpStream>,
        file_id: [u8; 16],
    },
    Temp(NamedTempFile),
}

/// Seekable SMB reader using live SMB2 READ-at-offset when the dialect is 2.0.2/2.1.
///
/// Falls back to a tempfile from [`fetch_smb_to_temp`] when the server rejects the
/// in-tree dialect and `smbclient` is on `PATH`.
pub struct SmbRangeFile {
    loc: SmbLocation,
    size: u64,
    pos: u64,
    inner: SmbRangeInner,
}

impl std::fmt::Debug for SmbRangeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmbRangeFile")
            .field("host", &self.loc.host)
            .field("share", &self.loc.share)
            .field("path", &self.loc.path)
            .field("size", &self.size)
            .field("pos", &self.pos)
            .field("uses_ranges", &self.uses_ranges())
            .finish()
    }
}

impl SmbRangeFile {
    /// Open `smb://…`, using live SMB2 READ when the dialect is supported.
    pub fn open(url_str: &str) -> Result<Self> {
        let loc = parse_smb_url(url_str)?;
        Self::open_location(&loc)
    }

    /// Open a parsed location (see [`SmbRangeFile::open`]).
    pub fn open_location(loc: &SmbLocation) -> Result<Self> {
        Self::open_location_with(
            loc,
            find_smbclient().map(|_| run_smbclient_get as fn(&SmbLocation, &Path) -> Result<u64>),
        )
    }

    fn open_location_with<F>(loc: &SmbLocation, fallback: Option<F>) -> Result<Self>
    where
        F: FnOnce(&SmbLocation, &Path) -> Result<u64>,
    {
        require_smb_file_path(loc)?;
        match open_smb_live(loc) {
            Ok(f) => Ok(f),
            Err(e) if is_smb_dialect_unsupported(&e) => match fallback {
                Some(runner) => {
                    debug!("SMB dialect unsupported ({e}); falling back to smbclient");
                    open_smb_fallback_temp(loc, runner)
                }
                None => Err(smb_fallback_clear_error(&e)),
            },
            Err(e) => Err(e),
        }
    }

    pub fn location(&self) -> &SmbLocation {
        &self.loc
    }

    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// True when reads issue live SMB2 READ (not a tempfile from `smbclient`).
    pub fn uses_ranges(&self) -> bool {
        matches!(self.inner, SmbRangeInner::Live { .. })
    }
}

/// Open a seekable SMB reader using live Range READs when the dialect allows it.
///
/// Equivalent to [`SmbRangeFile::open`].
pub fn open_smb_range(url_str: &str) -> Result<SmbRangeFile> {
    SmbRangeFile::open(url_str)
}

fn connect_smb_tree(loc: &SmbLocation) -> Result<Smb2Client<TcpStream>> {
    let addr = resolve_smb_addr(&loc.host, loc.port)?;
    let mut client = Smb2Client::connect(addr)?;
    client.negotiate()?;
    match smb_credentials(loc) {
        Some((user, domain, password)) => {
            client.session_setup_ntlmv2(&user, &domain, &password)?;
        }
        None => client.session_setup_guest()?,
    }
    client.tree_connect(&loc.host, &loc.share)?;
    Ok(client)
}

fn smb_create_name(path: &str) -> String {
    path.replace('/', "\\").trim_matches('\\').to_string()
}

fn open_smb_live(loc: &SmbLocation) -> Result<SmbRangeFile> {
    let mut client = connect_smb_tree(loc)?;
    let name = smb_create_name(&loc.path);
    let open = client.create(&name)?;
    Ok(SmbRangeFile {
        loc: loc.clone(),
        size: open.end_of_file,
        pos: 0,
        inner: SmbRangeInner::Live {
            client,
            file_id: open.file_id,
        },
    })
}

/// Error when QUERY_DIRECTORY is unavailable. `smbclient` listing is residual.
fn smb_listing_clear_error(cause: &RemoteError) -> RemoteError {
    RemoteError::Smb(format!(
        "{cause}; QUERY_DIRECTORY requires SMB 2.0.2/2.1 (smbclient directory listing is residual). \
         install Samba client tools (e.g. `apt install smbclient` / `dnf install samba-client`) \
         or use an SMB 2.0.2/2.1 share"
    ))
}

fn map_smb_listing_err(err: RemoteError) -> RemoteError {
    if is_smb_dialect_unsupported(&err) {
        smb_listing_clear_error(&err)
    } else {
        err
    }
}

fn is_not_a_directory(err: &RemoteError) -> bool {
    let RemoteError::Smb(msg) = err else {
        return false;
    };
    msg.contains(&format!("{STATUS_NOT_A_DIRECTORY:#010x}"))
        || msg.to_ascii_lowercase().contains("not_a_directory")
}

fn is_missing_name(err: &RemoteError) -> bool {
    let RemoteError::Smb(msg) = err else {
        return false;
    };
    msg.contains(&format!("{STATUS_OBJECT_NAME_NOT_FOUND:#010x}"))
}

fn join_smb_child(parent: &str, name: &str) -> String {
    let parent = parent.trim_matches('/').trim_matches('\\');
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn list_smb_path(loc: &SmbLocation, remote_path: &str) -> Result<Vec<RemoteDirent>> {
    let mut client = connect_smb_tree(loc).map_err(map_smb_listing_err)?;
    let name = smb_create_name(remote_path);
    let ents = client.list_directory(&name).map_err(map_smb_listing_err)?;
    if ents.len() > QUERY_DIR_ENTRY_CAP {
        return Err(RemoteError::Smb(format!(
            "QUERY_DIRECTORY too large (>{QUERY_DIR_ENTRY_CAP} entries) for {remote_path}; \
             listing is not silently truncated"
        )));
    }
    Ok(ents
        .into_iter()
        .map(|e| RemoteDirent {
            remote_path: join_smb_child(remote_path, &e.name),
            name: e.name,
            is_dir: e.is_dir,
            size: e.size,
            mtime: e.mtime,
        })
        .collect())
}

/// Prefix listing backend for [`RemoteFolderMountSource`].
pub struct SmbListing {
    loc: SmbLocation,
}

impl SmbListing {
    pub fn new(loc: SmbLocation) -> Self {
        Self { loc }
    }
}

impl RemoteListing for SmbListing {
    fn list(&self, remote_path: &str) -> Result<Vec<RemoteDirent>> {
        list_smb_path(&self.loc, remote_path)
    }

    fn is_dir(&self, remote_path: &str) -> Result<bool> {
        if remote_path.is_empty() || remote_path.ends_with('/') || remote_path.ends_with('\\') {
            return Ok(true);
        }
        let mut client = connect_smb_tree(&self.loc).map_err(map_smb_listing_err)?;
        match client.create_dir(&smb_create_name(remote_path)) {
            Ok(open) => {
                client.close_and_shutdown(open.file_id);
                Ok(true)
            }
            Err(e) if is_not_a_directory(&e) || is_missing_name(&e) => Ok(false),
            Err(e) => Err(map_smb_listing_err(e)),
        }
    }

    fn open_range(&self, remote_path: &str, _size: u64) -> Result<Box<dyn ArchiveRead>> {
        let mut loc = self.loc.clone();
        loc.path = remote_path.trim_matches('/').replace('\\', "/");
        Ok(Box::new(SmbRangeFile::open_location(&loc)?))
    }
}

fn smb_url_looks_like_folder(url_str: &str, loc: &SmbLocation) -> bool {
    loc.path.is_empty() || loc.path.ends_with('/') || url_str.trim_end().ends_with('/')
}

/// Open `smb://host/share/` or `smb://host/share/dir/` as a folder.
///
/// `Ok(None)` if the path is a file (factory should fall through to [`open_smb_range`]),
/// including when the dialect is unsupported so smbclient Range fallback can run.
/// Folder URLs still `Err` on dialect / QUERY_DIRECTORY failure (not an empty listing).
pub fn open_smb_folder(url_str: &str) -> Result<Option<Arc<dyn MountSource>>> {
    let loc = parse_smb_url(url_str)?;
    let looks_like_folder = smb_url_looks_like_folder(url_str, &loc);
    match list_smb_path(&loc, loc.path.trim_end_matches('/')) {
        Ok(_) => {}
        Err(e)
            if !looks_like_folder
                && (is_not_a_directory(&e)
                    || is_missing_name(&e)
                    || is_smb_dialect_unsupported(&e)) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    }
    let root = loc.path.trim_end_matches('/').to_string();
    Ok(Some(Arc::new(RemoteFolderMountSource::new(
        root,
        SmbListing::new(loc),
    ))))
}

fn open_smb_fallback_temp<F>(loc: &SmbLocation, runner: F) -> Result<SmbRangeFile>
where
    F: FnOnce(&SmbLocation, &Path) -> Result<u64>,
{
    let (mut tmp, size) = fetch_smb_location_to_temp_with(loc, runner)?;
    tmp.as_file_mut().seek(SeekFrom::Start(0))?;
    Ok(SmbRangeFile {
        loc: loc.clone(),
        size,
        pos: 0,
        inner: SmbRangeInner::Temp(tmp),
    })
}

impl Read for SmbRangeFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        match &mut self.inner {
            SmbRangeInner::Temp(tmp) => {
                tmp.as_file_mut().seek(SeekFrom::Start(self.pos))?;
                let n = tmp.as_file_mut().read(buf)?;
                self.pos += n as u64;
                Ok(n)
            }
            SmbRangeInner::Live { client, file_id } => {
                let file_id = *file_id;
                let cap = client.max_read_size().max(1);
                let want = ((self.size - self.pos) as usize).min(buf.len());
                let mut filled = 0;
                while filled < want {
                    let remaining = want - filled;
                    let length = remaining.min(cap as usize) as u32;
                    let chunk = client
                        .read_at(file_id, self.pos, length)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    if chunk.is_empty() {
                        break;
                    }
                    let n = chunk.len().min(remaining);
                    buf[filled..filled + n].copy_from_slice(&chunk[..n]);
                    filled += n;
                    self.pos += n as u64;
                    if self.pos >= self.size {
                        break;
                    }
                }
                Ok(filled)
            }
        }
    }
}

impl Seek for SmbRangeFile {
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

impl Drop for SmbRangeFile {
    fn drop(&mut self) {
        if let SmbRangeInner::Live { client, file_id } = &mut self.inner {
            client.close_and_shutdown(*file_id);
        }
    }
}

/// Redact `user%password` after `-U` for logs.
fn redact_smbclient_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for a in args {
        if redact_next {
            if let Some((u, _)) = a.split_once('%') {
                out.push(format!("{u}%***"));
            } else {
                out.push("***".into());
            }
            redact_next = false;
        } else {
            redact_next = a == "-U";
            out.push(a.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn parse_basic() {
        let loc = parse_smb_url("smb://fileserver/backups/archives/a.tar").unwrap();
        assert_eq!(loc.host, "fileserver");
        assert_eq!(loc.port, 445);
        assert_eq!(loc.share, "backups");
        assert_eq!(loc.path, "archives/a.tar");
        assert!(loc.user.is_none());
        assert!(loc.password.is_none());
        assert!(loc.domain.is_none());
        assert_eq!(loc.unc_share(), "//fileserver/backups");
    }

    #[test]
    fn parse_auth_port_and_domain_semicolon() {
        let loc = parse_smb_url("smb://CORP;alice:s3cret@nas.example:1445/data/iso/x.iso").unwrap();
        assert_eq!(loc.host, "nas.example");
        assert_eq!(loc.port, 1445);
        assert_eq!(loc.share, "data");
        assert_eq!(loc.path, "iso/x.iso");
        assert_eq!(loc.user.as_deref(), Some("alice"));
        assert_eq!(loc.password.as_deref(), Some("s3cret"));
        assert_eq!(loc.domain.as_deref(), Some("CORP"));
    }

    #[test]
    fn parse_domain_backslash() {
        // url crate: backslash in userinfo may need encoding; percent-encoded works.
        let loc = parse_smb_url("smb://CORP%5Cbob:pw@host/share/f.bin").unwrap();
        assert_eq!(loc.user.as_deref(), Some("bob"));
        assert_eq!(loc.domain.as_deref(), Some("CORP"));
        assert_eq!(loc.password.as_deref(), Some("pw"));
        assert_eq!(loc.share, "share");
        assert_eq!(loc.path, "f.bin");
    }

    #[test]
    fn parse_share_only_path_empty() {
        let loc = parse_smb_url("smb://host/myshare").unwrap();
        assert_eq!(loc.share, "myshare");
        assert!(loc.path.is_empty());
    }

    #[test]
    fn parse_rejects_missing_share() {
        let err = parse_smb_url("smb://hostonly").unwrap_err();
        assert!(err.to_string().contains("share") || err.to_string().contains("url"));
    }

    #[test]
    fn parse_rejects_other_scheme() {
        let err = parse_smb_url("http://x/y").unwrap_err();
        assert!(matches!(err, RemoteError::UnsupportedScheme(_)));
    }

    #[test]
    fn smbclient_args_with_auth() {
        let loc = SmbLocation {
            host: "h".into(),
            port: 445,
            share: "s".into(),
            path: "dir/file.tar".into(),
            user: Some("u".into()),
            password: Some("p".into()),
            domain: Some("D".into()),
        };
        let dest = Path::new("/tmp/out.bin");
        let args = smbclient_download_args(&loc, dest);
        assert_eq!(args[0], "//h/s");
        assert!(args.contains(&"-p".into()));
        assert!(args.contains(&"445".into()));
        assert!(args.contains(&"-U".into()));
        assert!(args.contains(&"u%p".into()));
        assert!(args.contains(&"-W".into()));
        assert!(args.contains(&"D".into()));
        assert!(args.contains(&"-c".into()));
        let c = args.iter().position(|a| a == "-c").unwrap();
        assert!(args[c + 1].contains("get "));
        assert!(args[c + 1].contains("dir/file.tar"));
        assert!(args[c + 1].contains("/tmp/out.bin"));
        // Guest -N should not appear when -U is used.
        assert!(!args.iter().any(|a| a == "-N"));
    }

    #[test]
    fn smbclient_args_guest() {
        let loc = SmbLocation {
            host: "h".into(),
            port: 445,
            share: "pub".into(),
            path: "a.tar".into(),
            user: None,
            password: None,
            domain: None,
        };
        let args = smbclient_download_args(&loc, Path::new("/tmp/x"));
        assert!(args.contains(&"-N".into()));
        assert!(!args.contains(&"-U".into()));
    }

    #[test]
    fn fetch_with_mock_runner() {
        let loc = parse_smb_url("smb://mockhost/share/nested/a.tar").unwrap();
        let body = b"smb-mock-file-body";
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let (tmp, size) = fetch_smb_location_to_temp_with(&loc, move |l, dest| {
            calls2.fetch_add(1, Ordering::SeqCst);
            assert_eq!(l.share, "share");
            assert_eq!(l.path, "nested/a.tar");
            // Mimic smbclient: write through a fresh open of the dest path.
            std::fs::write(dest, body).map_err(RemoteError::Io)?;
            Ok(body.len() as u64)
        })
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(size, body.len() as u64);
        let from_path = std::fs::read(tmp.path()).unwrap();
        assert_eq!(from_path, body);
    }

    #[test]
    fn redact_hides_password() {
        let redacted = redact_smbclient_args(&[
            "//h/s".into(),
            "-U".into(),
            "alice:s3cret".into(), // no % form
            "-U".into(),
            "alice%s3cret".into(),
        ]);
        assert_eq!(redacted[2], "***");
        assert_eq!(redacted[4], "alice%***");
    }

    #[test]
    fn fetch_rejects_empty_file_path() {
        let loc = parse_smb_url("smb://host/shareonly").unwrap();
        let err = fetch_smb_location_to_temp_with(&loc, |_l, _d| Ok(0)).unwrap_err();
        assert!(err.to_string().contains("file path") || err.to_string().contains("smb"));
    }

    #[test]
    fn missing_smbclient_error_is_clear() {
        // Only run the real runner check if smbclient is truly absent; otherwise
        // skip the "not found" assertion (CI may have samba-client installed).
        if find_smbclient().is_some() {
            return;
        }
        let loc = parse_smb_url("smb://no-such-host.invalid/share/a.tar").unwrap();
        let err = run_smbclient_get(&loc, Path::new("/tmp/ratarmount-smb-test-dest")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("smbclient") && (msg.contains("install") || msg.contains("not found")),
            "unexpected message: {msg}"
        );
    }

    fn fake_smb_url(port: u16) -> String {
        format!(
            "smb://127.0.0.1:{port}/{}/{}",
            crate::smb2_client::tests::SHARE,
            crate::smb2_client::tests::FILE_NAME
        )
    }

    fn no_smbclient_runner() -> Option<fn(&SmbLocation, &Path) -> Result<u64>> {
        None
    }

    fn open_smb_range_without_smbclient(url: &str) -> Result<SmbRangeFile> {
        let loc = parse_smb_url(url)?;
        SmbRangeFile::open_location_with(&loc, no_smbclient_runner())
    }

    /// Direct-TCP NBSS frame whose payload is SMB1 magic (`0xffSMB`), not SMB2.
    fn spawn_smb1_banner() -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind smb1 banner");
        let port = listener.local_addr().expect("addr").port();
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut payload = vec![0xff, b'S', b'M', b'B'];
                payload.resize(64, 0);
                let n = payload.len();
                let mut framed = vec![
                    0,
                    ((n >> 16) & 0xff) as u8,
                    ((n >> 8) & 0xff) as u8,
                    (n & 0xff) as u8,
                ];
                framed.extend_from_slice(&payload);
                let _ = stream.write_all(&framed);
            }
        });
        (port, handle)
    }

    fn assert_send<T: Send>() {}

    #[test]
    fn smb_range_file_is_send() {
        assert_send::<SmbRangeFile>();
    }

    /// Regression: READ at offset 1 MiB issues SMB2 READ(s) at that offset, not a from-0 GET.
    #[test]
    fn smb_range_read_at_one_mib_issues_read_at_offset() {
        use crate::smb2_client::tests::{AuthMode, FakeSmb, OFFSET_1MIB, TAIL};
        let srv = FakeSmb::spawn(AuthMode::Guest);
        let url = fake_smb_url(srv.addr.port());
        let mut f = open_smb_range(&url).expect("open live SMB range");
        assert!(
            f.uses_ranges(),
            "expected live SMB2 READ, not smbclient temp"
        );
        assert_eq!(f.len(), OFFSET_1MIB + TAIL.len() as u64);
        f.seek(SeekFrom::Start(OFFSET_1MIB)).unwrap();
        let mut buf = vec![0u8; TAIL.len()];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(buf, TAIL);
        let stats = srv.stats();
        assert!(
            !stats.reads.is_empty(),
            "live Range must issue at least one READ"
        );
        assert!(
            stats.reads.iter().all(|(off, _)| *off >= OFFSET_1MIB),
            "READs must start at 1 MiB, not a prefix GET: {:?}",
            stats.reads
        );
        assert_eq!(stats.reads[0], (OFFSET_1MIB, TAIL.len() as u32));
    }

    /// Regression: short SUCCESS (request 32, reply 16) then remaining bytes is not EOF.
    #[test]
    fn smb_range_short_success_fill_loop_is_not_eof() {
        use crate::smb2_client::tests::{FakeOpts, FakeSmb, HEAD};
        let mut opts = FakeOpts::guest();
        opts.read_data_cap = Some(16);
        let srv = FakeSmb::spawn_with(opts);
        let url = fake_smb_url(srv.addr.port());
        let mut f = open_smb_range(&url).expect("open live SMB range");
        let mut buf = [0u8; 32];
        let n = f.read(&mut buf).expect("fill-loop read");
        assert_eq!(n, 32, "short SUCCESS must continue until 32 bytes, not EOF");
        assert_eq!(&buf[..HEAD.len()], HEAD);
        let stats = srv.stats();
        assert!(
            stats.reads.len() >= 2,
            "fill-loop must issue a second READ after short SUCCESS: {:?}",
            stats.reads
        );
        assert_eq!(stats.reads[0], (0, 32));
        assert_eq!(stats.reads[1].0, 16);
    }

    #[test]
    fn smb_range_ntlmv2_read_at_one_mib() {
        use crate::smb2_client::tests::{AuthMode, FakeSmb, FILE_NAME, OFFSET_1MIB, SHARE, TAIL};
        let srv = FakeSmb::spawn(AuthMode::Password {
            user: "alice".into(),
            domain: "CORP".into(),
            password: "s3cret".into(),
        });
        let url = format!(
            "smb://CORP;alice:s3cret@127.0.0.1:{}/{}/{}",
            srv.addr.port(),
            SHARE,
            FILE_NAME
        );
        let mut f = open_smb_range(&url).expect("NTLMv2 live range");
        assert!(f.uses_ranges());
        f.seek(SeekFrom::Start(OFFSET_1MIB)).unwrap();
        let mut buf = vec![0u8; TAIL.len()];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(buf, TAIL);
        assert_eq!(srv.stats().reads[0].0, OFFSET_1MIB);
    }

    #[test]
    fn smb_fallback_clear_error_message_names_install_or_dialect() {
        let cause = RemoteError::Smb(format!(
            "NEGOTIATE NTSTATUS {STATUS_NOT_SUPPORTED:#010x} (NOT_SUPPORTED)"
        ));
        let err = smb_fallback_clear_error(&cause);
        let msg = err.to_string();
        let lower = msg.to_ascii_lowercase();
        assert!(
            lower.contains("smbclient") && lower.contains("install"),
            "{msg}"
        );
        assert!(
            lower.contains("dialect") || lower.contains("not_supported") || lower.contains("2.0.2"),
            "{msg}"
        );
    }

    /// Dialect STATUS_NOT_SUPPORTED + no smbclient → clear error (install or dialect).
    #[test]
    fn smb_fallback_clear_error_without_smbclient() {
        use crate::smb2_client::tests::{AuthMode, FakeSmb};
        let srv = FakeSmb::spawn(AuthMode::RejectDialect);
        let url = fake_smb_url(srv.addr.port());
        let err = open_smb_range_without_smbclient(&url).unwrap_err();
        let msg = err.to_string();
        let lower = msg.to_ascii_lowercase();
        assert!(
            lower.contains("smbclient") && lower.contains("install"),
            "{msg}"
        );
        assert!(
            lower.contains("dialect") || lower.contains("not_supported") || lower.contains("2.0.2"),
            "{msg}"
        );
    }

    #[test]
    fn smb_range_rejects_empty_file_path() {
        let err = open_smb_range("smb://host/shareonly").unwrap_err();
        assert!(err.to_string().contains("file path") || err.to_string().contains("smb"));
    }

    #[test]
    fn smb_range_dialect_matcher_keeps_auth_and_connect_out() {
        assert!(is_smb_dialect_unsupported(&RemoteError::Smb(
            "not SMB2".into()
        )));
        assert!(is_smb_dialect_unsupported(&RemoteError::Smb(
            "SMB2 header truncated".into()
        )));
        assert!(is_smb_dialect_unsupported(&RemoteError::Smb(
            "SMB Direct TCP type must be 0".into()
        )));
        assert!(is_smb_dialect_unsupported(&RemoteError::Smb(
            "NEGOTIATE: unsupported dialect 0x0300 (need 2.0.2/2.1)".into()
        )));
        assert!(is_smb_dialect_unsupported(&RemoteError::Smb(format!(
            "NEGOTIATE NTSTATUS {STATUS_NOT_SUPPORTED:#010x} (NOT_SUPPORTED)"
        ))));
        assert!(!is_smb_dialect_unsupported(&RemoteError::Smb(
            "SMB connect 127.0.0.1:445 failed: Connection refused".into()
        )));
        assert!(!is_smb_dialect_unsupported(&RemoteError::Smb(
            "SESSION_SETUP Type3 (NTLMv2) NTSTATUS 0xc000006d (LOGON_FAILURE)".into()
        )));
        assert!(!is_smb_dialect_unsupported(&RemoteError::Smb(
            "NEGOTIATE SIGNING_REQUIRED; guest session is unsigned — use NTLMv2".into()
        )));
    }

    /// Regression: non-SMB2 banner is dialect residual (falls back / clear error), not a hard fail.
    #[test]
    fn smb_fallback_clear_error_non_smb2_banner() {
        let (port, handle) = spawn_smb1_banner();
        let url = format!("smb://127.0.0.1:{port}/data/payload.bin");
        let err = open_smb_range_without_smbclient(&url).unwrap_err();
        let _ = handle.join();
        let msg = err.to_string();
        let lower = msg.to_ascii_lowercase();
        assert!(
            lower.contains("smbclient") && lower.contains("install"),
            "{msg}"
        );
        assert!(
            lower.contains("not smb2") || lower.contains("dialect") || lower.contains("2.0.2"),
            "{msg}"
        );
    }

    /// Dialect STATUS_NOT_SUPPORTED with a stub smbclient runner materializes tempfile Range.
    #[test]
    fn smb_range_fallback_temp_when_dialect_unsupported() {
        use crate::smb2_client::tests::{AuthMode, FakeSmb};
        let srv = FakeSmb::spawn(AuthMode::RejectDialect);
        let url = fake_smb_url(srv.addr.port());
        let loc = parse_smb_url(&url).unwrap();
        let body = b"smbclient-fallback-body";
        let mut f = SmbRangeFile::open_location_with(
            &loc,
            Some(|_l: &SmbLocation, dest: &Path| {
                std::fs::write(dest, body).map_err(RemoteError::Io)?;
                Ok(body.len() as u64)
            }),
        )
        .expect("dialect residual should use stub smbclient");
        assert!(
            !f.uses_ranges(),
            "fallback must be tempfile mode, not live READ"
        );
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, body);
        assert!(
            srv.stats().reads.is_empty(),
            "live READ must not run after dialect reject: {:?}",
            srv.stats().reads
        );
    }

    #[test]
    fn smb_range_connect_refused_does_not_fallback() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = format!("smb://127.0.0.1:{port}/data/payload.bin");
        let loc = parse_smb_url(&url).unwrap();
        let called = AtomicBool::new(false);
        let err = SmbRangeFile::open_location_with(
            &loc,
            Some(|_l: &SmbLocation, dest: &Path| {
                called.store(true, Ordering::SeqCst);
                std::fs::write(dest, b"should-not-run").map_err(RemoteError::Io)?;
                Ok(0)
            }),
        )
        .unwrap_err();
        assert!(
            !called.load(Ordering::SeqCst),
            "connect refused must not invoke smbclient fallback"
        );
        let msg = err.to_string();
        assert!(
            msg.to_ascii_lowercase().contains("connect"),
            "unexpected: {msg}"
        );
    }

    fn fake_smb_share_url(port: u16) -> String {
        format!(
            "smb://127.0.0.1:{port}/{}/",
            crate::smb2_client::tests::SHARE
        )
    }

    /// RemoteFolderMountSource list_dirents carries Depth-1 names + sizes.
    #[test]
    fn smb_folder_mountsource_list_dirents() {
        use crate::smb2_client::tests::{
            AuthMode, FakeSmb, DIR_FILE_A, DIR_FILE_A_BODY, DIR_SUB, FILE_NAME, OFFSET_1MIB, TAIL,
        };
        let srv = FakeSmb::spawn(AuthMode::Guest);
        let url = fake_smb_share_url(srv.addr.port());
        let ms = open_smb_folder(&url)
            .expect("open folder")
            .expect("share URL should mount as folder");
        let dents = ms.list_dirents("/").expect("dirents");
        assert!(
            dents
                .iter()
                .any(|d| d.name == DIR_FILE_A && d.size == DIR_FILE_A_BODY.len() as u64),
            "{dents:?}"
        );
        assert!(
            dents
                .iter()
                .any(|d| d.name == FILE_NAME && d.size == OFFSET_1MIB + TAIL.len() as u64),
            "{dents:?}"
        );
        assert!(dents.iter().any(|d| d.name == DIR_SUB), "{dents:?}");
        assert!(!dents.iter().any(|d| d.name == "." || d.name == ".."));
        assert!(
            !dents.iter().any(|d| d.name == "nested.bin"),
            "Depth-1 must not leak nested names: {dents:?}"
        );
        let sub = ms.list_dirents("/sub").expect("subdir dirents");
        assert!(
            sub.iter().any(|d| d.name == "nested.bin" && d.size == 4),
            "{sub:?}"
        );
    }

    #[test]
    fn smb_folder_mountsource_open_range_child() {
        use crate::smb2_client::tests::{AuthMode, FakeSmb, DIR_FILE_A, DIR_FILE_A_BODY};
        let srv = FakeSmb::spawn(AuthMode::Guest);
        let url = fake_smb_share_url(srv.addr.port());
        let ms = open_smb_folder(&url).unwrap().expect("folder");
        let fi = ms
            .lookup(&format!("/{DIR_FILE_A}"), 0)
            .expect("lookup a.tar");
        assert_eq!(fi.size, DIR_FILE_A_BODY.len() as u64);
        let mut r = ms.open(&fi, 0).expect("open child Range");
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, DIR_FILE_A_BODY);
    }

    #[test]
    fn smb_folder_file_url_is_none() {
        use crate::smb2_client::tests::{AuthMode, FakeSmb, FILE_NAME, SHARE};
        let srv = FakeSmb::spawn(AuthMode::Guest);
        let url = format!(
            "smb://127.0.0.1:{}/{}/{}",
            srv.addr.port(),
            SHARE,
            FILE_NAME
        );
        assert!(
            open_smb_folder(&url).unwrap().is_none(),
            "file URL must return Ok(None) so Range can take over"
        );
    }

    /// File URL + unsupported dialect is Ok(None) so PR 4 can reach smbclient Range.
    #[test]
    fn smb_folder_file_url_dialect_unsupported_is_none() {
        use crate::smb2_client::tests::{AuthMode, FakeSmb, FILE_NAME, SHARE};
        let srv = FakeSmb::spawn(AuthMode::RejectDialect);
        let url = format!(
            "smb://127.0.0.1:{}/{}/{}",
            srv.addr.port(),
            SHARE,
            FILE_NAME
        );
        assert!(
            open_smb_folder(&url).unwrap().is_none(),
            "file URL dialect miss must be Ok(None), not Err that skips Range fallback"
        );
    }

    #[test]
    fn smb_folder_dialect_unsupported_is_clear_error() {
        use crate::smb2_client::tests::{AuthMode, FakeSmb};
        let srv = FakeSmb::spawn(AuthMode::RejectDialect);
        let url = fake_smb_share_url(srv.addr.port());
        let err = match open_smb_folder(&url) {
            Err(e) => e,
            Ok(_) => panic!("dialect residual must be Err, not Ok(None) or a folder"),
        };
        let msg = err.to_string();
        let lower = msg.to_ascii_lowercase();
        assert!(
            lower.contains("smbclient") && lower.contains("install"),
            "{msg}"
        );
        assert!(
            lower.contains("dialect")
                || lower.contains("not_supported")
                || lower.contains("2.0.2")
                || lower.contains("query_directory"),
            "{msg}"
        );
    }

    #[test]
    fn smb_folder_query_directory_unsupported_is_not_empty_list() {
        use crate::smb2_client::tests::{FakeOpts, FakeSmb};
        let mut opts = FakeOpts::guest();
        opts.reject_query_directory = true;
        let srv = FakeSmb::spawn_with(opts);
        let url = fake_smb_share_url(srv.addr.port());
        let err = match open_smb_folder(&url) {
            Err(e) => e,
            Ok(_) => panic!("QUERY_DIRECTORY unsupported must be Err, not an empty folder"),
        };
        let msg = err.to_string();
        let lower = msg.to_ascii_lowercase();
        assert!(
            lower.contains("not_supported")
                || lower.contains("query_directory")
                || lower.contains("dialect")
                || msg.contains(&format!("{STATUS_NOT_SUPPORTED:#010x}")),
            "{msg}"
        );
        assert!(
            lower.contains("residual") || lower.contains("smbclient") || lower.contains("install"),
            "must name install/dialect residual, not return empty: {msg}"
        );
    }
}
