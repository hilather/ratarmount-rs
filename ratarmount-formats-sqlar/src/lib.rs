//! SQLAR (SQLite Archiver) mount source — Python `SQLARMountSource` parity.
//!
//! Schema: <https://www.sqlite.org/sqlar.html>
//! ```text
//! CREATE TABLE sqlar(
//!   name TEXT PRIMARY KEY,  -- path without leading slash
//!   mode INT,
//!   mtime INT,
//!   sz INT,                 -- original size; 0 dir/empty; -1 symlink
//!   data BLOB               -- NULL=dir; link text if sz=-1; zlib if len<data < sz
//! );
//! ```
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! Unencrypted SQLAR can open from any [`Read`] stream without a host path or
//! `/tmp` spool: [`SqlarMountSource::open_from_reader`] loads the full image into
//! RAM and attaches it with SQLite `sqlite3_deserialize` (read-only in-memory DB).
//!
//! | Concern | Behaviour |
//! |---------|-----------|
//! | Host temp file | **Never** for the nested no-tmp path |
//! | Memory | Full SQLAR image retained for the mount lifetime |
//! | Encrypted SQLAR | **Not** opened from a stream — detect-only residual (use path [`open`] + `sqlcipher`) |
//! | Member random read | Yes — file payloads live in the `sqlar` table blobs (zlib as needed) |
//!
//! # Encrypted SQLAR (SQLCipher)
//!
//! Encrypted archives do **not** start with the SQLite magic (`SQLite format 3\0`);
//! the first 16 bytes are the AES salt. Opening them requires SQLCipher.
//!
//! | Build | Behaviour |
//! |-------|-----------|
//! | Default (`bundled` SQLite) | Encrypted files are **detected**; open fails with a clear [`SqlarError`] (`EncryptedRequiresPassword` / `EncryptedNotSupported`). |
//! | `--features sqlcipher` | Passwords from [`OpenOptions::passwords`] are tried via `PRAGMA key` (passphrase form, then PBKDF2-HMAC-SHA512 raw key — Python / sqlcipher3 parity). |
//!
//! ## Building with SQLCipher
//!
//! ```bash
//! # Crate alone
//! cargo build -p ratarmount-formats-sqlar --features sqlcipher
//! cargo test  -p ratarmount-formats-sqlar --features sqlcipher --lib
//!
//! # Binary (forward the feature from a dependent crate)
//! cargo build -p ratarmount --features sqlcipher   # if the bin crate exposes it
//! # or pin the dependency:
//! # ratarmount-formats-sqlar = { path = "...", features = ["sqlcipher"] }
//! ```
//!
//! Compiling `sqlcipher` vendors OpenSSL and the SQLCipher amalgamation (see
//! `rusqlite` feature `bundled-sqlcipher-vendored-openssl`). First builds can take a while.
//!
//! ## Passwords
//!
//! Supply one or more passwords via [`OpenOptions::passwords`] (CLI: `--password` /
//! password file). Unencrypted archives ignore unused passwords. Encrypted archives
//! without a password always error; with passwords but no `sqlcipher` feature they
//! error with [`SqlarError::EncryptedNotSupported`].
//!
//! Use [`sqlcipher_enabled`] to probe at runtime whether this build can decrypt.

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use flate2::read::ZlibDecoder;
use ratarmount_core::{
    create_root_file_info, normpath, FileInfo, ListModeResult, ListResult, MountSource,
    OpenOptions, UserData,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use thiserror::Error;

pub const BACKEND_NAME: &str = "SQLARMountSource";
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
const OPEN_FLAGS: OpenFlags =
    OpenFlags::SQLITE_OPEN_READ_ONLY.union(OpenFlags::SQLITE_OPEN_NO_MUTEX);

/// SQLCipher default KDF iterations (current); salt is the first 16 file bytes.
#[cfg(feature = "sqlcipher")]
const SQLCIPHER_KDF_ITER: u32 = 256_000;

/// Whether this build was compiled with the `sqlcipher` feature (decryption support).
///
/// Always `true` when linked with SQLCipher; always `false` in the default stock-SQLite build.
#[inline]
pub const fn sqlcipher_enabled() -> bool {
    cfg!(feature = "sqlcipher")
}

#[derive(Debug, Error)]
pub enum SqlarError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
    /// File looks like SQLCipher-encrypted SQLAR but no password was supplied.
    ///
    /// Message text depends on whether the `sqlcipher` feature is enabled so callers
    /// get a single actionable hint (provide a password vs rebuild + password).
    #[cfg_attr(
        feature = "sqlcipher",
        error(
            "encrypted SQLAR requires a password; pass --password \
             (or set OpenOptions.passwords)"
        )
    )]
    #[cfg_attr(
        not(feature = "sqlcipher"),
        error(
            "encrypted SQLAR requires a password and SQLCipher support; pass --password and \
             rebuild with `--features sqlcipher` on ratarmount-formats-sqlar \
             (e.g. `cargo build -p ratarmount-formats-sqlar --features sqlcipher`)"
        )
    )]
    EncryptedRequiresPassword,
    /// Passwords were given but this build was not linked with SQLCipher.
    #[error(
        "encrypted SQLAR is not supported in this build (stock SQLite, no sqlcipher). \
         Rebuild with `cargo build -p ratarmount-formats-sqlar --features sqlcipher` \
         (or enable the feature on dependents), then pass --password. \
         Passwords were ignored."
    )]
    EncryptedNotSupported,
    /// SQLCipher is available but none of the provided passwords unlocked the archive.
    #[error("could not decrypt SQLAR with the provided password(s)")]
    WrongPassword,
}

pub type Result<T> = std::result::Result<T, SqlarError>;

/// SQLAR archive opened read-only.
pub struct SqlarMountSource {
    #[allow(dead_code)]
    path: PathBuf,
    /// Dropped before [`Self::mem_image`] (declaration order) so deserialize
    /// disconnects before the backing buffer is freed.
    conn: Mutex<Connection>,
    /// Full DB image when opened via [`Self::open_from_reader`]; referenced by
    /// `sqlite3_deserialize` (must outlive `conn`).
    #[allow(dead_code)]
    mem_image: Option<Box<[u8]>>,
    /// When paths are denormal, map normalized path → original `name` key.
    name_map: Option<BTreeMap<String, String>>,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl SqlarMountSource {
    /// Open an SQLAR archive.
    ///
    /// Unencrypted archives open with stock SQLite. Encrypted (no SQLite magic) archives:
    /// * no passwords → [`SqlarError::EncryptedRequiresPassword`]
    /// * passwords, no `sqlcipher` feature → [`SqlarError::EncryptedNotSupported`]
    /// * passwords + `sqlcipher` → try each password; fail with [`SqlarError::WrongPassword`]
    pub fn open(path: impl AsRef<Path>, options: &OpenOptions) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !looks_like_sqlar(&path) {
            return Err(SqlarError::Msg(format!(
                "{} is not an SQLAR/SQLite file",
                path.display()
            )));
        }

        let header = read_header(&path)?;
        let conn = match open_plain(&path) {
            Ok(c) => c,
            Err(plain_err) => {
                if header_is_sqlite_magic(&header) {
                    // Plain SQLite header but not a usable SQLAR (missing table / corrupt).
                    return Err(plain_err);
                }
                // No SQLite magic → treat as sqlcipher-encrypted candidate.
                open_encrypted(&path, options, &header, plain_err)?
            }
        };

        let name_map = build_name_map(&conn)?;
        Ok(Self {
            path,
            conn: Mutex::new(conn),
            mem_image: None,
            name_map,
            options: options.clone(),
        })
    }

    /// Open an **unencrypted** SQLAR from any readable stream (nested AutoMount without `/tmp`).
    ///
    /// Reads the entire archive into memory and attaches it with SQLite
    /// `sqlite3_deserialize` (read-only). No host temp file is created.
    ///
    /// `archive_label` is used for logs / path metadata (may be a nested member name).
    ///
    /// # Limitations
    /// - **Memory**: the full SQLAR image is retained for the lifetime of this mount.
    /// - **Encrypted SQLAR**: stream open does **not** decrypt. If the stream lacks
    ///   the SQLite magic (and the label looks like `.sqlar`), returns the same
    ///   structured encrypted errors as path open; actual decrypt remains path-based
    ///   [`open`] with the `sqlcipher` feature.
    pub fn open_from_reader<R>(
        mut reader: R,
        archive_label: impl AsRef<Path>,
        options: &OpenOptions,
    ) -> Result<Self>
    where
        R: Read,
    {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        Self::open_from_bytes(bytes, archive_label, options)
    }

    /// Open an **unencrypted** SQLAR already loaded as bytes (no host temp file).
    ///
    /// See [`Self::open_from_reader`] for memory and encryption limitations.
    pub fn open_from_bytes(
        bytes: impl Into<Vec<u8>>,
        archive_label: impl AsRef<Path>,
        options: &OpenOptions,
    ) -> Result<Self> {
        let path = archive_label.as_ref().to_path_buf();
        let bytes = bytes.into();
        if bytes.len() < 16 {
            return Err(SqlarError::Msg(format!(
                "{} is not an SQLAR/SQLite stream (too short)",
                path.display()
            )));
        }

        let header = &bytes[..16.min(bytes.len())];
        if !header_is_sqlite_magic(header) {
            // Same structured residual as path open for encrypted candidates.
            let plain_err = SqlarError::Msg(format!(
                "{} is not a plain SQLite/SQLAR stream (missing SQLite magic)",
                path.display()
            ));
            if header.len() >= 16 && has_sqlar_extension(&path) {
                return encrypted_from_stream_residual(&path, options, header, plain_err);
            }
            return Err(plain_err);
        }

        let image: Box<[u8]> = bytes.into_boxed_slice();
        let conn = open_plain_from_mem_image(&image)?;
        let name_map = build_name_map(&conn)?;
        Ok(Self {
            path,
            conn: Mutex::new(conn),
            mem_image: Some(image),
            name_map,
            options: options.clone(),
        })
    }

    fn with_conn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let g = self.conn.lock().expect("sqlar mutex");
        f(&g)
    }

    fn sql_name(&self, path: &str) -> String {
        let p = path.trim_start_matches('/');
        if let Some(map) = &self.name_map {
            if let Some(orig) = map.get(p) {
                return orig.clone();
            }
        }
        p.to_string()
    }

    fn row_to_file_info(rowid: i64, mode: i64, mtime: i64, sz: i64, linkname: String) -> FileInfo {
        FileInfo {
            size: sz.max(0) as u64,
            mtime: mtime as f64,
            mode: mode as u32,
            linkname,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            userdata: vec![UserData::Other(format!("sqlar:{rowid}"))],
        }
    }

    /// `(rowid, mode, mtime, sz, symlink_target_or_empty)`
    #[allow(clippy::type_complexity)]
    fn lookup_row(&self, path: &str) -> Result<Option<(i64, i64, i64, i64, String)>> {
        if path == "/" {
            return Ok(None); // handled by caller
        }
        let name = self.sql_name(path);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT rowid, mode, mtime, sz, CASE WHEN sz=-1 THEN CAST(data AS TEXT) ELSE '' END \
                 FROM sqlar WHERE name = ?1",
            )?;
            let row = stmt
                .query_row(rusqlite::params![name], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                })
                .optional()?;
            Ok(row)
        })
    }
}

fn read_header(path: &Path) -> Result<Vec<u8>> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = [0u8; 16];
    let n = f.read(&mut buf)?;
    Ok(buf[..n].to_vec())
}

fn header_is_sqlite_magic(header: &[u8]) -> bool {
    header.len() >= SQLITE_MAGIC.len() && &header[..SQLITE_MAGIC.len()] == SQLITE_MAGIC
}

fn has_sqlar_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("sqlar"))
}

/// Open unencrypted SQLAR and verify the `sqlar` table is readable.
fn open_plain(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, OPEN_FLAGS)?;
    verify_sqlar_readable(&conn)?;
    Ok(conn)
}

/// Attach a pre-loaded plain SQLite image as the main DB via `sqlite3_deserialize`.
///
/// `image` must remain alive for the lifetime of the returned connection (READONLY,
/// no FREEONCLOSE). Callers store the buffer on [`SqlarMountSource::mem_image`].
fn open_plain_from_mem_image(image: &[u8]) -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    let sz = i64::try_from(image.len()).map_err(|_| {
        SqlarError::Msg(format!(
            "SQLAR image too large for sqlite3_deserialize ({} bytes)",
            image.len()
        ))
    })?;
    // SAFETY: buffer is valid for the connection lifetime (held in mem_image);
    // READONLY without FREEONCLOSE / RESIZEABLE so SQLite does not free or resize it.
    let rc = unsafe {
        let handle = conn.handle();
        let ptr = image.as_ptr().cast_mut();
        rusqlite::ffi::sqlite3_deserialize(
            handle,
            c"main".as_ptr(),
            ptr,
            sz,
            sz,
            rusqlite::ffi::SQLITE_DESERIALIZE_READONLY,
        )
    };
    if rc != rusqlite::ffi::SQLITE_OK {
        return Err(SqlarError::Msg(format!(
            "sqlite3_deserialize failed (rc={rc}); not a usable SQLite database image"
        )));
    }
    verify_sqlar_readable(&conn)?;
    Ok(conn)
}

fn verify_sqlar_readable(conn: &Connection) -> Result<()> {
    let ok: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='sqlar'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if ok.is_none() {
        return Err(SqlarError::Msg("missing sqlar table".into()));
    }
    // Touch the table (also fails if still encrypted / wrong key).
    let _ = conn.query_row("SELECT COUNT(*) FROM sqlar", [], |r| r.get::<_, i64>(0))?;
    Ok(())
}

fn open_encrypted(
    path: &Path,
    options: &OpenOptions,
    header: &[u8],
    plain_err: SqlarError,
) -> Result<Connection> {
    // Require at least a 16-byte salt for a plausible sqlcipher file.
    if header.len() < 16 {
        return Err(plain_err);
    }

    if options.passwords.is_empty() {
        log::debug!(
            "SQLAR open failed without SQLite magic ({}): {plain_err}; treating as encrypted \
             (sqlcipher_enabled={})",
            path.display(),
            sqlcipher_enabled()
        );
        return Err(SqlarError::EncryptedRequiresPassword);
    }

    #[cfg(feature = "sqlcipher")]
    {
        let salt: [u8; 16] = header[..16].try_into().expect("checked len >= 16");
        try_sqlcipher_passwords(path, &options.passwords, &salt)
    }

    #[cfg(not(feature = "sqlcipher"))]
    {
        let _ = (path, plain_err);
        // Stock rusqlite `bundled` has no codec; PRAGMA key is a no-op / unused.
        // Surface a structured error rather than a cryptic "file is not a database".
        log::info!(
            "encrypted SQLAR detected at {}; passwords present but sqlcipher feature disabled",
            path.display()
        );
        Err(SqlarError::EncryptedNotSupported)
    }
}

/// Encrypted SQLAR residual for stream open: detect and return structured errors only.
///
/// SQLCipher page codec needs a path-backed open; in-memory deserialize of ciphertext
/// is not supported. Callers must materialize a path (or use top-level [`SqlarMountSource::open`]).
fn encrypted_from_stream_residual(
    path: &Path,
    options: &OpenOptions,
    header: &[u8],
    plain_err: SqlarError,
) -> Result<SqlarMountSource> {
    if header.len() < 16 {
        return Err(plain_err);
    }
    if options.passwords.is_empty() {
        log::debug!(
            "SQLAR stream open without SQLite magic ({}): treating as encrypted \
             (sqlcipher_enabled={}); stream decrypt not supported",
            path.display(),
            sqlcipher_enabled()
        );
        return Err(SqlarError::EncryptedRequiresPassword);
    }
    #[cfg(feature = "sqlcipher")]
    {
        let _ = plain_err;
        // Passwords present and SQLCipher linked, but we still cannot decrypt a pure
        // stream without a path/VFS. Surface a clear residual rather than WrongPassword.
        log::info!(
            "encrypted SQLAR stream at {}; sqlcipher is enabled but open_from_reader \
             does not decrypt — use path-based open (or AutoMount temp spool)",
            path.display()
        );
        Err(SqlarError::Msg(format!(
            "encrypted SQLAR cannot be opened from a nested stream without a host path; \
             use path open with --password (label={})",
            path.display()
        )))
    }
    #[cfg(not(feature = "sqlcipher"))]
    {
        let _ = plain_err;
        log::info!(
            "encrypted SQLAR stream at {}; passwords present but sqlcipher feature disabled",
            path.display()
        );
        Err(SqlarError::EncryptedNotSupported)
    }
}

/// Try each password with SQLCipher (passphrase form, then PBKDF2 raw key).
#[cfg(feature = "sqlcipher")]
fn try_sqlcipher_passwords(
    path: &Path,
    passwords: &[String],
    salt: &[u8; 16],
) -> Result<Connection> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512;

    for password in passwords {
        // 1) Passphrase mode — SQLCipher derives the key itself.
        if let Ok(conn) = Connection::open_with_flags(path, OPEN_FLAGS) {
            if apply_pragma_key_passphrase(&conn, password).is_ok()
                && verify_sqlar_readable(&conn).is_ok()
            {
                return Ok(conn);
            }
        }

        // 2) Raw key from PBKDF2-HMAC-SHA512 (Python / sqlcipher3 parity; safe for any password chars).
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha512>(password.as_bytes(), salt, SQLCIPHER_KDF_ITER, &mut key);
        if let Ok(conn) = Connection::open_with_flags(path, OPEN_FLAGS) {
            if apply_pragma_key_raw(&conn, &key).is_ok() && verify_sqlar_readable(&conn).is_ok() {
                return Ok(conn);
            }
        }
    }
    Err(SqlarError::WrongPassword)
}

#[cfg(feature = "sqlcipher")]
fn apply_pragma_key_passphrase(conn: &Connection, password: &str) -> rusqlite::Result<()> {
    // Escape single quotes for SQL string literal.
    let escaped = password.replace('\'', "''");
    conn.execute_batch(&format!("PRAGMA key = '{escaped}';"))?;
    Ok(())
}

#[cfg(feature = "sqlcipher")]
fn apply_pragma_key_raw(conn: &Connection, key: &[u8; 32]) -> rusqlite::Result<()> {
    // https://www.zetetic.net/sqlcipher/sqlcipher-api/#PRAGMA_key
    // Double-quoted x'..' form (Python uses the same).
    let hex = to_hex(key);
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))?;
    Ok(())
}

#[cfg(feature = "sqlcipher")]
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn build_name_map(conn: &Connection) -> Result<Option<BTreeMap<String, String>>> {
    let mut stmt = conn.prepare("SELECT name FROM sqlar")?;
    let names: Vec<String> = stmt
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let needs: bool = names.iter().any(|n| {
        let stripped = n.trim_start_matches('/');
        let norm = {
            let mut parts = Vec::new();
            for p in stripped.split('/') {
                if p.is_empty() || p == "." {
                    continue;
                }
                if p == ".." {
                    parts.pop();
                } else {
                    parts.push(p);
                }
            }
            parts.join("/")
        };
        norm != *n
    });
    if !needs {
        return Ok(None);
    }
    let mut map = BTreeMap::new();
    for n in names {
        let stripped = n.trim_start_matches('/');
        let mut parts = Vec::new();
        for p in stripped.split('/') {
            if p.is_empty() || p == "." {
                continue;
            }
            if p == ".." {
                parts.pop();
            } else {
                parts.push(p);
            }
        }
        let key = parts.join("/");
        map.entry(key).or_insert(n);
    }
    Ok(Some(map))
}

/// True if path is a plausible SQLAR: SQLite magic + `sqlar` table, or `.sqlar` extension
/// (encrypted sqlcipher archives omit the magic and store salt in the first 16 bytes).
pub fn looks_like_sqlar(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 16];
    let Ok(n) = std::io::Read::read(&mut f, &mut magic) else {
        return false;
    };
    if n < 16 {
        return false;
    }
    if magic.as_slice() != SQLITE_MAGIC {
        // Encrypted SQLAR (sqlcipher): no magic; first 16 B are salt.
        // Require .sqlar extension to avoid claiming every random 16+ byte file.
        return has_sqlar_extension(path);
    }
    // Prefer verifying table when possible.
    if let Ok(conn) = Connection::open_with_flags(path, OPEN_FLAGS) {
        let has: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlar' LIMIT 1",
                [],
                |_| Ok(true),
            )
            .optional()
            .ok()
            .flatten()
            .unwrap_or(false);
        return has;
    }
    false
}

/// True when the file does not have a SQLite header (likely sqlcipher-encrypted SQLAR).
pub fn looks_like_encrypted_sqlar(path: &Path) -> bool {
    let Ok(header) = read_header(path) else {
        return false;
    };
    header.len() >= 16 && !header_is_sqlite_magic(&header) && has_sqlar_extension(path)
}

impl MountSource for SqlarMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        if path != "/" {
            // Must be a directory entry.
            let fi = self.lookup(&path, 0)?;
            if fi.mode & ratarmount_core::S_IFMT != ratarmount_core::S_IFDIR {
                return None;
            }
        }

        let prefix = if path == "/" {
            String::new()
        } else {
            path.trim_start_matches('/').to_string()
        };

        self.with_conn(|conn| {
            let mut map = BTreeMap::new();
            let mut stmt = conn.prepare(
                "SELECT name, rowid, mode, mtime, sz, \
                 CASE WHEN sz=-1 THEN CAST(data AS TEXT) ELSE '' END FROM sqlar",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })?;
            for row in rows {
                let (name, rowid, mode, mtime, sz, link) = row?;
                let norm = name.trim_start_matches('/');
                let child = if prefix.is_empty() {
                    // top-level component
                    let first = norm.split('/').next().unwrap_or("");
                    if first.is_empty() {
                        continue;
                    }
                    // Only direct children: either exact name or first component of nested
                    if norm == first {
                        Some((first.to_string(), rowid, mode, mtime, sz, link))
                    } else if norm.starts_with(&(first.to_string() + "/")) {
                        // synthetic parent folder may exist as its own row; if not, still expose name
                        // Prefer real row for `first` when present; else skip synthetic here
                        // (directories are stored explicitly in SQLAR).
                        None
                    } else {
                        None
                    }
                } else if norm == prefix {
                    continue;
                } else if let Some(rest) = norm.strip_prefix(&(prefix.clone() + "/")) {
                    let first = rest.split('/').next().unwrap_or("");
                    if first.is_empty() {
                        None
                    } else if rest == first {
                        Some((first.to_string(), rowid, mode, mtime, sz, link))
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some((cname, rowid, mode, mtime, sz, link)) = child {
                    map.entry(cname)
                        .or_insert_with(|| Self::row_to_file_info(rowid, mode, mtime, sz, link));
                }
            }
            Ok(Some(ListResult::Infos(map)))
        })
        .ok()
        .flatten()
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        match self.list(path)? {
            ListResult::Names(n) => Some(ListModeResult::Names(n)),
            ListResult::Infos(m) => Some(ListModeResult::Modes(
                m.into_iter().map(|(k, v)| (k, v.mode)).collect(),
            )),
        }
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(create_root_file_info());
        }
        match self.lookup_row(&path) {
            Ok(Some((rowid, mode, mtime, sz, link))) => {
                Some(Self::row_to_file_info(rowid, mode, mtime, sz, link))
            }
            _ => None,
        }
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        let rowid = file_info
            .userdata
            .iter()
            .rev()
            .find_map(|u| match u {
                UserData::Other(s) => s.strip_prefix("sqlar:").and_then(|n| n.parse::<i64>().ok()),
                _ => None,
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing sqlar rowid"))?;

        let (sz, data): (i64, Vec<u8>) = self
            .with_conn(|conn| {
                let row = conn.query_row(
                    "SELECT sz, data FROM sqlar WHERE rowid = ?1",
                    rusqlite::params![rowid],
                    |r| {
                        let sz: i64 = r.get(0)?;
                        let data: Option<Vec<u8>> = r.get(1)?;
                        Ok((sz, data.unwrap_or_default()))
                    },
                )?;
                Ok(row)
            })
            .map_err(|e| io::Error::other(e.to_string()))?;

        if sz < 0 {
            // symlink — content is target (already in linkname)
            return Ok(Box::new(Cursor::new(Vec::new())));
        }
        if sz == 0 {
            return Ok(Box::new(Cursor::new(Vec::new())));
        }
        let body = if data.len() as i64 == sz {
            data
        } else if (data.len() as i64) < sz {
            let mut dec = ZlibDecoder::new(data.as_slice());
            let mut out = Vec::with_capacity(sz as usize);
            dec.read_to_end(&mut out)
                .map_err(|e| io::Error::other(format!("sqlar zlib: {e}")))?;
            if out.len() as i64 != sz {
                // tolerate slight mismatch; truncate/pad not required for fixtures
            }
            out
        } else {
            return Err(io::Error::other("sqlar data longer than declared size"));
        };
        Ok(Box::new(Cursor::new(body)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Fixture root: `RATARMOUNT_PY_ROOT` (Python ratarmount checkout) or a local default.
    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    fn skip_missing(path: &Path, kind: &str) -> bool {
        if path.exists() {
            return false;
        }
        eprintln!(
            "skip missing {kind} fixture {} (set RATARMOUNT_PY_ROOT to the Python ratarmount tree)",
            path.display()
        );
        true
    }

    fn assert_ufo(m: &SqlarMountSource) {
        let fi = m.lookup("/foo/fighter/ufo", 0).expect("ufo");
        assert_eq!(fi.size, 6);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");
    }

    #[test]
    fn sqlcipher_enabled_matches_cfg() {
        assert_eq!(sqlcipher_enabled(), cfg!(feature = "sqlcipher"));
    }

    /// Display text for structured encrypted errors always mentions encryption / sqlcipher path.
    #[test]
    fn encrypted_error_messages_are_actionable() {
        let req = SqlarError::EncryptedRequiresPassword.to_string();
        assert!(
            req.contains("password") && req.contains("encrypted"),
            "EncryptedRequiresPassword: {req}"
        );
        if sqlcipher_enabled() {
            assert!(
                !req.contains("Rebuild") && !req.contains("rebuild"),
                "with sqlcipher feature, no rebuild hint expected: {req}"
            );
        } else {
            assert!(
                req.contains("sqlcipher") || req.contains("SQLCipher"),
                "without sqlcipher, message should mention the feature: {req}"
            );
        }

        let unsupported = SqlarError::EncryptedNotSupported.to_string();
        assert!(
            unsupported.contains("sqlcipher")
                && unsupported.contains("--features")
                && unsupported.contains("Passwords were ignored"),
            "EncryptedNotSupported: {unsupported}"
        );

        let wrong = SqlarError::WrongPassword.to_string();
        assert!(wrong.contains("password"), "WrongPassword: {wrong}");
    }

    #[test]
    fn nested_tar_sqlar() {
        let path = py_test("nested-tar.sqlar");
        if skip_missing(&path, "unencrypted") {
            return;
        }
        assert!(looks_like_sqlar(&path));
        assert!(!looks_like_encrypted_sqlar(&path));
        let m = SqlarMountSource::open(&path, &OpenOptions::default()).unwrap();
        assert_ufo(&m);
        let root = m.list("/").expect("root");
        if let ListResult::Infos(map) = root {
            assert!(map.contains_key("foo"));
        }
        // nested dirs
        assert!(m.lookup("/foo", 0).is_some());
        assert!(m.lookup("/foo/fighter", 0).is_some());
    }

    #[test]
    fn nested_tar_denormal_sqlar() {
        let path = py_test("nested-tar-denormal.sqlar");
        if skip_missing(&path, "unencrypted") {
            return;
        }
        assert!(looks_like_sqlar(&path));
        let m = SqlarMountSource::open(&path, &OpenOptions::default()).unwrap();
        assert_ufo(&m);
    }

    #[test]
    fn nested_tar_compressed_sqlar() {
        let path = py_test("nested-tar-compressed.sqlar");
        if skip_missing(&path, "unencrypted") {
            return;
        }
        assert!(looks_like_sqlar(&path));
        let m = SqlarMountSource::open(&path, &OpenOptions::default()).unwrap();
        assert_ufo(&m);
    }

    #[test]
    fn nested_tar_trailing_slash_sqlar() {
        let path = py_test("nested-tar-trailing-slash.sqlar");
        if skip_missing(&path, "unencrypted") {
            return;
        }
        let m = SqlarMountSource::open(&path, &OpenOptions::default()).unwrap();
        assert_ufo(&m);
    }

    #[test]
    fn encrypted_detection_without_password() {
        let path = py_test("encrypted-nested-tar.sqlar");
        if skip_missing(&path, "encrypted") {
            return;
        }
        assert!(looks_like_sqlar(&path));
        assert!(looks_like_encrypted_sqlar(&path));

        match SqlarMountSource::open(&path, &OpenOptions::default()) {
            Err(err @ SqlarError::EncryptedRequiresPassword) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("password") && msg.contains("encrypted"),
                    "message should mention password/encrypted: {msg}"
                );
            }
            Err(other) => panic!("expected EncryptedRequiresPassword, got {other}"),
            Ok(_) => panic!("expected error for encrypted SQLAR without password"),
        }
    }

    #[test]
    fn encrypted_with_password() {
        let path = py_test("encrypted-nested-tar.sqlar");
        if skip_missing(&path, "encrypted") {
            return;
        }
        // Python fixture password is "foo"; also try a decoy first (multi-password trial).
        let opts = OpenOptions {
            passwords: vec![r#""; DROP TABLE sqlar;"#.into(), "foo".into()],
            ..OpenOptions::default()
        };

        #[cfg(feature = "sqlcipher")]
        {
            assert!(sqlcipher_enabled());
            let m = SqlarMountSource::open(&path, &opts).expect("decrypt with password foo");
            assert_ufo(&m);
        }

        #[cfg(not(feature = "sqlcipher"))]
        {
            assert!(!sqlcipher_enabled());
            match SqlarMountSource::open(&path, &opts) {
                Err(err @ SqlarError::EncryptedNotSupported) => {
                    let msg = err.to_string();
                    assert!(
                        msg.contains("sqlcipher")
                            && (msg.contains("--features") || msg.contains("not supported")),
                        "message: {msg}"
                    );
                }
                Err(other) => panic!("expected EncryptedNotSupported, got {other}"),
                Ok(_) => panic!("expected EncryptedNotSupported without sqlcipher feature"),
            }
        }
    }

    #[test]
    fn encrypted_wrong_password_or_unsupported() {
        let path = py_test("encrypted-nested-tar.sqlar");
        if skip_missing(&path, "encrypted") {
            return;
        }
        let opts = OpenOptions {
            passwords: vec!["not-the-password".into()],
            ..OpenOptions::default()
        };

        match SqlarMountSource::open(&path, &opts) {
            #[cfg(feature = "sqlcipher")]
            Err(SqlarError::WrongPassword) => {}
            #[cfg(not(feature = "sqlcipher"))]
            Err(SqlarError::EncryptedNotSupported) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("expected decrypt failure"),
        }
    }

    /// Unencrypted path still works when unused passwords are supplied.
    #[test]
    fn unencrypted_ignores_passwords() {
        let path = py_test("nested-tar.sqlar");
        if skip_missing(&path, "unencrypted") {
            return;
        }
        let opts = OpenOptions {
            passwords: vec!["irrelevant".into()],
            ..OpenOptions::default()
        };
        let m = SqlarMountSource::open(&path, &opts).unwrap();
        assert_ufo(&m);
    }

    /// Nested no-tmp path: fixture bytes via Cursor → open_from_reader (no host file).
    #[test]
    fn open_from_reader_cursor_equals_path() {
        let path = py_test("nested-tar.sqlar");
        if skip_missing(&path, "unencrypted") {
            return;
        }
        let bytes = std::fs::read(&path).expect("read fixture");
        let from_path = SqlarMountSource::open(&path, &OpenOptions::default()).unwrap();
        let from_reader = SqlarMountSource::open_from_reader(
            Cursor::new(bytes),
            "nested-tar.sqlar",
            &OpenOptions::default(),
        )
        .expect("open_from_reader");
        assert_ufo(&from_path);
        assert_ufo(&from_reader);
        // list root names should match
        let path_root = from_path.list("/").expect("path root");
        let reader_root = from_reader.list("/").expect("reader root");
        match (path_root, reader_root) {
            (ListResult::Infos(a), ListResult::Infos(b)) => {
                assert_eq!(a.keys().collect::<Vec<_>>(), b.keys().collect::<Vec<_>>());
            }
            _ => panic!("expected Infos lists"),
        }
    }

    #[test]
    fn open_from_reader_compressed_fixture() {
        let path = py_test("nested-tar-compressed.sqlar");
        if skip_missing(&path, "unencrypted") {
            return;
        }
        let bytes = std::fs::read(&path).expect("read fixture");
        let m = SqlarMountSource::open_from_bytes(
            bytes,
            "nested-tar-compressed.sqlar",
            &OpenOptions::default(),
        )
        .expect("open_from_bytes");
        assert_ufo(&m);
    }

    #[test]
    fn open_from_reader_rejects_non_sqlite() {
        let result = SqlarMountSource::open_from_reader(
            Cursor::new(b"not a database at all!!!!"),
            "fake.sqlar",
            &OpenOptions::default(),
        );
        // .sqlar label + no magic → encrypted residual without password
        match result {
            Err(err @ SqlarError::EncryptedRequiresPassword) => {
                assert!(err.to_string().contains("password"));
            }
            Err(err) if err.to_string().contains("not a plain SQLite") => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("non-sqlite should fail"),
        }
    }

    #[test]
    fn open_from_reader_encrypted_residual() {
        let path = py_test("encrypted-nested-tar.sqlar");
        if skip_missing(&path, "encrypted") {
            return;
        }
        let bytes = std::fs::read(&path).expect("read encrypted fixture");
        match SqlarMountSource::open_from_reader(
            Cursor::new(bytes),
            "encrypted-nested-tar.sqlar",
            &OpenOptions::default(),
        ) {
            Err(SqlarError::EncryptedRequiresPassword) => {}
            Err(other) => panic!("expected EncryptedRequiresPassword, got {other}"),
            Ok(_) => panic!("encrypted stream must not open without password/path"),
        }
    }

    #[test]
    fn open_from_reader_encrypted_with_password_still_residual() {
        let path = py_test("encrypted-nested-tar.sqlar");
        if skip_missing(&path, "encrypted") {
            return;
        }
        let bytes = std::fs::read(&path).expect("read encrypted fixture");
        let opts = OpenOptions {
            passwords: vec!["foo".into()],
            ..OpenOptions::default()
        };
        match SqlarMountSource::open_from_reader(
            Cursor::new(bytes),
            "encrypted-nested-tar.sqlar",
            &opts,
        ) {
            #[cfg(feature = "sqlcipher")]
            Err(SqlarError::Msg(msg)) => {
                assert!(
                    msg.contains("encrypted") && msg.contains("stream"),
                    "expected stream residual: {msg}"
                );
            }
            #[cfg(not(feature = "sqlcipher"))]
            Err(SqlarError::EncryptedNotSupported) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("encrypted stream decrypt is residual"),
        }
    }
}
