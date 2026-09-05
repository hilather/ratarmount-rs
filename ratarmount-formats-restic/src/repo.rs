//! Local restic repo: keys, config, index, snapshots, pack blob reads.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;

use crate::crypto::{decrypt, encrypt, hex_encode, scrypt_derive, sha256, MasterKey, EXTENSION};
use crate::{ResticError, Result};

/// Caps so a crafted repo cannot force unbounded reads (past issue).
pub const MAX_KEY_FILE: u64 = 64 * 1024;
pub const MAX_CONFIG_FILE: u64 = 64 * 1024;
pub const MAX_INDEX_FILE: u64 = 16 * 1024 * 1024;
pub const MAX_SNAPSHOT_FILE: u64 = 2 * 1024 * 1024;
pub const MAX_BLOB: u64 = 16 * 1024 * 1024;
pub const MAX_KEYS: usize = 32;
pub const MAX_INDEX_FILES: usize = 4096;
pub const MAX_SNAPSHOTS: usize = 4096;
const MAX_PASSWORD_FILE: u64 = 4 * 1024;

#[derive(Debug, Deserialize)]
struct KeyFileJson {
    kdf: String,
    #[serde(rename = "N")]
    n: u32,
    r: u32,
    p: u32,
    salt: String,
    data: String,
}

#[derive(Debug, Deserialize)]
struct MasterKeyJson {
    mac: MacJson,
    encrypt: String,
}

#[derive(Debug, Deserialize)]
struct MacJson {
    k: String,
    r: String,
}

#[derive(Debug, Deserialize)]
struct ConfigJson {
    version: u32,
    #[allow(dead_code)]
    id: String,
}

#[derive(Debug, Deserialize)]
pub struct IndexFile {
    #[serde(default)]
    pub supersedes: Vec<String>,
    #[serde(default)]
    pub packs: Vec<IndexPack>,
}

#[derive(Debug, Deserialize)]
pub struct IndexPack {
    pub id: String,
    #[serde(default)]
    pub blobs: Vec<IndexBlob>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct IndexBlob {
    pub id: String,
    #[serde(rename = "type")]
    pub blob_type: String,
    pub offset: u64,
    pub length: u64,
    #[serde(default)]
    pub uncompressed_length: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SnapshotJson {
    pub time: String,
    pub tree: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TreeJson {
    #[serde(default)]
    pub nodes: Vec<TreeNode>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TreeNode {
    pub name: String,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(default)]
    pub mode: u32,
    #[serde(default)]
    pub mtime: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub content: Option<Vec<String>>,
    #[serde(default)]
    pub subtree: Option<String>,
    #[serde(default)]
    pub linktarget: Option<String>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
}

#[derive(Clone)]
pub struct BlobLoc {
    pub pack_id: String,
    pub offset: u64,
    pub length: u64,
    pub uncompressed_length: Option<u64>,
}

pub struct SnapshotMeta {
    pub id: String,
    pub short_id: String,
    pub unix: f64,
    pub tree: String,
}

pub struct Repo {
    pub root: PathBuf,
    key: MasterKey,
    pub blobs: HashMap<String, BlobLoc>,
    pub snapshots: Vec<SnapshotMeta>,
    trees: Mutex<HashMap<String, TreeJson>>,
}

impl Repo {
    pub fn open(path: &Path, password: &[u8]) -> Result<Self> {
        if password.is_empty() {
            return Err(ResticError::Msg("empty restic password".into()));
        }
        let key = load_master_key(path, password)?;
        let cfg_plain = decrypt_repo_file(&key, &path.join("config"), MAX_CONFIG_FILE)?;
        let cfg_json = decode_unpacked(&cfg_plain, MAX_CONFIG_FILE)?;
        let cfg: ConfigJson = serde_json::from_slice(&cfg_json)
            .map_err(|e| ResticError::Msg(format!("restic config: {e}")))?;
        if cfg.version != 1 && cfg.version != 2 {
            return Err(ResticError::Msg(format!(
                "unsupported restic repo version {}",
                cfg.version
            )));
        }
        let blobs = load_index(path, &key)?;
        let snapshots = load_snapshots(path, &key)?;
        Ok(Self {
            root: path.to_path_buf(),
            key,
            blobs,
            snapshots,
            trees: Mutex::new(HashMap::new()),
        })
    }

    pub fn latest(&self) -> Option<&SnapshotMeta> {
        self.snapshots.iter().max_by(|a, b| {
            a.unix
                .partial_cmp(&b.unix)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id))
        })
    }

    pub fn snapshot_by_prefix(&self, prefix: &str) -> Option<&SnapshotMeta> {
        let matches: Vec<&SnapshotMeta> = self
            .snapshots
            .iter()
            .filter(|s| s.id.starts_with(prefix) || s.short_id == prefix)
            .collect();
        if matches.len() == 1 {
            Some(matches[0])
        } else {
            None
        }
    }

    pub fn load_tree(&self, id: &str) -> Result<TreeJson> {
        {
            let cache = self
                .trees
                .lock()
                .map_err(|_| ResticError::Msg("tree cache lock poisoned".into()))?;
            if let Some(t) = cache.get(id) {
                return Ok(t.clone());
            }
        }
        let plain = self.read_blob(id)?;
        let json = decode_unpacked(&plain, MAX_BLOB)?;
        let tree: TreeJson = serde_json::from_slice(&json)
            .map_err(|e| ResticError::Msg(format!("restic tree {id}: {e}")))?;
        let mut cache = self
            .trees
            .lock()
            .map_err(|_| ResticError::Msg("tree cache lock poisoned".into()))?;
        cache.insert(id.to_string(), tree.clone());
        Ok(tree)
    }

    pub fn read_blob(&self, id: &str) -> Result<Vec<u8>> {
        let loc = self
            .blobs
            .get(id)
            .ok_or_else(|| ResticError::Msg(format!("blob {id} not in index")))?;
        if loc.length > MAX_BLOB {
            return Err(ResticError::Msg(format!(
                "blob {id} length {} exceeds cap",
                loc.length
            )));
        }
        let enc = read_pack_slice(&self.root, &loc.pack_id, loc.offset, loc.length)?;
        let mut plain = decrypt(&self.key, &enc)?;
        if let Some(uncomp) = loc.uncompressed_length {
            if uncomp > MAX_BLOB {
                return Err(ResticError::Msg("uncompressed blob exceeds cap".into()));
            }
            if uncomp == 0 {
                plain.clear();
            } else {
                // Cap at the index length (already ≤ MAX_BLOB), not decode_all.
                plain = zstd_decode_capped(plain.as_slice(), uncomp)?;
                if plain.len() as u64 != uncomp {
                    return Err(ResticError::Msg(format!(
                        "blob {id} uncompressed length mismatch"
                    )));
                }
            }
        }
        Ok(plain)
    }

    pub fn blob_plain_len(&self, id: &str) -> Result<u64> {
        let loc = self
            .blobs
            .get(id)
            .ok_or_else(|| ResticError::Msg(format!("blob {id} not in index")))?;
        if let Some(n) = loc.uncompressed_length {
            Ok(n)
        } else {
            Ok(loc.length.saturating_sub(EXTENSION as u64))
        }
    }
}

pub fn load_password_from_env() -> Result<Vec<u8>> {
    if let Ok(p) = std::env::var("RESTIC_PASSWORD") {
        if !p.is_empty() {
            return Ok(p.into_bytes());
        }
    }
    if let Ok(path) = std::env::var("RESTIC_PASSWORD_FILE") {
        let meta = fs::metadata(&path)?;
        if meta.len() > MAX_PASSWORD_FILE {
            return Err(ResticError::Msg("RESTIC_PASSWORD_FILE too large".into()));
        }
        let s = fs::read_to_string(&path)?;
        // restic TrimRight(s, "\r\n") — all trailing CR/LF, not a single newline.
        let trimmed = trim_restic_password_file(&s);
        if trimmed.is_empty() {
            return Err(ResticError::Msg("RESTIC_PASSWORD_FILE is empty".into()));
        }
        return Ok(trimmed.as_bytes().to_vec());
    }
    Err(ResticError::Msg(
        "restic password required (RESTIC_PASSWORD or RESTIC_PASSWORD_FILE)".into(),
    ))
}

/// Match restic `TrimRight(..., "\r\n")` (every trailing CR/LF).
pub(crate) fn trim_restic_password_file(s: &str) -> &str {
    s.trim_end_matches(['\n', '\r'])
}

fn load_master_key(root: &Path, password: &[u8]) -> Result<MasterKey> {
    let keys_dir = root.join("keys");
    let mut files: Vec<PathBuf> = fs::read_dir(&keys_dir)
        .map_err(|e| ResticError::Msg(format!("restic keys/: {e}")))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(ResticError::Msg("no restic key files".into()));
    }
    if files.len() > MAX_KEYS {
        files.truncate(MAX_KEYS);
    }
    let mut last_err = ResticError::Msg("wrong password or no key found".into());
    for path in files {
        match try_key_file(&path, password) {
            Ok(k) => return Ok(k),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn try_key_file(path: &Path, password: &[u8]) -> Result<MasterKey> {
    let raw = read_capped(path, MAX_KEY_FILE)?;
    let kf: KeyFileJson = serde_json::from_slice(&raw)
        .map_err(|e| ResticError::Msg(format!("restic key file: {e}")))?;
    if !kf.kdf.eq_ignore_ascii_case("scrypt") {
        return Err(ResticError::Msg(format!("unsupported KDF {}", kf.kdf)));
    }
    let salt = B64
        .decode(kf.salt.as_bytes())
        .map_err(|_| ResticError::Msg("restic key salt base64".into()))?;
    let data = B64
        .decode(kf.data.as_bytes())
        .map_err(|_| ResticError::Msg("restic key data base64".into()))?;
    let derived = scrypt_derive(password, &salt, kf.n, kf.r, kf.p)?;
    let pw_key = MasterKey::from_kdf_bytes(&derived);
    let plain = decrypt(&pw_key, &data)?;
    let mk: MasterKeyJson = serde_json::from_slice(&plain)
        .map_err(|e| ResticError::Msg(format!("restic master key JSON: {e}")))?;
    let encrypt = B64
        .decode(mk.encrypt.as_bytes())
        .map_err(|_| ResticError::Msg("master encrypt base64".into()))?;
    let k = B64
        .decode(mk.mac.k.as_bytes())
        .map_err(|_| ResticError::Msg("master mac.k base64".into()))?;
    let r = B64
        .decode(mk.mac.r.as_bytes())
        .map_err(|_| ResticError::Msg("master mac.r base64".into()))?;
    MasterKey::from_json_parts(&encrypt, &k, &r)
}

fn load_index(root: &Path, key: &MasterKey) -> Result<HashMap<String, BlobLoc>> {
    let dir = root.join("index");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .map_err(|e| ResticError::Msg(format!("restic index/: {e}")))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    if files.len() > MAX_INDEX_FILES {
        return Err(ResticError::Msg("too many restic index files".into()));
    }
    let mut blobs = HashMap::new();
    for path in files {
        let enc = read_capped(&path, MAX_INDEX_FILE)?;
        let plain = decrypt(key, &enc)?;
        let json = decode_unpacked(&plain, MAX_INDEX_FILE)?;
        let idx = parse_index_json(&json)?;
        for pack in idx.packs {
            for blob in pack.blobs {
                blobs.insert(
                    blob.id,
                    BlobLoc {
                        pack_id: pack.id.clone(),
                        offset: blob.offset,
                        length: blob.length,
                        uncompressed_length: blob.uncompressed_length,
                    },
                );
            }
        }
    }
    Ok(blobs)
}

/// Parse restic v1/v2 index JSON (plaintext).
pub fn parse_index_json(json: &[u8]) -> Result<IndexFile> {
    serde_json::from_slice(json).map_err(|e| ResticError::Msg(format!("restic index JSON: {e}")))
}

fn load_snapshots(root: &Path, key: &MasterKey) -> Result<Vec<SnapshotMeta>> {
    let dir = root.join("snapshots");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .map_err(|e| ResticError::Msg(format!("restic snapshots/: {e}")))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    if files.len() > MAX_SNAPSHOTS {
        return Err(ResticError::Msg("too many restic snapshots".into()));
    }
    let mut snaps = Vec::new();
    for path in files {
        let id = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        if id.len() < 8 {
            continue;
        }
        let enc = read_capped(&path, MAX_SNAPSHOT_FILE)?;
        let plain = decrypt(key, &enc)?;
        let json = decode_unpacked(&plain, MAX_SNAPSHOT_FILE)?;
        let snap: SnapshotJson = serde_json::from_slice(&json)
            .map_err(|e| ResticError::Msg(format!("restic snapshot {id}: {e}")))?;
        snaps.push(SnapshotMeta {
            id,
            short_id: String::new(),
            unix: rfc3339_to_unix(&snap.time).unwrap_or(0.0),
            tree: snap.tree,
        });
    }
    assign_short_ids(&mut snaps);
    Ok(snaps)
}

fn assign_short_ids(snaps: &mut [SnapshotMeta]) {
    let mut len = 8usize;
    loop {
        let mut seen: HashMap<String, usize> = HashMap::new();
        let mut unique = true;
        for (i, s) in snaps.iter().enumerate() {
            let short = s.id.chars().take(len).collect::<String>();
            if let Some(prev) = seen.insert(short, i) {
                let _ = prev;
                unique = false;
                break;
            }
        }
        if unique || len >= 64 {
            for s in snaps.iter_mut() {
                s.short_id = s.id.chars().take(len).collect();
            }
            return;
        }
        len += 1;
    }
}

fn decrypt_repo_file(key: &MasterKey, path: &Path, cap: u64) -> Result<Vec<u8>> {
    let enc = read_capped(path, cap)?;
    decrypt(key, &enc)
}

fn decode_unpacked(plain: &[u8], max: u64) -> Result<Vec<u8>> {
    if plain.is_empty() {
        return Err(ResticError::Msg("empty restic plaintext".into()));
    }
    match plain[0] {
        b'{' | b'[' => {
            if plain.len() as u64 > max {
                return Err(ResticError::Msg("unpacked JSON exceeds cap".into()));
            }
            Ok(plain.to_vec())
        }
        2 => {
            if plain.len() == 1 {
                return Err(ResticError::Msg("empty zstd unpacked payload".into()));
            }
            zstd_decode_capped(&plain[1..], max)
        }
        v => Err(ResticError::Msg(format!(
            "unsupported restic encoding version {v}"
        ))),
    }
}

/// Streaming zstd decode that stops at `max` output bytes (no `decode_all`).
pub(crate) fn zstd_decode_capped(src: &[u8], max: u64) -> Result<Vec<u8>> {
    let max = usize::try_from(max).unwrap_or(usize::MAX);
    let mut decoder =
        zstd::Decoder::new(src).map_err(|e| ResticError::Msg(format!("zstd: {e}")))?;
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let n = decoder
            .read(&mut tmp)
            .map_err(|e| ResticError::Msg(format!("zstd: {e}")))?;
        if n == 0 {
            break;
        }
        let new_len = out.len().saturating_add(n);
        if new_len > max {
            return Err(ResticError::Msg(format!(
                "zstd output exceeds {max} byte cap"
            )));
        }
        out.extend_from_slice(&tmp[..n]);
    }
    Ok(out)
}

fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let meta = fs::metadata(path)?;
    if meta.len() > cap {
        return Err(ResticError::Msg(format!(
            "{} exceeds {} byte cap",
            path.display(),
            cap
        )));
    }
    Ok(fs::read(path)?)
}

fn read_pack_slice(root: &Path, pack_id: &str, offset: u64, length: u64) -> Result<Vec<u8>> {
    if length > MAX_BLOB {
        return Err(ResticError::Msg("pack slice exceeds blob cap".into()));
    }
    let path = pack_path(root, pack_id)?;
    let mut f = File::open(&path)?;
    let meta = f.metadata()?;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| ResticError::Msg("pack offset overflow".into()))?;
    if end > meta.len() {
        return Err(ResticError::Msg(format!("pack {} slice past EOF", pack_id)));
    }
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; length as usize];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn pack_path(root: &Path, pack_id: &str) -> Result<PathBuf> {
    if pack_id.len() < 2 {
        return Err(ResticError::Msg("pack id too short".into()));
    }
    let sub = &pack_id[..2];
    let p = root.join("data").join(sub).join(pack_id);
    if p.is_file() {
        return Ok(p);
    }
    // Prefix match when the full id is unique in the shard directory.
    let dir = root.join("data").join(sub);
    let rd = fs::read_dir(&dir).map_err(|e| ResticError::Msg(format!("pack dir: {e}")))?;
    let mut found = None;
    let mut n = 0usize;
    for ent in rd.flatten() {
        n += 1;
        if n > 4096 {
            break;
        }
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(pack_id) || pack_id.starts_with(name.as_ref()) {
            if found.is_some() {
                return Err(ResticError::Msg(format!("ambiguous pack id {pack_id}")));
            }
            found = Some(ent.path());
        }
    }
    found.ok_or_else(|| ResticError::Msg(format!("pack {pack_id} not found")))
}

pub fn rfc3339_to_unix(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.len() < 19 {
        return None;
    }
    let year: i32 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(5..7)?.parse().ok()?;
    let day: u32 = s.get(8..10)?.parse().ok()?;
    let hour: u32 = s.get(11..13)?.parse().ok()?;
    let min: u32 = s.get(14..16)?.parse().ok()?;
    let sec: u32 = s.get(17..19)?.parse().ok()?;
    let rest = s.get(19..)?;
    let (frac, tz) = if let Some(stripped) = rest.strip_prefix('.') {
        let mut i = 0usize;
        while i < stripped.len() && stripped.as_bytes()[i].is_ascii_digit() {
            i += 1;
        }
        let digits = &stripped[..i];
        let mut f = 0.0f64;
        let mut place = 0.1;
        for b in digits.bytes().take(9) {
            f += f64::from(b - b'0') * place;
            place *= 0.1;
        }
        (f, &stripped[i..])
    } else {
        (0.0, rest)
    };
    let tz_secs: i32 = if tz.is_empty() || tz == "Z" || tz == "z" {
        0
    } else {
        let sign = if tz.starts_with('+') {
            1
        } else if tz.starts_with('-') {
            -1
        } else {
            return None;
        };
        let body = &tz[1..];
        let (th, tm): (i32, i32) = if body.len() >= 5 && body.as_bytes()[2] == b':' {
            (body.get(0..2)?.parse().ok()?, body.get(3..5)?.parse().ok()?)
        } else if body.len() >= 4 {
            (body.get(0..2)?.parse().ok()?, body.get(2..4)?.parse().ok()?)
        } else {
            return None;
        };
        sign * (th * 3600 + tm * 60)
    };
    let days = days_from_civil(year, month, day)?;
    let unix = days * 86400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec)
        - i64::from(tz_secs);
    Some(unix as f64 + frac)
}

fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || d == 0 || d > 31 {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(i64::from(era) * 146097 + i64::from(doe) - 719468)
}

/// Write a tiny v1 restic repo: two snapshots, one 1 KiB file `hello.bin`.
pub fn write_synthetic_repo(dir: &Path, password: &[u8]) -> Result<SyntheticRepo> {
    write_synthetic_repo_version(dir, password, 1)
}

/// Same layout as [`write_synthetic_repo`] with restic v2 encoding:
/// unpacked index/snapshot JSON is `0x02 || zstd(json)`; pack blobs are zstd
/// with `uncompressed_length` in the index.
pub fn write_synthetic_repo_v2(dir: &Path, password: &[u8]) -> Result<SyntheticRepo> {
    write_synthetic_repo_version(dir, password, 2)
}

fn zstd_encode(plain: &[u8]) -> Result<Vec<u8>> {
    zstd::encode_all(plain, 3).map_err(|e| ResticError::Msg(format!("zstd encode: {e}")))
}

fn seal_unpacked(master: &MasterKey, json: &[u8], version: u32, iv: &[u8; 16]) -> Result<Vec<u8>> {
    let body = if version >= 2 {
        let mut v = vec![2u8];
        v.extend(zstd_encode(json)?);
        v
    } else {
        json.to_vec()
    };
    Ok(encrypt(master, &body, iv))
}

fn seal_blob(
    master: &MasterKey,
    plain: &[u8],
    version: u32,
    iv: &[u8; 16],
) -> Result<(Vec<u8>, Option<u64>)> {
    let (to_enc, uncomp) = if version >= 2 {
        (zstd_encode(plain)?, Some(plain.len() as u64))
    } else {
        (plain.to_vec(), None)
    };
    Ok((encrypt(master, &to_enc, iv), uncomp))
}

fn write_synthetic_repo_version(
    dir: &Path,
    password: &[u8],
    version: u32,
) -> Result<SyntheticRepo> {
    fs::create_dir_all(dir.join("keys"))?;
    fs::create_dir_all(dir.join("data"))?;
    fs::create_dir_all(dir.join("index"))?;
    fs::create_dir_all(dir.join("snapshots"))?;
    fs::create_dir_all(dir.join("locks"))?;

    let mut master_bytes = [0u8; 64];
    // Deterministic non-zero test key (not a secret).
    for (i, b) in master_bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17).wrapping_add(3);
    }
    let master = MasterKey::from_kdf_bytes(&master_bytes);

    let salt = [9u8; 32];
    let n = 1024u32;
    let r = 8u32;
    let p = 1u32;
    let derived = scrypt_derive(password, &salt, n, r, p)?;
    let pw_key = MasterKey::from_kdf_bytes(&derived);
    let mk_json = format!(
        "{{\"mac\":{{\"k\":\"{}\",\"r\":\"{}\"}},\"encrypt\":\"{}\"}}",
        B64.encode(&master_bytes[32..48]),
        B64.encode(&master_bytes[48..64]),
        B64.encode(&master_bytes[..32])
    );
    let mut iv = [1u8; 16];
    let key_data = encrypt(&pw_key, mk_json.as_bytes(), &iv);
    let key_doc = serde_json::json!({
        "created": "2020-01-01T00:00:00Z",
        "username": "ratarmount",
        "hostname": "test",
        "kdf": "scrypt",
        "N": n,
        "r": r,
        "p": p,
        "salt": B64.encode(salt),
        "data": B64.encode(&key_data),
    });
    let key_bytes = serde_json::to_vec(&key_doc)?;
    let key_id = hex_encode(&sha256(&key_bytes));
    fs::write(dir.join("keys").join(&key_id), &key_bytes)?;

    let cfg = serde_json::json!({
        "version": version,
        "id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "chunker_polynomial": "25b468838dcb75",
    });
    iv[0] = 2;
    // restic config is never zstd-wrapped.
    let cfg_enc = encrypt(&master, cfg.to_string().as_bytes(), &iv);
    fs::write(dir.join("config"), &cfg_enc)?;

    let payload = vec![0xABu8; 1024];
    let data_id = hex_encode(&sha256(&payload));
    iv[0] = 3;
    let (data_enc, data_uncomp) = seal_blob(&master, &payload, version, &iv)?;

    let tree = serde_json::json!({
        "nodes": [{
            "name": "hello.bin",
            "type": "file",
            "mode": 0o644,
            "mtime": "2020-01-02T00:00:00Z",
            "size": 1024,
            "content": [data_id],
        }]
    });
    let tree_bytes = serde_json::to_vec(&tree)?;
    let tree_id = hex_encode(&sha256(&tree_bytes));
    iv[0] = 4;
    let (tree_enc, tree_uncomp) = seal_blob(&master, &tree_bytes, version, &iv)?;

    let mut pack = Vec::new();
    let data_off = 0u64;
    pack.extend_from_slice(&data_enc);
    let tree_off = pack.len() as u64;
    pack.extend_from_slice(&tree_enc);

    let mut header = Vec::new();
    let data_type = if version >= 2 { 2u8 } else { 0u8 };
    let tree_type = if version >= 2 { 3u8 } else { 1u8 };
    header.push(data_type);
    header.extend_from_slice(&(data_enc.len() as u32).to_le_bytes());
    if let Some(n) = data_uncomp {
        header.extend_from_slice(&(n as u32).to_le_bytes());
    }
    header.extend_from_slice(&sha256(&payload));
    header.push(tree_type);
    header.extend_from_slice(&(tree_enc.len() as u32).to_le_bytes());
    if let Some(n) = tree_uncomp {
        header.extend_from_slice(&(n as u32).to_le_bytes());
    }
    header.extend_from_slice(&sha256(&tree_bytes));
    iv[0] = 5;
    let header_enc = encrypt(&master, &header, &iv);
    let header_len = header_enc.len() as u32;
    pack.extend_from_slice(&header_enc);
    pack.extend_from_slice(&header_len.to_le_bytes());

    let pack_id = hex_encode(&sha256(&pack));
    let shard = dir.join("data").join(&pack_id[..2]);
    fs::create_dir_all(&shard)?;
    fs::write(shard.join(&pack_id), &pack)?;

    let index = if version >= 2 {
        serde_json::json!({
            "supersedes": [],
            "packs": [{
                "id": pack_id,
                "blobs": [
                    {"id": data_id, "type": "data", "offset": data_off, "length": data_enc.len(), "uncompressed_length": data_uncomp},
                    {"id": tree_id, "type": "tree", "offset": tree_off, "length": tree_enc.len(), "uncompressed_length": tree_uncomp},
                ]
            }]
        })
    } else {
        serde_json::json!({
            "supersedes": [],
            "packs": [{
                "id": pack_id,
                "blobs": [
                    {"id": data_id, "type": "data", "offset": data_off, "length": data_enc.len()},
                    {"id": tree_id, "type": "tree", "offset": tree_off, "length": tree_enc.len()},
                ]
            }]
        })
    };
    iv[0] = 6;
    let index_enc = seal_unpacked(&master, index.to_string().as_bytes(), version, &iv)?;
    let index_id = hex_encode(&sha256(&index_enc));
    fs::write(dir.join("index").join(&index_id), &index_enc)?;

    let mut snap_ids = Vec::new();
    for (i, time) in ["2020-01-01T00:00:00Z", "2020-06-01T00:00:00Z"]
        .iter()
        .enumerate()
    {
        let snap = serde_json::json!({
            "time": time,
            "tree": tree_id,
            "paths": ["/hello.bin"],
            "hostname": "test",
            "username": "ratarmount",
        });
        iv[0] = 7 + i as u8;
        let snap_enc = seal_unpacked(&master, snap.to_string().as_bytes(), version, &iv)?;
        let snap_id = hex_encode(&sha256(&snap_enc));
        fs::write(dir.join("snapshots").join(&snap_id), &snap_enc)?;
        snap_ids.push(snap_id);
    }

    Ok(SyntheticRepo {
        file_bytes: payload,
        snapshot_ids: snap_ids,
        tree_id,
    })
}

pub struct SyntheticRepo {
    pub file_bytes: Vec<u8>,
    pub snapshot_ids: Vec<String>,
    pub tree_id: String,
}

/// Seekable concatenation of restic data blobs (one blob in memory at a time).
pub struct ResticFile {
    repo: std::sync::Arc<Repo>,
    parts: Vec<(u64, String, u64)>, // file offset, blob id, plain len
    total: u64,
    pos: u64,
    cache: Option<(usize, Vec<u8>)>,
}

impl ResticFile {
    pub fn new(repo: std::sync::Arc<Repo>, blob_ids: Vec<String>) -> Result<Self> {
        let mut parts = Vec::new();
        let mut off = 0u64;
        for id in blob_ids {
            let len = repo.blob_plain_len(&id)?;
            parts.push((off, id, len));
            off = off
                .checked_add(len)
                .ok_or_else(|| ResticError::Msg("file size overflow".into()))?;
        }
        Ok(Self {
            repo,
            parts,
            total: off,
            pos: 0,
            cache: None,
        })
    }
}

impl Read for ResticFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.total || buf.is_empty() {
            return Ok(0);
        }
        let idx = match self
            .parts
            .iter()
            .position(|(start, _, len)| self.pos >= *start && self.pos < start + len)
        {
            Some(i) => i,
            None => return Ok(0),
        };
        if self.cache.as_ref().map(|(i, _)| *i) != Some(idx) {
            let data = self
                .repo
                .read_blob(&self.parts[idx].1)
                .map_err(|e| io::Error::other(e.to_string()))?;
            self.cache = Some((idx, data));
        }
        let (start, _, _) = self.parts[idx];
        let data = &self.cache.as_ref().unwrap().1;
        let inner = (self.pos - start) as usize;
        let n = buf.len().min(data.len().saturating_sub(inner));
        buf[..n].copy_from_slice(&data[inner..inner + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for ResticFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.total as i64 + o,
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

pub fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
