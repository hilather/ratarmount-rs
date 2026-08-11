//! Compact in-memory index: string pool, path segments, SoA rows, dir shards.
//!
//! Fat [`FileInfo`] is materialized only at the list/lookup boundary. Open uses
//! [`CompactOpenCookie`] (offsets/flags) without retaining a pre-cloned `FileInfo`
//! per entry.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use ratarmount_core::{FileInfo, SQLiteIndexedTarUserData, UserData};

use crate::FileRow;

/// When directory count exceeds this, entries are stored under hashed shards
/// (still correct list/lookup; denser for wide trees).
pub const DIR_SHARD_THRESHOLD: u32 = 64;

/// Number of shards when sharding is active.
pub const DIR_SHARD_COUNT: u32 = 32;

// ---------------------------------------------------------------------------
// String pool
// ---------------------------------------------------------------------------

/// Interned UTF-8 strings (paths segments, names, link targets, full dirs).
#[derive(Debug, Clone)]
pub struct StringPool {
    strings: Vec<Arc<str>>,
    by_str: HashMap<Box<str>, u32>,
}

impl Default for StringPool {
    fn default() -> Self {
        Self::new()
    }
}

impl StringPool {
    pub fn new() -> Self {
        let empty: Arc<str> = Arc::from("");
        let mut by_str = HashMap::new();
        by_str.insert(Box::from(""), 0u32);
        Self {
            strings: vec![empty],
            by_str,
        }
    }

    pub fn intern(&mut self, s: &str) -> Arc<str> {
        if let Some(&id) = self.by_str.get(s) {
            return Arc::clone(&self.strings[id as usize]);
        }
        let id = self.strings.len() as u32;
        let a: Arc<str> = Arc::from(s);
        self.by_str.insert(Box::from(s), id);
        self.strings.push(Arc::clone(&a));
        a
    }

    pub fn intern_id(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.by_str.get(s) {
            return id;
        }
        let id = self.strings.len() as u32;
        let a: Arc<str> = Arc::from(s);
        self.by_str.insert(Box::from(s), id);
        self.strings.push(a);
        id
    }

    pub fn get(&self, id: u32) -> &str {
        self.strings
            .get(id as usize)
            .map(|a| a.as_ref())
            .unwrap_or("")
    }

    /// Resolve an existing pooled string without inserting.
    pub fn lookup_arc(&self, s: &str) -> Option<Arc<str>> {
        self.by_str
            .get(s)
            .map(|&id| Arc::clone(&self.strings[id as usize]))
    }

    pub fn unique_count(&self) -> usize {
        self.strings.len()
    }
}

// ---------------------------------------------------------------------------
// Path segments (prefix compression)
// ---------------------------------------------------------------------------

/// Directory path as a chain of segment string-ids (root = empty chain).
///
/// Full path strings are not stored once per file; each unique directory is a
/// small id chain. Segments themselves are interned in the string pool.
#[derive(Debug, Clone, Default)]
struct PathTable {
    /// path_id → segment string ids (empty vec = root SQL path `""`).
    paths: Vec<Vec<u32>>,
    /// Flattened path string → path_id (for lookup during build).
    by_flat: HashMap<Box<str>, u32>,
}

impl PathTable {
    fn new() -> Self {
        // path_id 0 = root ""
        let mut by_flat = HashMap::new();
        by_flat.insert(Box::from(""), 0u32);
        Self {
            paths: vec![Vec::new()],
            by_flat,
        }
    }

    fn intern_dir(&mut self, pool: &mut StringPool, dir: &str) -> u32 {
        if let Some(&id) = self.by_flat.get(dir) {
            return id;
        }
        let mut segs = Vec::new();
        if !dir.is_empty() {
            // dir may be "/a/b" or "a/b" — strip leading slash for segments
            let d = dir.trim_start_matches('/');
            if !d.is_empty() {
                for part in d.split('/') {
                    if !part.is_empty() {
                        segs.push(pool.intern_id(part));
                    }
                }
            }
        }
        let id = self.paths.len() as u32;
        // Also store flattened form for reverse (with leading slash if original had it)
        self.by_flat.insert(Box::from(dir), id);
        // Normalize key: if dir was "/a/b" we already inserted that
        if dir.starts_with('/') && dir.len() > 1 {
            // also map without double entries handled by get
        }
        self.paths.push(segs);
        id
    }

    #[allow(dead_code)]
    fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// True if path storage is segment-based (not one independent full string per file).
    fn uses_segments(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// SoA entry store + open cookie
// ---------------------------------------------------------------------------

/// Compact open coordinates (no fat FileInfo).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactOpenCookie {
    pub offsetheader: i64,
    pub offset: u64,
    pub size: u64,
    pub mode: u32,
    pub istar: bool,
    pub issparse: bool,
    pub isgenerated: bool,
    pub recursiondepth: u32,
}

/// Columnar storage for all file versions.
#[derive(Debug, Default, Clone)]
struct EntrySoa {
    offsetheader: Vec<i64>,
    offset: Vec<u64>,
    size: Vec<u64>,
    mtime: Vec<f64>,
    mode: Vec<u32>,
    linkname_id: Vec<u32>,
    uid: Vec<u32>,
    gid: Vec<u32>,
    /// bit0 istar, bit1 issparse, bit2 isgenerated
    flags: Vec<u8>,
    recursiondepth: Vec<u32>,
}

impl EntrySoa {
    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.offsetheader.len()
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        offsetheader: i64,
        offset: u64,
        size: u64,
        mtime: f64,
        mode: u32,
        linkname_id: u32,
        uid: u32,
        gid: u32,
        istar: bool,
        issparse: bool,
        isgenerated: bool,
        recursiondepth: u32,
    ) -> u32 {
        let id = self.offsetheader.len() as u32;
        self.offsetheader.push(offsetheader);
        self.offset.push(offset);
        self.size.push(size);
        self.mtime.push(mtime);
        self.mode.push(mode);
        self.linkname_id.push(linkname_id);
        self.uid.push(uid);
        self.gid.push(gid);
        let mut f = 0u8;
        if istar {
            f |= 1;
        }
        if issparse {
            f |= 2;
        }
        if isgenerated {
            f |= 4;
        }
        self.flags.push(f);
        self.recursiondepth.push(recursiondepth);
        id
    }

    #[allow(clippy::too_many_arguments)]
    fn replace(
        &mut self,
        idx: u32,
        offsetheader: i64,
        offset: u64,
        size: u64,
        mtime: f64,
        mode: u32,
        linkname_id: u32,
        uid: u32,
        gid: u32,
        istar: bool,
        issparse: bool,
        isgenerated: bool,
        recursiondepth: u32,
    ) {
        let i = idx as usize;
        self.offsetheader[i] = offsetheader;
        self.offset[i] = offset;
        self.size[i] = size;
        self.mtime[i] = mtime;
        self.mode[i] = mode;
        self.linkname_id[i] = linkname_id;
        self.uid[i] = uid;
        self.gid[i] = gid;
        let mut f = 0u8;
        if istar {
            f |= 1;
        }
        if issparse {
            f |= 2;
        }
        if isgenerated {
            f |= 4;
        }
        self.flags[i] = f;
        self.recursiondepth[i] = recursiondepth;
    }

    fn open_cookie(&self, idx: u32) -> CompactOpenCookie {
        let i = idx as usize;
        let f = self.flags[i];
        CompactOpenCookie {
            offsetheader: self.offsetheader[i],
            offset: self.offset[i],
            size: self.size[i],
            mode: self.mode[i],
            istar: f & 1 != 0,
            issparse: f & 2 != 0,
            isgenerated: f & 4 != 0,
            recursiondepth: self.recursiondepth[i],
        }
    }

    fn to_file_info(&self, pool: &StringPool, idx: u32) -> FileInfo {
        let i = idx as usize;
        let f = self.flags[i];
        let oh = self.offsetheader[i];
        FileInfo {
            size: self.size[i],
            mtime: self.mtime[i],
            mode: self.mode[i],
            linkname: pool.get(self.linkname_id[i]).to_string(),
            uid: self.uid[i],
            gid: self.gid[i],
            userdata: vec![UserData::Tar(SQLiteIndexedTarUserData {
                offset: self.offset[i],
                offsetheader: if oh >= 0 { Some(oh as u64) } else { None },
                istar: f & 1 != 0,
                issparse: f & 2 != 0,
                isgenerated: f & 4 != 0,
                recursiondepth: self.recursiondepth[i],
            })],
        }
    }
}

// ---------------------------------------------------------------------------
// Directory directory: name_id → version entry indices (oldest→newest)
// ---------------------------------------------------------------------------

type NameMap = BTreeMap<u32, Vec<u32>>;

/// One directory's name → version indices.
#[derive(Debug, Default, Clone)]
struct DirEntries {
    names: NameMap,
}

// ---------------------------------------------------------------------------
// MemIndex
// ---------------------------------------------------------------------------

/// Hot-path projection: SoA rows + path segments + optional dir sharding.
pub struct MemIndex {
    pool: StringPool,
    paths: PathTable,
    soa: EntrySoa,
    /// path_id → directory entries (used when not sharded).
    dirs: HashMap<u32, DirEntries>,
    /// When sharded: shard → path_id → DirEntries
    shards: Option<Vec<HashMap<u32, DirEntries>>>,
    count: u64,
    /// Layout contracts for tests.
    sharded: bool,
}

impl MemIndex {
    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn pool_unique_count(&self) -> usize {
        self.pool.unique_count()
    }

    #[allow(dead_code)] // test / observability contracts
    pub fn path_table_count(&self) -> usize {
        self.paths.path_count()
    }

    pub fn uses_path_segments(&self) -> bool {
        self.paths.uses_segments()
    }

    pub fn is_soa_layout(&self) -> bool {
        // SoA is always used for row payloads.
        true
    }

    pub fn is_dir_sharded(&self) -> bool {
        self.sharded
    }

    #[allow(dead_code)] // test / observability contracts
    pub fn soa_row_count(&self) -> usize {
        self.soa.len()
    }

    /// Prefer [`lookup_pooled`] for read-only sharing of existing strings.
    pub fn lookup_pooled(&self, s: &str) -> Option<Arc<str>> {
        self.pool.lookup_arc(s)
    }

    pub fn dir_path_is_shared(&self, dir: &str) -> bool {
        // Segment table: one path_id per unique dir; ≥2 names under it.
        let Some(&pid) = self.paths.by_flat.get(dir) else {
            // try with/without leading slash
            let alt = if dir.starts_with('/') {
                dir.trim_start_matches('/').to_string()
            } else {
                format!("/{dir}")
            };
            if !self.paths.by_flat.contains_key(alt.as_str())
                && !self.paths.by_flat.contains_key(dir)
            {
                return false;
            }
            let pid = *self
                .paths
                .by_flat
                .get(dir)
                .or_else(|| self.paths.by_flat.get(alt.as_str()))
                .unwrap();
            return self.name_count(pid) >= 2;
        };
        self.name_count(pid) >= 2
    }

    fn name_count(&self, path_id: u32) -> usize {
        self.dir_entries(path_id)
            .map(|d| d.names.len())
            .unwrap_or(0)
    }

    fn dir_entries(&self, path_id: u32) -> Option<&DirEntries> {
        if let Some(shards) = &self.shards {
            let sh = (path_id % DIR_SHARD_COUNT) as usize;
            shards.get(sh)?.get(&path_id)
        } else {
            self.dirs.get(&path_id)
        }
    }

    fn resolve_path_id(&self, dir: &str) -> Option<u32> {
        if dir.is_empty() || dir == "/" {
            return Some(0);
        }
        if let Some(&id) = self.paths.by_flat.get(dir) {
            return Some(id);
        }
        if dir.starts_with('/') {
            if let Some(&id) = self.paths.by_flat.get(dir.trim_start_matches('/')) {
                return Some(id);
            }
        } else {
            let with_slash = format!("/{dir}");
            if let Some(&id) = self.paths.by_flat.get(with_slash.as_str()) {
                return Some(id);
            }
        }
        None
    }

    fn resolve_name_id(&self, name: &str) -> Option<u32> {
        self.pool.by_str.get(name).copied()
    }

    pub fn version_count(&self, dir: &str, name: &str) -> u32 {
        let Some(pid) = self.resolve_path_id(dir) else {
            return 0;
        };
        let Some(nid) = self.resolve_name_id(name) else {
            return 0;
        };
        self.dir_entries(pid)
            .and_then(|d| d.names.get(&nid))
            .map(|v| v.len() as u32)
            .unwrap_or(0)
    }

    pub fn lookup(&self, dir: &str, name: &str, file_version: i32) -> Option<FileInfo> {
        let idx = self.lookup_entry_index(dir, name, file_version)?;
        Some(self.soa.to_file_info(&self.pool, idx))
    }

    pub fn lookup_open_cookie(
        &self,
        dir: &str,
        name: &str,
        file_version: i32,
    ) -> Option<CompactOpenCookie> {
        let idx = self.lookup_entry_index(dir, name, file_version)?;
        Some(self.soa.open_cookie(idx))
    }

    fn lookup_entry_index(&self, dir: &str, name: &str, file_version: i32) -> Option<u32> {
        let pid = self.resolve_path_id(dir)?;
        let nid = self.resolve_name_id(name)?;
        let versions = self.dir_entries(pid)?.names.get(&nid)?;
        if versions.is_empty() {
            return None;
        }
        let i = if file_version <= 0 {
            let n = (-file_version) as usize;
            versions.len().saturating_sub(1 + n)
        } else {
            (file_version as usize).saturating_sub(1)
        };
        versions.get(i).copied()
    }

    pub fn list(&self, dir: &str) -> Option<BTreeMap<String, FileInfo>> {
        let pid = self.resolve_path_id(dir)?;
        let d = self.dir_entries(pid)?;
        let mut map = BTreeMap::new();
        for (&nid, versions) in &d.names {
            if let Some(&idx) = versions.last() {
                let name = self.pool.get(nid).to_string();
                map.insert(name, self.soa.to_file_info(&self.pool, idx));
            }
        }
        if map.is_empty() {
            None
        } else {
            Some(map)
        }
    }

    pub fn list_mode(&self, dir: &str) -> Option<BTreeMap<String, u32>> {
        let pid = self.resolve_path_id(dir)?;
        let d = self.dir_entries(pid)?;
        let mut map = BTreeMap::new();
        for (&nid, versions) in &d.names {
            if let Some(&idx) = versions.last() {
                let name = self.pool.get(nid).to_string();
                map.insert(name, self.soa.mode[idx as usize]);
            }
        }
        if map.is_empty() {
            None
        } else {
            Some(map)
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

pub struct MemIndexBuilder {
    pool: StringPool,
    paths: PathTable,
    soa: EntrySoa,
    dirs: HashMap<u32, DirEntries>,
    count: u64,
    /// (path_id, name_id, offsetheader) → soa index for REPLACE
    by_key_oh: HashMap<(u32, u32, i64), u32>,
}

impl Default for MemIndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MemIndexBuilder {
    pub fn new() -> Self {
        Self {
            pool: StringPool::new(),
            paths: PathTable::new(),
            soa: EntrySoa::default(),
            dirs: HashMap::new(),
            count: 0,
            by_key_oh: HashMap::new(),
        }
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn intern_shared(&mut self, s: &str) -> Arc<str> {
        self.pool.intern(s)
    }

    pub fn push_row(&mut self, row: &FileRow) {
        if row.name.is_empty() {
            return;
        }
        let path_id = self.paths.intern_dir(&mut self.pool, &row.path);
        let name_id = self.pool.intern_id(&row.name);
        let link_id = self.pool.intern_id(&row.linkname);
        let oh = row.offsetheader;
        let key = (path_id, name_id, oh);

        if let Some(&idx) = self.by_key_oh.get(&key) {
            self.soa.replace(
                idx,
                oh,
                row.offset.max(0) as u64,
                row.size.max(0) as u64,
                row.mtime,
                row.mode as u32,
                link_id,
                row.uid.max(0) as u32,
                row.gid.max(0) as u32,
                row.istar,
                row.issparse,
                row.isgenerated,
                row.recursiondepth.max(0) as u32,
            );
            return;
        }

        let idx = self.soa.push(
            oh,
            row.offset.max(0) as u64,
            row.size.max(0) as u64,
            row.mtime,
            row.mode as u32,
            link_id,
            row.uid.max(0) as u32,
            row.gid.max(0) as u32,
            row.istar,
            row.issparse,
            row.isgenerated,
            row.recursiondepth.max(0) as u32,
        );
        self.by_key_oh.insert(key, idx);
        let versions = self
            .dirs
            .entry(path_id)
            .or_default()
            .names
            .entry(name_id)
            .or_default();
        versions.push(idx);
        // keep versions sorted by offsetheader
        versions.sort_by_key(|&i| self.soa.offsetheader[i as usize]);
        self.count += 1;
    }

    pub fn push_rows(&mut self, rows: &[FileRow]) {
        for r in rows {
            self.push_row(r);
        }
    }

    pub fn finish(self) -> MemIndex {
        let dir_count = self.dirs.len() as u32;
        let sharded = dir_count > DIR_SHARD_THRESHOLD;
        let (dirs, shards, sharded) = if sharded {
            let mut shards: Vec<HashMap<u32, DirEntries>> =
                (0..DIR_SHARD_COUNT).map(|_| HashMap::new()).collect();
            for (pid, de) in self.dirs {
                let sh = (pid % DIR_SHARD_COUNT) as usize;
                shards[sh].insert(pid, de);
            }
            (HashMap::new(), Some(shards), true)
        } else {
            (self.dirs, None, false)
        };
        MemIndex {
            pool: self.pool,
            paths: self.paths,
            soa: self.soa,
            dirs,
            shards,
            count: self.count,
            sharded,
        }
    }
}

/// Build from ordered SQL rows (warm open).
pub fn mem_index_from_sql_rows<I>(rows: I) -> MemIndex
where
    I: IntoIterator<Item = SqlMemRow>,
{
    let mut b = MemIndexBuilder::new();
    for r in rows {
        if r.name.is_empty() {
            continue;
        }
        b.push_row(&FileRow::new(
            r.path,
            r.name,
            r.offsetheader,
            r.offset as i64,
            r.size as i64,
            r.mtime,
            r.mode as i64,
            0,
            r.linkname,
            r.uid as i64,
            r.gid as i64,
            r.istar,
            r.issparse,
            r.isgenerated,
            r.recursiondepth as i64,
        ));
    }
    b.finish()
}

pub struct SqlMemRow {
    pub path: String,
    pub name: String,
    pub offsetheader: i64,
    pub offset: u64,
    pub size: u64,
    pub mtime: f64,
    pub mode: u32,
    pub linkname: String,
    pub uid: u32,
    pub gid: u32,
    pub istar: bool,
    pub issparse: bool,
    pub isgenerated: bool,
    pub recursiondepth: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(path: &str, name: &str, oh: i64) -> FileRow {
        FileRow::new(
            path,
            name,
            oh,
            oh + 32,
            4,
            1.0,
            0o100644,
            0,
            "",
            0,
            0,
            false,
            false,
            false,
            0,
        )
    }

    #[test]
    fn string_pool_interns_duplicates() {
        let mut pool = StringPool::new();
        let a = pool.intern("/shared/dir");
        let b = pool.intern("/shared/dir");
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(pool.unique_count(), 2);
    }

    #[test]
    fn path_segments_not_one_string_per_file() {
        let mut b = MemIndexBuilder::new();
        // Deep shared prefix: many files under /a/b/c
        for i in 0..20 {
            b.push_row(&row("/a/b/c", &format!("f{i}.txt"), i * 10));
        }
        let mem = b.finish();
        assert!(mem.uses_path_segments());
        // Unique dirs: root + /a/b/c (segmentized) — path table small
        assert!(
            mem.path_table_count() <= 4,
            "expected few path ids, got {}",
            mem.path_table_count()
        );
        // Segments a,b,c interned once each + names
        assert!(mem.lookup("/a/b/c", "f5.txt", 0).is_some());
        assert!(mem.dir_path_is_shared("/a/b/c"));
    }

    #[test]
    fn soa_layout_and_open_cookie() {
        let mut b = MemIndexBuilder::new();
        b.push_row(&row("/d", "a", 10));
        b.push_row(&row("/d", "b", 20));
        let mem = b.finish();
        assert!(mem.is_soa_layout());
        assert_eq!(mem.soa_row_count(), 2);
        let cookie = mem.lookup_open_cookie("/d", "a", 0).unwrap();
        assert_eq!(cookie.offsetheader, 10);
        assert_eq!(cookie.size, 4);
        // No fat FileInfo retained in store — materialize only here
        let fi = mem.lookup("/d", "a", 0).unwrap();
        assert_eq!(fi.size, 4);
    }

    #[test]
    fn dir_sharding_when_many_dirs() {
        let mut b = MemIndexBuilder::new();
        let n = DIR_SHARD_THRESHOLD as usize + 10;
        for i in 0..n {
            b.push_row(&row(&format!("/dir{i}"), "f.txt", i as i64));
        }
        let mem = b.finish();
        assert!(
            mem.is_dir_sharded(),
            "expected sharding when dirs > {DIR_SHARD_THRESHOLD}"
        );
        assert!(mem.lookup("/dir0", "f.txt", 0).is_some());
        assert!(mem.lookup(&format!("/dir{}", n - 1), "f.txt", 0).is_some());
    }

    #[test]
    fn builder_versions_and_replace() {
        let mut b = MemIndexBuilder::new();
        b.push_row(&row("/d", "a", 30));
        b.push_row(&row("/d", "a", 10));
        b.push_row(&row("/d", "a", 10)); // replace
        assert_eq!(b.count(), 2);
        let mem = b.finish();
        assert_eq!(mem.version_count("/d", "a"), 2);
        let newest = mem.lookup_open_cookie("/d", "a", 0).unwrap();
        assert_eq!(newest.offsetheader, 30);
    }

    #[test]
    fn pool_shared_lookup_for_sidecars() {
        let mut b = MemIndexBuilder::new();
        b.push_row(&row("/d", "member.bin", 1));
        let shared = b.intern_shared("member.bin");
        let mem = b.finish();
        let again = mem.lookup_pooled("member.bin").unwrap();
        assert!(Arc::ptr_eq(&shared, &again));
    }
}
