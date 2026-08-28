//! Compact in-memory index: string pool, path segments, SoA rows, dir shards.
//!
//! Fat [`FileInfo`] is materialized only at the list/lookup boundary. Open uses
//! [`CompactOpenCookie`] (offsets/flags) without retaining a pre-cloned `FileInfo`
//! per entry.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    // Inline `const { Cell::new(0) }` needs Rust 1.79+; workspace MSRV is 1.74.
    #[allow(clippy::missing_const_for_thread_local)]
    static TO_FILE_INFO_COUNT: Cell<u64> = Cell::new(0);
}

use ratarmount_core::{CheapSearchHit, FileInfo, SQLiteIndexedTarUserData, UserData};

use crate::search::{locate_pattern_matches, DEFAULT_SEARCH_LIMIT, DUMPDIR_DELETE_LINKNAME};
use crate::FileRow;

/// When directory count exceeds this, entries are stored under hashed shards
/// (still correct list/lookup; denser for wide trees).
pub const DIR_SHARD_THRESHOLD: u32 = 64;

/// Number of shards when sharding is active.
pub const DIR_SHARD_COUNT: u32 = 32;

// ---------------------------------------------------------------------------
// String pool
// ---------------------------------------------------------------------------

/// Build-time HashMap vs post-seal sorted-hash binary search.
#[derive(Debug, Clone)]
enum PoolLookup {
    Build(HashMap<Box<str>, u32>),
    /// `(fnv1a64, id)` sorted by hash then id. Collisions compare slab bytes.
    Sealed(Vec<(u64, u32)>),
}

/// Interned UTF-8 strings stored as a byte slab + `(start, len)` spans.
///
/// Rows keep `u32` ids; [`get`] slices the slab. `Arc<str>` / `String` are
/// materialized only at API boundaries ([`intern`], [`lookup_arc`]). After
/// [`Self::seal`], the build HashMap is dropped and lookup is read-only.
#[derive(Debug, Clone)]
pub struct StringPool {
    slab: Vec<u8>,
    /// `(start, len)` in `slab` for each string id.
    spans: Vec<(u32, u32)>,
    lookup: PoolLookup,
    /// Intern() identity cache (API boundary). Kept after [`Self::seal`] so
    /// ZIP/7z sidecar names that called [`Self::intern`] still `Arc::ptr_eq`
    /// [`Self::lookup_arc`]. The live store is the slab, not this map.
    arcs: Option<HashMap<u32, Arc<str>>>,
}

impl Default for StringPool {
    fn default() -> Self {
        Self::new()
    }
}

fn fnv1a64(s: &str) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl StringPool {
    pub fn new() -> Self {
        let mut by_str = HashMap::new();
        by_str.insert(Box::from(""), 0u32);
        Self {
            slab: Vec::new(),
            spans: vec![(0, 0)],
            lookup: PoolLookup::Build(by_str),
            arcs: Some(HashMap::new()),
        }
    }

    /// Freeze the pool: drop the build HashMap. Interned Arc identity is kept
    /// so `intern` + post-seal `lookup_arc` stay the same allocation.
    pub fn seal(&mut self) {
        if matches!(self.lookup, PoolLookup::Sealed(_)) {
            return;
        }
        self.rebuild_sealed_lookup();
    }

    fn rebuild_sealed_lookup(&mut self) {
        let mut pairs: Vec<(u64, u32)> = (0..self.spans.len() as u32)
            .map(|id| (fnv1a64(self.get(id)), id))
            .collect();
        pairs.sort_unstable_by_key(|&(h, id)| (h, id));
        self.lookup = PoolLookup::Sealed(pairs);
    }

    pub fn is_sealed_slab(&self) -> bool {
        matches!(self.lookup, PoolLookup::Sealed(_))
    }

    fn lookup_id(&self, s: &str) -> Option<u32> {
        match &self.lookup {
            PoolLookup::Build(m) => m.get(s).copied(),
            PoolLookup::Sealed(v) => {
                let h = fnv1a64(s);
                let i = v.partition_point(|&(hv, _)| hv < h);
                for &(hv, id) in &v[i..] {
                    if hv != h {
                        break;
                    }
                    if self.get(id) == s {
                        return Some(id);
                    }
                }
                None
            }
        }
    }

    /// Materialize `Arc<str>` at the API boundary. Repeated intern of the
    /// same bytes returns the same Arc; that identity is kept across
    /// [`Self::seal`] so ZIP/7z sidecars can `Arc::ptr_eq` the pool.
    pub fn intern(&mut self, s: &str) -> Arc<str> {
        let id = self.intern_id(s);
        if let Some(arcs) = &self.arcs {
            if let Some(a) = arcs.get(&id) {
                return Arc::clone(a);
            }
        }
        let a: Arc<str> = Arc::from(self.get(id));
        if let Some(arcs) = &mut self.arcs {
            arcs.insert(id, Arc::clone(&a));
        }
        a
    }

    pub fn intern_id(&mut self, s: &str) -> u32 {
        if let Some(id) = self.lookup_id(s) {
            return id;
        }
        let id = self.spans.len() as u32;
        let start = self.slab.len() as u32;
        self.slab.extend_from_slice(s.as_bytes());
        self.spans.push((start, s.len() as u32));
        let reseal = matches!(self.lookup, PoolLookup::Sealed(_));
        if let PoolLookup::Build(m) = &mut self.lookup {
            m.insert(Box::from(s), id);
        }
        if reseal {
            self.rebuild_sealed_lookup();
        }
        id
    }

    pub fn get(&self, id: u32) -> &str {
        let Some(&(start, len)) = self.spans.get(id as usize) else {
            return "";
        };
        let start = start as usize;
        let end = start + len as usize;
        if end > self.slab.len() {
            return "";
        }
        // Only UTF-8 is written into the slab.
        std::str::from_utf8(&self.slab[start..end]).unwrap_or("")
    }

    /// Resolve an existing pooled string without inserting.
    ///
    /// If the string was [`intern`]ed during build, the same Arc is returned
    /// after seal. Otherwise a fresh Arc is materialized from the slab.
    pub fn lookup_arc(&self, s: &str) -> Option<Arc<str>> {
        let id = self.lookup_id(s)?;
        if let Some(arcs) = &self.arcs {
            if let Some(a) = arcs.get(&id) {
                return Some(Arc::clone(a));
            }
        }
        Some(Arc::from(self.get(id)))
    }

    pub fn unique_count(&self) -> usize {
        self.spans.len()
    }
}

// ---------------------------------------------------------------------------
// Path segments (prefix compression)
// ---------------------------------------------------------------------------

/// Directory path as a chain of segment string-ids (root = empty chain).
///
/// Live store is CSR: `offsets[path_id] .. offsets[path_id+1]` indexes `seg_ids`.
/// Full path strings are not stored once per file; each unique directory is a
/// small id chain. Segments themselves are interned in the string pool.
#[derive(Debug, Clone)]
struct PathTable {
    /// path_id → start in `seg_ids`; extra trailing length (`offsets.len() == path_count + 1`).
    offsets: Vec<u32>,
    /// Concatenated segment string-ids.
    seg_ids: Vec<u32>,
    /// Flattened path string → path_id (for lookup during build / resolve).
    by_flat: HashMap<Box<str>, u32>,
}

impl Default for PathTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PathTable {
    fn new() -> Self {
        // path_id 0 = root ""
        let mut by_flat = HashMap::new();
        by_flat.insert(Box::from(""), 0u32);
        Self {
            offsets: vec![0, 0],
            seg_ids: Vec::new(),
            by_flat,
        }
    }

    fn intern_dir(&mut self, pool: &mut StringPool, dir: &str) -> u32 {
        if let Some(&id) = self.by_flat.get(dir) {
            return id;
        }
        let start = self.seg_ids.len() as u32;
        if !dir.is_empty() {
            // dir may be "/a/b" or "a/b" — strip leading slash for segments
            let d = dir.trim_start_matches('/');
            if !d.is_empty() {
                for part in d.split('/') {
                    if !part.is_empty() {
                        self.seg_ids.push(pool.intern_id(part));
                    }
                }
            }
        }
        let id = (self.offsets.len() - 1) as u32;
        self.offsets.push(self.seg_ids.len() as u32);
        debug_assert_eq!(self.offsets[id as usize], start);
        self.by_flat.insert(Box::from(dir), id);
        id
    }

    fn path_count(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    /// True if path storage is segment-based (not one independent full string per file).
    fn uses_segments(&self) -> bool {
        true
    }

    /// CSR contract: offsets[0]==0, last offset == seg_ids.len(), one extra trailing length.
    fn is_csr(&self) -> bool {
        let n = self.path_count();
        self.offsets.len() == n + 1
            && self.offsets.first().copied() == Some(0)
            && self.offsets.last().copied() == Some(self.seg_ids.len() as u32)
            && self.offsets.windows(2).all(|w| w[0] <= w[1])
    }

    fn segs(&self, path_id: u32) -> &[u32] {
        let i = path_id as usize;
        if i + 1 >= self.offsets.len() {
            return &[];
        }
        let start = self.offsets[i] as usize;
        let end = self.offsets[i + 1] as usize;
        if start > end || end > self.seg_ids.len() {
            return &[];
        }
        &self.seg_ids[start..end]
    }

    /// Reconstruct SQL-style directory path for export (`""` root, else `/a/b`).
    fn flat_string_for_export(&self, pool: &StringPool, path_id: u32) -> String {
        let segs = self.segs(path_id);
        if segs.is_empty() {
            return String::new();
        }
        let mut out = String::from("/");
        for (i, &sid) in segs.iter().enumerate() {
            if i > 0 {
                out.push('/');
            }
            out.push_str(pool.get(sid));
        }
        out
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

/// Cheap readdir entry: pool name + SoA mode/size + open cookie (no [`FileInfo`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexDirent {
    pub name: String,
    pub mode: u32,
    pub size: u64,
    /// Link target (empty if none). Used to hide GNU dumpdir tombstones
    /// without materializing [`FileInfo`].
    pub linkname: String,
    pub cookie: CompactOpenCookie,
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
        #[cfg(test)]
        TO_FILE_INFO_COUNT.with(|c| c.set(c.get() + 1));
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

    /// True when directory prefixes live as CSR `offsets` + `seg_ids` (not `Vec<Vec<u32>>`).
    pub fn path_table_is_csr(&self) -> bool {
        self.paths.is_csr()
    }

    /// True when the string pool is a sealed byte slab (no live `Vec<Arc<str>>` / build HashMap).
    pub fn pool_is_sealed_slab(&self) -> bool {
        self.pool.is_sealed_slab()
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
        self.pool.lookup_id(name)
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
        let dents = self.list_dirents(dir)?;
        Some(dents.into_iter().map(|d| (d.name, d.mode)).collect())
    }

    /// Catalog-wide glob locate over SoA + pool ids (no [`FileInfo`]).
    ///
    /// Walks every version index (not `versions.last()` only). Skips generated
    /// rows, GNU dumpdir tombstones, and empty names. Path strings are cloned
    /// only for emitted hits. Cap is [`DEFAULT_SEARCH_LIMIT`].
    pub fn scan_glob(&self, pattern: &str) -> Vec<CheapSearchHit> {
        if pattern.is_empty() || pattern.starts_with("fts:") {
            return Vec::new();
        }
        let mut hits = Vec::new();
        let mut path_buf = String::new();
        self.for_each_dir(|path_id, de| {
            if hits.len() >= DEFAULT_SEARCH_LIMIT {
                return;
            }
            for (&nid, versions) in &de.names {
                if hits.len() >= DEFAULT_SEARCH_LIMIT {
                    break;
                }
                let name = self.pool.get(nid);
                if name.is_empty() {
                    continue;
                }
                for &soa_idx in versions {
                    if hits.len() >= DEFAULT_SEARCH_LIMIT {
                        break;
                    }
                    let i = soa_idx as usize;
                    if self.soa.flags[i] & 4 != 0 {
                        continue;
                    }
                    let link = self.pool.get(self.soa.linkname_id[i]);
                    if link == DUMPDIR_DELETE_LINKNAME {
                        continue;
                    }
                    self.write_fullpath(&mut path_buf, path_id, name);
                    if locate_pattern_matches(pattern, &path_buf, name) {
                        let oh = self.soa.offsetheader[i];
                        hits.push(CheapSearchHit {
                            path: path_buf.clone(),
                            name: name.to_string(),
                            size: self.soa.size[i] as i64,
                            mtime: self.soa.mtime[i],
                            offsetheader: if oh < 0 { None } else { Some(oh) },
                        });
                    }
                }
            }
        });
        hits.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then(a.offsetheader.cmp(&b.offsetheader))
        });
        hits.truncate(DEFAULT_SEARCH_LIMIT);
        hits
    }

    fn write_fullpath(&self, buf: &mut String, path_id: u32, name: &str) {
        buf.clear();
        let segs = self.paths.segs(path_id);
        if segs.is_empty() {
            buf.push('/');
            buf.push_str(name);
            return;
        }
        buf.push('/');
        for (i, &sid) in segs.iter().enumerate() {
            if i > 0 {
                buf.push('/');
            }
            buf.push_str(self.pool.get(sid));
        }
        buf.push('/');
        buf.push_str(name);
    }

    fn for_each_dir(&self, mut f: impl FnMut(u32, &DirEntries)) {
        if let Some(shards) = &self.shards {
            for sh in shards {
                for (&pid, de) in sh {
                    f(pid, de);
                }
            }
        } else {
            for (&pid, de) in &self.dirs {
                f(pid, de);
            }
        }
    }

    /// Stream name / mode / size / open cookie from the pool + SoA (no [`FileInfo`]).
    pub fn list_dirents(&self, dir: &str) -> Option<Vec<IndexDirent>> {
        let pid = self.resolve_path_id(dir)?;
        let d = self.dir_entries(pid)?;
        let mut out = Vec::with_capacity(d.names.len());
        for (&nid, versions) in &d.names {
            if let Some(&idx) = versions.last() {
                let i = idx as usize;
                out.push(IndexDirent {
                    name: self.pool.get(nid).to_string(),
                    mode: self.soa.mode[i],
                    size: self.soa.size[i],
                    linkname: self.pool.get(self.soa.linkname_id[i]).to_string(),
                    cookie: self.soa.open_cookie(idx),
                });
            }
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    /// Newest-wins row per `(path, name)` across every directory (`versions.last()`).
    ///
    /// Includes dumpdir tombstones and generated rows so callers can apply the
    /// same newest-then-filter rules as mount APIs. Empty names are skipped.
    pub(crate) fn newest_dirents(&self) -> Vec<(String, IndexDirent)> {
        let mut out = Vec::new();
        for pid in self.all_path_ids() {
            let path_str = self.paths.flat_string_for_export(&self.pool, pid);
            let Some(de) = self.dir_entries(pid) else {
                continue;
            };
            for (&nid, versions) in &de.names {
                let Some(&idx) = versions.last() else {
                    continue;
                };
                let i = idx as usize;
                let name = self.pool.get(nid).to_string();
                if name.is_empty() {
                    continue;
                }
                out.push((
                    path_str.clone(),
                    IndexDirent {
                        name,
                        mode: self.soa.mode[i],
                        size: self.soa.size[i],
                        linkname: self.pool.get(self.soa.linkname_id[i]).to_string(),
                        cookie: self.soa.open_cookie(idx),
                    },
                ));
            }
        }
        out
    }

    fn all_path_ids(&self) -> Vec<u32> {
        if let Some(shards) = &self.shards {
            let mut ids = Vec::new();
            for sh in shards {
                ids.extend(sh.keys().copied());
            }
            ids.sort_unstable();
            ids
        } else {
            let mut ids: Vec<u32> = self.dirs.keys().copied().collect();
            ids.sort_unstable();
            ids
        }
    }

    /// Export every version as [`FileRow`]s for durable nested index blobs.
    pub fn export_file_rows(&self) -> Vec<FileRow> {
        let mut rows = Vec::with_capacity(self.count as usize);
        let path_ids: Vec<u32> = if let Some(shards) = &self.shards {
            let mut ids = Vec::new();
            for sh in shards {
                ids.extend(sh.keys().copied());
            }
            ids.sort_unstable();
            ids
        } else {
            let mut ids: Vec<u32> = self.dirs.keys().copied().collect();
            ids.sort_unstable();
            ids
        };
        for pid in path_ids {
            let path_str = self.paths.flat_string_for_export(&self.pool, pid);
            let Some(de) = self.dir_entries(pid) else {
                continue;
            };
            for (&nid, versions) in &de.names {
                let name = self.pool.get(nid).to_string();
                for &idx in versions {
                    let i = idx as usize;
                    let f = self.soa.flags[i];
                    rows.push(FileRow::new(
                        path_str.clone(),
                        name.clone(),
                        self.soa.offsetheader[i],
                        self.soa.offset[i] as i64,
                        self.soa.size[i] as i64,
                        self.soa.mtime[i],
                        self.soa.mode[i] as i64,
                        0,
                        self.pool.get(self.soa.linkname_id[i]).to_string(),
                        self.soa.uid[i] as i64,
                        self.soa.gid[i] as i64,
                        f & 1 != 0,
                        f & 2 != 0,
                        f & 4 != 0,
                        self.soa.recursiondepth[i] as i64,
                    ));
                }
            }
        }
        rows
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
        let mut pool = self.pool;
        pool.seal();
        MemIndex {
            pool,
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
        assert!(
            Arc::ptr_eq(&shared, &again),
            "intern() identity must survive seal for ZIP/7z sidecar sharing"
        );
        assert_eq!(&*again, "member.bin");
    }

    /// Regression: shared parent pool lock — nested compact indexes each own a
    /// private sealed `StringPool`. Two builders filled with the same rows
    /// finish to two sealed slabs; `MemIndexBuilder::new` takes no parent pool
    /// argument, so workers cannot intern member names into a shared parent.
    #[test]
    fn regression_nested_compact_pools_are_per_index() {
        // Compile-time: MemIndexBuilder::new() has no pool / parent parameter.
        let mut left_b = MemIndexBuilder::new();
        let mut right_b = MemIndexBuilder::new();
        let rows = [
            row("/shared/dir", "same.txt", 10),
            row("/shared/dir", "other.txt", 20),
            row("/other", "same.txt", 30),
        ];
        for r in &rows {
            left_b.push_row(r);
            right_b.push_row(r);
        }
        // Per-index intern() identity (ZIP/7z sidecar contract) stays local.
        let left_shared = left_b.intern_shared("same.txt");
        let right_shared = right_b.intern_shared("same.txt");
        let left = left_b.finish();
        let right = right_b.finish();

        assert!(
            left.pool_is_sealed_slab(),
            "left nested compact pool must seal"
        );
        assert!(
            right.pool_is_sealed_slab(),
            "right nested compact pool must seal"
        );
        assert!(
            !left.pool.slab.is_empty() && !right.pool.slab.is_empty(),
            "slabs must hold interned bytes so pointer compare is meaningful"
        );
        assert!(
            !std::ptr::eq(left.pool.slab.as_ptr(), right.pool.slab.as_ptr()),
            "nested compact pools must be distinct slabs, not a shared parent"
        );

        for name in ["same.txt", "other.txt", "shared", "dir", "other"] {
            let id_l = left.pool.lookup_id(name).expect(name);
            let id_r = right.pool.lookup_id(name).expect(name);
            assert_eq!(left.pool.get(id_l), name);
            assert_eq!(right.pool.get(id_r), name);
            assert_eq!(left.pool.get(id_l), right.pool.get(id_r));
        }
        assert_eq!(left.pool_unique_count(), right.pool_unique_count());
        assert!(left.lookup("/shared/dir", "same.txt", 0).is_some());
        assert!(right.lookup("/shared/dir", "same.txt", 0).is_some());

        let left_again = left.lookup_pooled("same.txt").unwrap();
        let right_again = right.lookup_pooled("same.txt").unwrap();
        assert!(
            Arc::ptr_eq(&left_shared, &left_again),
            "intern() identity stays on the left index after seal"
        );
        assert!(
            Arc::ptr_eq(&right_shared, &right_again),
            "intern() identity stays on the right index after seal"
        );
        assert!(
            !Arc::ptr_eq(&left_shared, &right_shared),
            "same logical string must not share Arc identity across indexes"
        );
    }

    /// Regression: finish() must seal the pool as a byte slab and keep PathTable as CSR.
    #[test]
    fn regression_finished_memindex_is_csr_and_sealed_slab() {
        let mut b = MemIndexBuilder::new();
        b.push_row(&row("/a/b", "x.txt", 1));
        b.push_row(&row("/a/b", "y.txt", 2));
        b.push_row(&row("/a/c", "z.txt", 3));
        let mem = b.finish();
        assert!(
            mem.path_table_is_csr(),
            "PathTable live store must be CSR offsets+seg_ids"
        );
        assert!(
            mem.pool_is_sealed_slab(),
            "StringPool must be a sealed slab after finish()"
        );
        assert!(mem.uses_path_segments());
        assert!(mem.is_soa_layout());
        assert_eq!(mem.lookup("/a/b", "x.txt", 0).unwrap().size, 4);
        assert_eq!(
            mem.paths.flat_string_for_export(&mem.pool, 0),
            "",
            "root path_id 0 exports SQL-style empty string"
        );
    }

    /// Regression: list_dirents on a large flat dir must match list()/lookup cookies
    /// without building FileInfo (list_mode is a thin wrapper over list_dirents).
    #[test]
    fn regression_list_dirents_large_flat_dir_matches_list() {
        let mut b = MemIndexBuilder::new();
        for i in 0..220 {
            let mut r = row("/flat", &format!("n{i:04}.dat"), i as i64 * 10);
            r.size = 100 + i as i64;
            r.mode = if i % 2 == 0 { 0o100644 } else { 0o100755 };
            b.push_row(&r);
        }
        let mem = b.finish();
        assert!(mem.path_table_is_csr());
        assert!(mem.pool_is_sealed_slab());

        let dents = mem
            .list_dirents("/flat")
            .expect("list_dirents on 220-name dir");
        assert_eq!(dents.len(), 220);
        let listed = mem.list("/flat").expect("list");
        assert_eq!(listed.len(), 220);
        let modes = mem
            .list_mode("/flat")
            .expect("list_mode wraps list_dirents");
        assert_eq!(modes.len(), 220);

        for d in &dents {
            let fi = listed
                .get(&d.name)
                .expect("name from list_dirents in list()");
            assert_eq!(d.mode, fi.mode, "mode {}", d.name);
            assert_eq!(d.size, fi.size, "size {}", d.name);
            assert_eq!(d.linkname, fi.linkname, "linkname {}", d.name);
            assert_eq!(modes.get(&d.name).copied(), Some(d.mode));
            let cookie = mem
                .lookup_open_cookie("/flat", &d.name, 0)
                .expect("lookup_open_cookie");
            assert_eq!(d.cookie, cookie, "cookie {}", d.name);
        }
    }

    fn take_to_file_info_count() -> u64 {
        TO_FILE_INFO_COUNT.with(|c| c.replace(0))
    }

    fn cheap_paths(hits: &[CheapSearchHit]) -> Vec<&str> {
        hits.iter().map(|h| h.path.as_str()).collect()
    }

    fn generated_row(path: &str, name: &str, oh: i64) -> FileRow {
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
            true,
            0,
        )
    }

    fn dumpdir_row(name: &str, oh: i64) -> FileRow {
        FileRow::new(
            "",
            name,
            oh,
            oh + 32,
            0,
            1.0,
            0o100644,
            0,
            DUMPDIR_DELETE_LINKNAME,
            0,
            0,
            false,
            false,
            false,
            0,
        )
    }

    /// Regression: SoA `scan_glob` matches SQL GLOB twins without `FileInfo`.
    #[test]
    fn scan_glob_twins_search_glob() {
        let mut b = MemIndexBuilder::new();
        b.push_row(&row("", "a.fits", 0));
        b.push_row(&row("/dir", "b.fits", 512));
        b.push_row(&row("", "readme.txt", 1024));
        b.push_row(&row("/dir", "nested.txt", 1536));
        let mem = b.finish();
        let _ = take_to_file_info_count();

        let hits = mem.scan_glob("*.fits");
        assert_eq!(
            take_to_file_info_count(),
            0,
            "scan_glob must not build FileInfo"
        );
        let paths: Vec<&str> = hits.iter().map(|h| h.path.as_str()).collect();
        assert_eq!(paths, vec!["/a.fits", "/dir/b.fits"]);
        assert_eq!(hits[0].name, "a.fits");
        assert_eq!(hits[0].size, 4);
        assert_eq!(hits[0].mtime, 1.0);
        assert_eq!(hits[0].offsetheader, Some(0));

        let dir = mem.scan_glob("/dir/*");
        assert_eq!(cheap_paths(&dir), vec!["/dir/b.fits", "/dir/nested.txt"]);

        let rel = mem.scan_glob("dir/*.fits");
        assert_eq!(cheap_paths(&rel), vec!["/dir/b.fits"]);

        let exact = mem.scan_glob("readme.txt");
        assert_eq!(cheap_paths(&exact), vec!["/readme.txt"]);

        let stars = mem.scan_glob("**/*.fits");
        assert_eq!(
            cheap_paths(&stars),
            vec!["/dir/b.fits"],
            "** collapses to *; slash means full-path GLOB /*/*.fits"
        );

        let like = mem.scan_glob("%.txt");
        assert_eq!(cheap_paths(&like), vec!["/dir/nested.txt", "/readme.txt"]);

        assert!(mem.scan_glob("nope").is_empty());
        assert!(mem.scan_glob("").is_empty());
        assert!(mem.scan_glob("fts:fits").is_empty());
    }

    /// Regression: generated parents and dumpdir tombstones are not SoA locate hits.
    #[test]
    fn scan_glob_skips_generated() {
        let mut b = MemIndexBuilder::new();
        b.push_row(&row("", "keep.fits", 0));
        b.push_row(&generated_row("", "ghost.fits", 512));
        b.push_row(&dumpdir_row("deleted.fits", 1024));
        let mem = b.finish();
        let hits = mem.scan_glob("*.fits");
        assert_eq!(cheap_paths(&hits), vec!["/keep.fits"]);
    }

    /// Regression: two offsetheaders, same catalog path — SoA emits both rows.
    #[test]
    fn scan_glob_two_offsetheader_same_path() {
        let mut b = MemIndexBuilder::new();
        b.push_row(&row("/dir", "a.fits", 0));
        b.push_row(&row("/dir", "a.fits", 512));
        let mem = b.finish();
        let hits = mem.scan_glob("*.fits");
        assert_eq!(hits.len(), 2, "every version index, not last-only");
        assert_eq!(hits[0].offsetheader, Some(0));
        assert_eq!(hits[1].offsetheader, Some(512));
        assert_eq!(hits[0].path, "/dir/a.fits");
        assert_eq!(hits[1].path, "/dir/a.fits");
    }

    /// Regression: locate `*.fits` on a 200k-row synthetic SoA builds 0 FileInfo.
    #[test]
    fn scan_glob_200k_synthetic_no_fileinfo() {
        let n: u32 = 200_000;
        let mut b = MemIndexBuilder::new();
        for i in 0..n {
            let name = if i % 100 == 0 {
                format!("f{i}.fits")
            } else {
                format!("f{i}.dat")
            };
            b.push_row(&row("", &name, i64::from(i) * 512));
        }
        let mem = b.finish();
        let _ = take_to_file_info_count();

        let hits = mem.scan_glob("*.fits");
        assert_eq!(
            take_to_file_info_count(),
            0,
            "scan_glob FileInfo-count must be 0"
        );
        assert_eq!(hits.len(), 2_000, "1% of 200k are *.fits");
        assert!(hits.iter().all(|h| h.path.ends_with(".fits")));

        let dense = mem.scan_glob("*");
        assert_eq!(take_to_file_info_count(), 0);
        assert_eq!(
            dense.len(),
            DEFAULT_SEARCH_LIMIT,
            "dense * still 0 FileInfo; cap at DEFAULT_SEARCH_LIMIT"
        );

        let listed = mem.list("/").expect("fat list");
        assert_eq!(
            take_to_file_info_count(),
            u64::from(n),
            "fat list() FileInfo count == N"
        );
        assert_eq!(listed.len(), n as usize);
    }
}
