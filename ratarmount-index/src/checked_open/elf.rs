//! Bounded inspection of a loaded ELF image's dynamic section (r11 S6, scoped
//! by issue #192).
//!
//! Two uses:
//!
//! * **Linux private-instance export inspection** ([`image_exports_no_sqlite`]):
//!   every defined, externally bindable dynamic symbol of the proof image is
//!   read, and any name starting with `sqlite3` (ASCII case-insensitive)
//!   refuses. This replaces the one-name `dlsym("sqlite3_libversion")` probe
//!   on Linux. It is a named-export property, not an absence of differently
//!   named access paths.
//! * **Initialization check, option (b)** ([`check_initialization`]): a
//!   given constructor is entry zero of the image's init array, and a
//!   `DT_INIT`, when present, is not the address of an exported symbol. The
//!   address of glibc's CRT `_init` is a hidden symbol, so it passes; an
//!   exported custom initializer (`-Wl,-init=name`) refuses. `_init` is never
//!   looked up with `dlsym`. This proves array position and an address
//!   comparison only: hidden custom initializers, `.init` fragments,
//!   profiling callbacks and dependency initializers that publish the image
//!   remain assumptions (issue #192 closed the arbitrary-DSO exclusivity
//!   proof as not implementable). No installation path calls it: the
//!   loader-private path it was designed for is not built, and the tests use
//!   it to show what it does and does not see.
//!
//! Every read is checked against the image's readable `PT_LOAD` ranges with
//! checked arithmetic; tables, chains and names are bounded by explicit work
//! limits, and partial inspection never accepts. No section headers, no
//! `.symtab`, no reopening of the file. The byte reader is portable (tests
//! build synthetic images); the live image is read only on 64-bit
//! little-endian Linux glibc.

use std::fmt;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const PF_R: u32 = 4;

const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_INIT: i64 = 12;
const DT_INIT_ARRAY: i64 = 25;
const DT_INIT_ARRAYSZ: i64 = 27;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

const SYM_SIZE: usize = 24;
const DYN_SIZE: usize = 16;

const SHN_UNDEF: u16 = 0;
const SHN_LORESERVE: u16 = 0xff00;
const SHN_ABS: u16 = 0xfff1;
const SHN_XINDEX: u16 = 0xffff;

const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STB_GNU_UNIQUE: u8 = 10;
const STV_INTERNAL: u8 = 1;
const STV_HIDDEN: u8 = 2;
const STT_TLS: u8 = 6;

/// Work limits (S6 addendum §3); exceeding one refuses.
pub(crate) const MAX_PHDRS: usize = 1024;
pub(crate) const MAX_LOADS: usize = 16;
pub(crate) const MAX_DYNAMIC: usize = 4096;
pub(crate) const MAX_SYMBOLS: usize = 1 << 20;
pub(crate) const MAX_NAME_BYTES: usize = 64 << 20;
pub(crate) const MAX_HASH_STEPS: usize = 4_194_304;

/// The first bytes of a symbol name, for diagnostics. Truncation affects the
/// message only; the inspection reads every name to its terminator.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SymbolName {
    bytes: [u8; 32],
    len: u8,
    truncated: bool,
}

impl SymbolName {
    pub(crate) fn from_prefix(prefix: &[u8], truncated: bool) -> Self {
        let mut bytes = [0u8; 32];
        let len = prefix.len().min(32);
        bytes[..len].copy_from_slice(&prefix[..len]);
        Self {
            bytes,
            len: len as u8,
            truncated: truncated || prefix.len() > 32,
        }
    }

    /// The recorded bytes (at most 32).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The name is longer than [`Self::as_bytes`].
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

impl fmt::Display for SymbolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.as_bytes()))?;
        if self.truncated {
            write!(f, "...")?;
        }
        Ok(())
    }
}

impl fmt::Debug for SymbolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_string())
    }
}

/// Why an image could not be inspected. Every variant refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    Missing(&'static str),
    Malformed(&'static str),
    Bounds(&'static str),
    AmbiguousPointer(&'static str),
    Unsupported(&'static str),
    WorkLimit(&'static str),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(what) => write!(f, "no {what}"),
            Self::Malformed(what) => write!(f, "malformed {what}"),
            Self::Bounds(what) => write!(f, "{what} is outside the image's readable segments"),
            Self::AmbiguousPointer(what) => {
                write!(f, "{what} is mapped both as a raw and a relocated address")
            }
            Self::Unsupported(what) => write!(f, "unsupported {what}"),
            Self::WorkLimit(what) => write!(f, "too many {what} to inspect"),
        }
    }
}

/// One program header, as far as the inspection needs it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Phdr {
    pub(crate) p_type: u32,
    pub(crate) flags: u32,
    pub(crate) vaddr: u64,
    pub(crate) memsz: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct Segment {
    start: usize,
    end: usize,
    flags: u32,
}

/// A loaded image: its identity (the program-header address the loader
/// reports, as in [`super::host::ImageIdentity`]), load bias, `PT_LOAD`
/// ranges and `PT_DYNAMIC` range. `bytes` is `None` for the live image (read
/// in place) and a synthetic image's `(base address, contents)` in tests.
#[derive(Clone, Copy)]
pub(crate) struct ElfImage<'a> {
    pub(crate) id: usize,
    pub(crate) bias: usize,
    loads: [Segment; MAX_LOADS],
    nloads: usize,
    dynamic: usize,
    dynamic_len: usize,
    bytes: Option<(usize, &'a [u8])>,
}

impl<'a> ElfImage<'a> {
    /// Build from the loader's program headers (`phnum` of them).
    pub(crate) fn from_phdrs(
        id: usize,
        bias: usize,
        phnum: usize,
        phdrs: impl Iterator<Item = Phdr>,
        bytes: Option<(usize, &'a [u8])>,
    ) -> Result<Self, ElfError> {
        if phnum > MAX_PHDRS {
            return Err(ElfError::WorkLimit("program headers"));
        }
        let mut image = Self {
            id,
            bias,
            loads: [Segment::default(); MAX_LOADS],
            nloads: 0,
            dynamic: 0,
            dynamic_len: 0,
            bytes,
        };
        let mut dynamic = None;
        for ph in phdrs.take(phnum) {
            let range = || {
                let start = usize::try_from(ph.vaddr)
                    .ok()
                    .and_then(|v| bias.checked_add(v))?;
                let len = usize::try_from(ph.memsz).ok()?;
                Some((start, start.checked_add(len)?))
            };
            match ph.p_type {
                PT_LOAD => {
                    let (start, end) = range().ok_or(ElfError::Bounds("load segment"))?;
                    if image.nloads == MAX_LOADS {
                        return Err(ElfError::WorkLimit("load segments"));
                    }
                    image.loads[image.nloads] = Segment {
                        start,
                        end,
                        flags: ph.flags,
                    };
                    image.nloads += 1;
                }
                PT_DYNAMIC => {
                    if dynamic.is_some() {
                        return Err(ElfError::Malformed("program headers (two PT_DYNAMIC)"));
                    }
                    let (start, end) = range().ok_or(ElfError::Bounds("PT_DYNAMIC"))?;
                    dynamic = Some((start, end - start));
                }
                _ => {}
            }
        }
        let (start, len) = dynamic.ok_or(ElfError::Missing("PT_DYNAMIC"))?;
        image.dynamic = start;
        image.dynamic_len = len;
        Ok(image)
    }

    fn segments(&self) -> &[Segment] {
        &self.loads[..self.nloads]
    }

    /// `[addr, addr + len)` lies inside one segment with all of `flags`.
    fn contains(&self, addr: usize, len: usize, flags: u32) -> bool {
        let Some(end) = addr.checked_add(len) else {
            return false;
        };
        self.segments()
            .iter()
            .any(|s| s.flags & flags == flags && s.start <= addr && end <= s.end)
    }

    fn read(&self, addr: usize, out: &mut [u8], what: &'static str) -> Result<(), ElfError> {
        if !self.contains(addr, out.len(), PF_R) {
            return Err(ElfError::Bounds(what));
        }
        match self.bytes {
            // SAFETY: the span lies inside a readable `PT_LOAD` range of an
            // image the loader reports as mapped; the image stays mapped and
            // unmodified while it is inspected (design contract: nothing
            // unloads or rewrites it concurrently).
            None => unsafe {
                std::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), out.len());
            },
            Some((base, bytes)) => {
                let off = addr.checked_sub(base).ok_or(ElfError::Bounds(what))?;
                let end = off.checked_add(out.len()).ok_or(ElfError::Bounds(what))?;
                out.copy_from_slice(bytes.get(off..end).ok_or(ElfError::Bounds(what))?);
            }
        }
        Ok(())
    }

    fn u32_at(&self, addr: usize, what: &'static str) -> Result<u32, ElfError> {
        let mut b = [0u8; 4];
        self.read(addr, &mut b, what)?;
        Ok(u32::from_le_bytes(b))
    }

    fn u64_at(&self, addr: usize, what: &'static str) -> Result<u64, ElfError> {
        let mut b = [0u8; 8];
        self.read(addr, &mut b, what)?;
        Ok(u64::from_le_bytes(b))
    }

    /// A table pointer from the dynamic section: glibc relocates some tags in
    /// place (`DT_SYMTAB`, `DT_STRTAB`, the hash tables on most
    /// architectures) and not others. Accept only one mapped interpretation.
    fn table_ptr(&self, raw: u64, what: &'static str) -> Result<usize, ElfError> {
        let raw = usize::try_from(raw).map_err(|_| ElfError::Bounds(what))?;
        let adjusted = self.bias.checked_add(raw);
        let mapped = |a: usize| self.contains(a, 1, PF_R);
        match (mapped(raw), adjusted.filter(|&a| mapped(a))) {
            (true, Some(a)) if a == raw => Ok(raw),
            (true, Some(_)) => Err(ElfError::AmbiguousPointer(what)),
            (true, None) => Ok(raw),
            (false, Some(a)) => Ok(a),
            (false, None) => Err(ElfError::Bounds(what)),
        }
    }

    /// A tag the loader never relocates (`DT_INIT`, `DT_INIT_ARRAY`):
    /// checked load-bias addition.
    fn runtime_addr(&self, raw: u64, what: &'static str) -> Result<usize, ElfError> {
        usize::try_from(raw)
            .ok()
            .and_then(|v| self.bias.checked_add(v))
            .ok_or(ElfError::Bounds(what))
    }
}

/// The dynamic-section values the inspection uses (raw `d_val`s).
#[derive(Default)]
struct Dynamic {
    symtab: Option<u64>,
    strtab: Option<u64>,
    strsz: Option<u64>,
    syment: Option<u64>,
    hash: Option<u64>,
    gnu_hash: Option<u64>,
    init: Option<u64>,
    init_array: Option<u64>,
    init_arraysz: Option<u64>,
}

fn dynamic(image: &ElfImage<'_>) -> Result<Dynamic, ElfError> {
    let mut d = Dynamic::default();
    let entries = image.dynamic_len / DYN_SIZE;
    let mut terminated = false;
    for i in 0..entries {
        if i == MAX_DYNAMIC {
            return Err(ElfError::WorkLimit("dynamic entries"));
        }
        let at = image.dynamic + i * DYN_SIZE;
        let tag = image.u64_at(at, "dynamic section")? as i64;
        let val = image.u64_at(at + 8, "dynamic section")?;
        let slot = match tag {
            DT_NULL => {
                terminated = true;
                break;
            }
            DT_SYMTAB => &mut d.symtab,
            DT_STRTAB => &mut d.strtab,
            DT_STRSZ => &mut d.strsz,
            DT_SYMENT => &mut d.syment,
            DT_HASH => &mut d.hash,
            DT_GNU_HASH => &mut d.gnu_hash,
            DT_INIT => &mut d.init,
            DT_INIT_ARRAY => &mut d.init_array,
            DT_INIT_ARRAYSZ => &mut d.init_arraysz,
            _ => continue,
        };
        match *slot {
            Some(old) if old != val => {
                return Err(ElfError::Malformed(
                    "dynamic section (conflicting duplicate tag)",
                ))
            }
            _ => *slot = Some(val),
        }
    }
    if !terminated {
        return Err(ElfError::Malformed("dynamic section (no DT_NULL)"));
    }
    Ok(d)
}

/// The validated symbol and string tables.
struct Tables {
    symtab: usize,
    count: usize,
    strtab: usize,
    strsz: usize,
}

fn tables(image: &ElfImage<'_>, d: &Dynamic) -> Result<Tables, ElfError> {
    match d.syment {
        Some(v) if v == SYM_SIZE as u64 => {}
        Some(_) => return Err(ElfError::Unsupported("DT_SYMENT")),
        None => return Err(ElfError::Missing("DT_SYMENT")),
    }
    let symtab = image.table_ptr(d.symtab.ok_or(ElfError::Missing("DT_SYMTAB"))?, "DT_SYMTAB")?;
    let strtab = image.table_ptr(d.strtab.ok_or(ElfError::Missing("DT_STRTAB"))?, "DT_STRTAB")?;
    let strsz = usize::try_from(d.strsz.ok_or(ElfError::Missing("DT_STRSZ"))?)
        .map_err(|_| ElfError::Bounds("string table"))?;
    if strsz == 0 || !image.contains(strtab, strsz, PF_R) {
        return Err(ElfError::Bounds("string table"));
    }
    let sysv = match d.hash {
        Some(raw) => {
            let h = image.table_ptr(raw, "DT_HASH")?;
            Some(image.u32_at(h + 4, "DT_HASH")? as usize)
        }
        None => None,
    };
    let gnu = match d.gnu_hash {
        Some(raw) => Some(gnu_symbol_count(
            image,
            image.table_ptr(raw, "DT_GNU_HASH")?,
        )?),
        None => None,
    };
    let count = match (sysv, gnu) {
        (Some(a), Some(b)) if a != b => {
            return Err(ElfError::Malformed(
                "hash tables (SysV and GNU symbol counts differ)",
            ))
        }
        (Some(n), _) | (None, Some(n)) => n,
        (None, None) => return Err(ElfError::Missing("DT_HASH or DT_GNU_HASH")),
    };
    if count > MAX_SYMBOLS {
        return Err(ElfError::WorkLimit("symbols"));
    }
    let span = count
        .checked_mul(SYM_SIZE)
        .ok_or(ElfError::Bounds("symbol table"))?;
    if count > 0 && !image.contains(symtab, span, PF_R) {
        return Err(ElfError::Bounds("symbol table"));
    }
    Ok(Tables {
        symtab,
        count,
        strtab,
        strsz,
    })
}

/// The number of dynamic symbols a GNU hash table covers: one past the
/// highest chain terminator, or `symoffset` when every bucket is empty.
/// Symbols below `symoffset` are not hashed but still counted (and
/// inspected). Every chain is walked to its terminator, under
/// [`MAX_HASH_STEPS`].
fn gnu_symbol_count(image: &ElfImage<'_>, h: usize) -> Result<usize, ElfError> {
    const WHAT: &str = "DT_GNU_HASH";
    let nbuckets = image.u32_at(h, WHAT)? as usize;
    let symoffset = image.u32_at(h + 4, WHAT)? as usize;
    let bloom_size = image.u32_at(h + 8, WHAT)? as usize;
    if nbuckets == 0 {
        return Err(ElfError::Malformed("GNU hash (no buckets)"));
    }
    let buckets = bloom_size
        .checked_mul(8)
        .and_then(|b| h.checked_add(16)?.checked_add(b))
        .ok_or(ElfError::Bounds(WHAT))?;
    let chains = nbuckets
        .checked_mul(4)
        .and_then(|b| buckets.checked_add(b))
        .ok_or(ElfError::Bounds(WHAT))?;
    let mut steps = 0usize;
    let mut step = || {
        steps += 1;
        if steps > MAX_HASH_STEPS {
            Err(ElfError::WorkLimit("hash-table steps"))
        } else {
            Ok(())
        }
    };
    let mut count = symoffset;
    for b in 0..nbuckets {
        step()?;
        let first = image.u32_at(buckets + b * 4, WHAT)? as usize;
        if first == 0 {
            continue;
        }
        if first < symoffset {
            return Err(ElfError::Malformed("GNU hash (bucket below symoffset)"));
        }
        let mut i = first;
        loop {
            step()?;
            if i >= MAX_SYMBOLS {
                return Err(ElfError::WorkLimit("symbols"));
            }
            let at = (i - symoffset)
                .checked_mul(4)
                .and_then(|o| chains.checked_add(o))
                .ok_or(ElfError::Bounds(WHAT))?;
            if image.u32_at(at, "GNU hash chain (no terminator)")? & 1 == 1 {
                count = count.max(i + 1);
                break;
            }
            i += 1;
        }
    }
    Ok(count)
}

/// One defined, externally bindable dynamic symbol (global, weak or
/// GNU-unique binding; default or protected visibility; any type).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Export {
    pub(crate) name: SymbolName,
    /// The full name starts with `sqlite3` (ASCII case-insensitive).
    pub(crate) sqlite: bool,
    pub(crate) kind: u8,
    pub(crate) shndx: u16,
    pub(crate) value: u64,
}

impl Export {
    /// The runtime address this definition binds to, for comparisons: `None`
    /// for TLS (its value is an offset); absolute definitions use their value;
    /// IFUNC uses the resolver's address (never invoked).
    fn address(&self, bias: usize) -> Result<Option<usize>, ElfError> {
        if self.kind == STT_TLS {
            return Ok(None);
        }
        let value = usize::try_from(self.value).map_err(|_| ElfError::Bounds("symbol value"))?;
        match self.shndx {
            SHN_ABS => Ok(Some(value)),
            SHN_XINDEX => Ok(bias.checked_add(value)),
            s if s >= SHN_LORESERVE => Err(ElfError::Unsupported("reserved section index")),
            _ => bias
                .checked_add(value)
                .map(Some)
                .ok_or(ElfError::Bounds("symbol value")),
        }
    }
}

/// Visit every defined, externally bindable dynamic symbol until `visit`
/// returns `false`; returns how many were visited. An unknown binding refuses
/// (it might be an export); local, hidden, internal and undefined symbols are
/// skipped.
pub(crate) fn for_each_export(
    image: &ElfImage<'_>,
    visit: &mut dyn FnMut(Export) -> bool,
) -> Result<u32, ElfError> {
    let d = dynamic(image)?;
    let t = tables(image, &d)?;
    let mut name_budget = MAX_NAME_BYTES;
    let mut visited = 0u32;
    for i in 0..t.count {
        let mut sym = [0u8; SYM_SIZE];
        image.read(t.symtab + i * SYM_SIZE, &mut sym, "symbol table")?;
        let st_name = u32::from_le_bytes(sym[0..4].try_into().unwrap()) as usize;
        let info = sym[4];
        let other = sym[5];
        let shndx = u16::from_le_bytes(sym[6..8].try_into().unwrap());
        let value = u64::from_le_bytes(sym[8..16].try_into().unwrap());
        if shndx == SHN_UNDEF {
            continue;
        }
        match info >> 4 {
            STB_LOCAL => continue,
            STB_GLOBAL | STB_WEAK | STB_GNU_UNIQUE => {}
            _ => return Err(ElfError::Unsupported("symbol binding")),
        }
        if matches!(other & 3, STV_INTERNAL | STV_HIDDEN) {
            continue;
        }
        let (name, sqlite) = symbol_name(image, &t, st_name, &mut name_budget)?;
        visited += 1;
        let keep_going = visit(Export {
            name,
            sqlite,
            kind: info & 0xf,
            shndx,
            value,
        });
        if !keep_going {
            break;
        }
    }
    Ok(visited)
}

/// Read the name at `st_name` to its terminator inside the string table.
fn symbol_name(
    image: &ElfImage<'_>,
    t: &Tables,
    st_name: usize,
    budget: &mut usize,
) -> Result<(SymbolName, bool), ElfError> {
    if st_name >= t.strsz {
        return Err(ElfError::Bounds("symbol name"));
    }
    let mut prefix = [0u8; 32];
    let mut len = 0usize;
    let mut off = st_name;
    let mut chunk = [0u8; 64];
    loop {
        if off >= t.strsz {
            return Err(ElfError::Malformed("string table (unterminated name)"));
        }
        let n = chunk.len().min(t.strsz - off);
        if n > *budget {
            return Err(ElfError::WorkLimit("name bytes"));
        }
        *budget -= n;
        image.read(t.strtab + off, &mut chunk[..n], "string table")?;
        let end = chunk[..n].iter().position(|&b| b == 0);
        for &b in &chunk[..end.unwrap_or(n)] {
            if len < prefix.len() {
                prefix[len] = b;
            }
            len += 1;
        }
        if end.is_some() {
            break;
        }
        off += n;
    }
    let kept = len.min(prefix.len());
    let sqlite = kept >= 7 && prefix[..7].eq_ignore_ascii_case(b"sqlite3");
    Ok((SymbolName::from_prefix(&prefix[..kept], len > kept), sqlite))
}

/// Why the export inspection refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExportFailure {
    Elf(ElfError),
    Sqlite(SymbolName),
}

/// Linux private-instance export check: no defined, externally bindable
/// dynamic symbol of `image` starts with `sqlite3`. Returns how many exports
/// were inspected.
pub(crate) fn image_exports_no_sqlite(image: &ElfImage<'_>) -> Result<u32, ExportFailure> {
    let mut found = None;
    let count = for_each_export(image, &mut |e| {
        if e.sqlite {
            found = Some(e.name);
        }
        found.is_none()
    })
    .map_err(ExportFailure::Elf)?;
    match found {
        Some(name) => Err(ExportFailure::Sqlite(name)),
        None => Ok(count),
    }
}

/// `DT_INIT` (when present: a present zero tag is not absent) and the first
/// init-array entry, both as runtime addresses.
#[cfg_attr(not(test), allow(dead_code))] // issue #192: no installation path uses it
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Initialization {
    pub(crate) dt_init: Option<usize>,
    pub(crate) first_init_array: usize,
}

/// Why the initialization check refused.
#[cfg_attr(not(test), allow(dead_code))] // issue #192: no installation path uses it
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitRefusal {
    Elf(ElfError),
    InitArray(&'static str),
    ExportedDtInit(SymbolName),
}

#[cfg_attr(not(test), allow(dead_code))] // issue #192: no installation path uses it
pub(crate) fn initialization(image: &ElfImage<'_>) -> Result<Initialization, InitRefusal> {
    let d = dynamic(image).map_err(InitRefusal::Elf)?;
    let dt_init = match d.init {
        Some(raw) => {
            let at = image
                .runtime_addr(raw, "DT_INIT")
                .map_err(InitRefusal::Elf)?;
            if !image.contains(at, 1, PF_X) {
                return Err(InitRefusal::Elf(ElfError::Bounds("DT_INIT")));
            }
            Some(at)
        }
        None => None,
    };
    let raw = d
        .init_array
        .ok_or(InitRefusal::InitArray("no DT_INIT_ARRAY"))?;
    let size = d.init_arraysz.ok_or(InitRefusal::InitArray(
        "DT_INIT_ARRAY without DT_INIT_ARRAYSZ",
    ))?;
    if size == 0 {
        return Err(InitRefusal::InitArray("empty init array"));
    }
    if size % 8 != 0 {
        return Err(InitRefusal::InitArray(
            "init array size is not a multiple of the pointer size",
        ));
    }
    let at = image
        .runtime_addr(raw, "DT_INIT_ARRAY")
        .map_err(InitRefusal::Elf)?;
    let size =
        usize::try_from(size).map_err(|_| InitRefusal::Elf(ElfError::Bounds("init array")))?;
    if !image.contains(at, size, PF_R) {
        return Err(InitRefusal::Elf(ElfError::Bounds("init array")));
    }
    let first = image.u64_at(at, "init array").map_err(InitRefusal::Elf)?;
    Ok(Initialization {
        dt_init,
        first_init_array: usize::try_from(first)
            .map_err(|_| InitRefusal::Elf(ElfError::Bounds("init array entry")))?,
    })
}

/// Option (b) of the S6 F3 decision: `constructor` is entry zero of the init
/// array, and a `DT_INIT` is not the address of any inspected exported
/// definition (aliases included, whatever the name or version). Refuses an
/// exported custom initializer; accepts glibc's hidden CRT `_init` and, by
/// the same rule, a hidden custom one (an assumption, not an observation).
#[cfg_attr(not(test), allow(dead_code))] // issue #192: no installation path uses it
pub(crate) fn check_initialization(
    image: &ElfImage<'_>,
    constructor: usize,
) -> Result<Initialization, InitRefusal> {
    let init = initialization(image)?;
    if init.first_init_array != constructor {
        return Err(InitRefusal::InitArray(
            "the constructor is not the first init-array entry",
        ));
    }
    if let Some(dt_init) = init.dt_init {
        let mut hit = None;
        let mut error = None;
        for_each_export(image, &mut |e| match e.address(image.bias) {
            Ok(Some(a)) if a == dt_init => {
                hit = Some(e.name);
                false
            }
            Ok(_) => true,
            Err(err) => {
                error = Some(err);
                false
            }
        })
        .map_err(InitRefusal::Elf)?;
        if let Some(err) = error {
            return Err(InitRefusal::Elf(err));
        }
        if let Some(name) = hit {
            return Err(InitRefusal::ExportedDtInit(name));
        }
    }
    Ok(init)
}

/// The live image containing `addr` (64-bit little-endian Linux glibc only).
#[cfg(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    target_os = "linux",
    target_env = "gnu"
))]
pub(crate) fn image_containing(addr: usize) -> Result<ElfImage<'static>, ElfError> {
    struct Search {
        addr: usize,
        matches: u32,
        found: Result<ElfImage<'static>, ElfError>,
    }

    unsafe extern "C" fn visit(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        // SAFETY: `data` is the `Search` below; `info` is valid for this call
        // and its `dlpi_phnum` headers are readable. Nothing here panics.
        let search = unsafe { &mut *(data as *mut Search) };
        let info = unsafe { &*info };
        if info.dlpi_phdr.is_null() {
            return 0;
        }
        let phnum = usize::from(info.dlpi_phnum);
        let phdrs = unsafe { std::slice::from_raw_parts(info.dlpi_phdr, phnum.min(MAX_PHDRS)) };
        let bias = info.dlpi_addr as usize;
        let hit = phdrs.iter().any(|ph| {
            ph.p_type == libc::PT_LOAD
                && bias
                    .checked_add(ph.p_vaddr as usize)
                    .and_then(|s| Some((s, s.checked_add(ph.p_memsz as usize)?)))
                    .is_some_and(|(s, e)| s <= search.addr && search.addr < e)
        });
        if hit {
            search.matches = search.matches.saturating_add(1);
            search.found = ElfImage::from_phdrs(
                info.dlpi_phdr as usize,
                bias,
                phnum,
                phdrs.iter().map(|ph| Phdr {
                    p_type: ph.p_type,
                    flags: ph.p_flags,
                    vaddr: ph.p_vaddr,
                    memsz: ph.p_memsz,
                }),
                None,
            );
        }
        0
    }

    let mut search = Search {
        addr,
        matches: 0,
        found: Err(ElfError::Missing("loaded image containing the address")),
    };
    // SAFETY: `visit` only reads the loader's records and writes `search`.
    unsafe { libc::dl_iterate_phdr(Some(visit), &mut search as *mut Search as *mut libc::c_void) };
    match search.matches {
        0 | 1 => search.found,
        _ => Err(ElfError::Malformed(
            "loader records (address in more than one image)",
        )),
    }
}

#[cfg(test)]
#[path = "elf_tests.rs"]
mod tests;
