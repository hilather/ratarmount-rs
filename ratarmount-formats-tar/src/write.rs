//! POSIX ustar/PAX writer and last-window TAR suffix rewrite.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use ratarmount_core::normpath;

use crate::{
    decode_bytes, pad512, parse_name, parse_octal, parse_pax_records, BLOCK_SIZE,
    MAX_HEADER_PAYLOAD_BYTES,
};

/// Largest file size the 11-digit ustar octal `size` field can hold (`8 GiB - 1`).
const USTAR_MAX_SIZE: u64 = 0o777_7777_7777;
const USTAR_NAME_LEN: usize = 100;
const USTAR_LINK_LEN: usize = 100;
const PAX_HDR_PREFIX: &str = "PaxHeaders.0/";
/// `PaxHeaders.0/` is 13 bytes; the path suffix must keep the whole name ≤ 100.
const PAX_HDR_PATH_MAX: usize = USTAR_NAME_LEN - 13;

/// Stream-aligned last two-zero-block pair.
///
/// `stream_offset` is the uncompressed TAR offset of `suffix` byte 0.
/// Returns the byte offset in `suffix` of the first of those two blocks.
///
/// When the suffix *ends* in at least two aligned zero blocks (GNU tar record
/// padding is typically 20 blocks), this is the start of that trailing run —
/// not the last overlapping 1024-zero window inside the padding. Only if the
/// suffix does not end in two zero blocks do we fall back to the last interior
/// pair (concatenated-TAR frames that were truncated before a new EOF).
///
/// **Warning:** the returned position is an *existence probe*, not a safe cut
/// boundary — a member whose final payload blocks are all zero extends the
/// trailing run into the payload, so the position can precede the true data
/// end. `rewrite_tar_suffix` derives the cut from parsed member spans instead.
pub fn find_last_tar_eof<R: Read + Seek>(
    suffix: &mut R,
    stream_offset: u64,
) -> io::Result<Option<u64>> {
    let len = suffix.seek(SeekFrom::End(0))?;
    let align = stream_align(stream_offset);
    if let Some(start) = trailing_zero_eof(suffix, align, len)? {
        return Ok(Some(start));
    }
    last_interior_two_zero(suffix, align, len)
}

/// Start of a trailing aligned zero-block run of at least 1024 bytes, if the
/// suffix ends in zeros (including a short leftover after the last full block).
fn trailing_zero_eof<R: Read + Seek>(
    suffix: &mut R,
    align: u64,
    len: u64,
) -> io::Result<Option<u64>> {
    if len < align.saturating_add(1024) {
        return Ok(None);
    }
    let nblocks = (len - align) / BLOCK_SIZE;
    if nblocks < 2 {
        return Ok(None);
    }
    let last_block = align + (nblocks - 1) * BLOCK_SIZE;
    let leftover_off = last_block + BLOCK_SIZE;
    if leftover_off < len && !region_all_zero(suffix, leftover_off, len - leftover_off)? {
        return Ok(None);
    }
    let mut run_start: Option<u64> = None;
    let mut i = last_block;
    loop {
        if !region_all_zero(suffix, i, BLOCK_SIZE)? {
            break;
        }
        run_start = Some(i);
        if i < align + BLOCK_SIZE {
            break;
        }
        i -= BLOCK_SIZE;
    }
    match run_start {
        Some(s) if last_block + BLOCK_SIZE - s >= 1024 => Ok(Some(s)),
        _ => Ok(None),
    }
}

/// Last stream-aligned 1024-zero window that is *not* a trailing padding run.
fn last_interior_two_zero<R: Read + Seek>(
    suffix: &mut R,
    align: u64,
    len: u64,
) -> io::Result<Option<u64>> {
    if len < align.saturating_add(1024) {
        return Ok(None);
    }
    let max_i = len - 1024;
    let last_aligned = align + ((max_i - align) / BLOCK_SIZE) * BLOCK_SIZE;
    let mut buf = [0u8; 1024];
    let mut i = last_aligned;
    loop {
        suffix.seek(SeekFrom::Start(i))?;
        suffix.read_exact(&mut buf)?;
        if buf.iter().all(|&b| b == 0) {
            return Ok(Some(i));
        }
        if i < align + BLOCK_SIZE {
            break;
        }
        i -= BLOCK_SIZE;
    }
    Ok(None)
}

fn region_all_zero<R: Read + Seek>(r: &mut R, start: u64, n: u64) -> io::Result<bool> {
    if n == 0 {
        return Ok(true);
    }
    r.seek(SeekFrom::Start(start))?;
    let mut remain = n;
    let mut buf = [0u8; 512];
    while remain > 0 {
        let chunk = remain.min(512) as usize;
        r.read_exact(&mut buf[..chunk])?;
        if buf[..chunk].iter().any(|&b| b != 0) {
            return Ok(false);
        }
        remain -= chunk as u64;
    }
    Ok(true)
}

/// Copy kept last-window bytes, drop deleted names (with their PAX/`L`/`K` helpers),
/// append `append`, write two zero blocks.
pub struct RewriteTarSuffix<'a> {
    /// Normalized archive-relative paths to drop (last-window only; caller classified).
    pub deleted_paths: &'a HashSet<String>,
    /// New members to append after the kept prefix (overlay files / dirs / symlinks).
    pub append: &'a [UstarMember<'a>],
    /// Same as the mount (`OpenOptions.encoding`); used to decode ustar/PAX/GNU names
    /// when matching `deleted_paths`. Default `"utf-8"`.
    pub encoding: &'a str,
}

/// Counters for tests and persist logs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RewriteTarSuffixStats {
    /// Bytes copied from the input suffix (opaque prefix + kept members).
    pub bytes_kept: u64,
    /// Logical members skipped because their path was in `deleted_paths`.
    pub members_dropped: u64,
    /// Logical members copied (excludes global PAX `g` and dropped names).
    pub members_kept: u64,
    /// Members written from `RewriteTarSuffix::append`.
    pub members_appended: u64,
}

/// Copy kept last-window bytes, drop deleted names (with their PAX/`L`/`K` helpers),
/// append `append`, write two zero blocks.
pub fn rewrite_tar_suffix<R, W>(
    suffix: &mut R,
    stream_offset: u64,
    opts: &RewriteTarSuffix<'_>,
    out: &mut W,
) -> io::Result<RewriteTarSuffixStats>
where
    R: Read + Seek,
    W: Write,
{
    let suffix_len = suffix.seek(SeekFrom::End(0))?;
    // The cut point must come from forward-parsed member spans, never from a
    // backward zero-run scan: a member whose final payload block(s) are all
    // zero is indistinguishable from EOF padding when scanning back, and
    // cutting there silently truncates the member and swallows appends.
    let first = find_first_valid_header(suffix, stream_offset, suffix_len)?;

    let mut stats = RewriteTarSuffixStats::default();
    match first {
        None => {
            if !opts.deleted_paths.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "could not parse last-window TAR headers; cannot apply last-window delete",
                ));
            }
            if !opts.append.is_empty() && !region_all_zero(suffix, 0, suffix_len)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "could not parse last-window TAR headers; the window has no \
                     member boundary (a member spans the whole window) — cannot \
                     locate the data end; enlarge the rewrite window",
                ));
            }
            // Pure zero padding (old EOF / record blocks): nothing to keep;
            // new members must not land behind an early EOF pair.
        }
        Some(first_pos) => {
            let mut cursor =
                TarMemberCursor::new(&mut *suffix, first_pos, stream_offset, opts.encoding);
            let mut members = Vec::new();
            while let Some(m) = cursor.next_member()? {
                members.push(m);
            }
            // Copy kept bytes only up to the end of the last walked member;
            // anything after (old EOF pair, record padding) is regenerated.
            let copy_end = members
                .iter()
                .map(|m| m.raw_end)
                .fold(first_pos, |a, b| a.max(b))
                .min(suffix_len);
            let deleted: HashSet<String> = opts
                .deleted_paths
                .iter()
                .map(|p| normalize_archive_rel_path(p))
                .collect();
            let mut seen: HashSet<String> = HashSet::new();
            for m in &members {
                if m.typeflag == b'g' {
                    continue;
                }
                let norm = normalize_archive_rel_path(&m.logical_path);
                if !norm.is_empty() && deleted.contains(&norm) {
                    seen.insert(norm);
                }
            }
            let mut missing: Vec<&str> = deleted
                .iter()
                .filter(|p| !p.is_empty() && !seen.contains(*p))
                .map(String::as_str)
                .collect();
            if !missing.is_empty() {
                missing.sort_unstable();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "last-window delete path(s) not found in the suffix: {}",
                        missing.join(", ")
                    ),
                ));
            }
            let mut bytes_kept = copy_span(suffix, out, 0, first_pos)?;
            let mut copy_from = first_pos;
            for m in &members {
                if m.typeflag == b'g' {
                    continue;
                }
                let norm = normalize_archive_rel_path(&m.logical_path);
                if !norm.is_empty() && deleted.contains(&norm) {
                    if copy_from < m.raw_start {
                        bytes_kept += copy_span(suffix, out, copy_from, m.raw_start)?;
                    }
                    copy_from = m.raw_end.min(copy_end);
                    stats.members_dropped += 1;
                } else {
                    stats.members_kept += 1;
                }
            }
            if copy_from < copy_end {
                bytes_kept += copy_span(suffix, out, copy_from, copy_end)?;
            }
            stats.bytes_kept = bytes_kept;
        }
    }

    write_ustar_members(out, opts.append)?;
    write_tar_eof(out)?;
    stats.members_appended = opts.append.len() as u64;
    Ok(stats)
}

/// Read-only walker over last-window TAR headers (no index inserts / sparse maps).
pub struct TarMemberCursor<R> {
    reader: R,
    pos: u64,
    encoding: String,
    pax_global: HashMap<String, String>,
    pending: Option<PendingHelper>,
    /// Start of the terminal zero run (EOF pair + padding), found by walking
    /// FORWARD — never by scanning zero runs backward (a member's all-zero
    /// payload blocks are indistinguishable from padding when scanning back).
    eof_off: Option<u64>,
    reader_len: u64,
    /// Set when `new` cannot measure the suffix; `next_member` surfaces it.
    init_err: Option<io::Error>,
}

struct PendingHelper {
    raw_start: u64,
    map: HashMap<String, String>,
}

impl<R: Read + Seek> TarMemberCursor<R> {
    pub fn new(mut reader: R, start_pos: u64, stream_offset: u64, encoding: &str) -> Self {
        let _ = stream_offset; // alignment is the caller's job (find_first_valid_header)
        let (reader_len, init_err) = match reader.seek(SeekFrom::End(0)) {
            Ok(len) => (len, None),
            Err(e) => (0, Some(e)),
        };
        let encoding = if encoding.trim().is_empty() {
            "utf-8".to_string()
        } else {
            encoding.to_string()
        };
        Self {
            reader,
            pos: start_pos,
            encoding,
            pax_global: HashMap::new(),
            pending: None,
            eof_off: None,
            reader_len,
            init_err,
        }
    }

    /// Start of the terminal zero run, once the walk has ended.
    pub fn stream_eof_offset(&self) -> Option<u64> {
        self.eof_off
    }

    /// Next logical member, or None at last two-zero EOF / reader EOF.
    /// Pending typeflag `x` / `L` / `K` are consumed into the returned member
    /// (their raw byte spans are recorded so a drop can skip them too).
    pub fn next_member(&mut self) -> io::Result<Option<TarRawMember>> {
        if let Some(e) = self.init_err.take() {
            return Err(e);
        }
        loop {
            if self.at_stop() {
                return Ok(None);
            }
            self.reader.seek(SeekFrom::Start(self.pos))?;
            let mut header = [0u8; 512];
            let n = self.reader.read(&mut header)?;
            if n == 0 {
                return Ok(None);
            }
            if n < 512 {
                return Ok(None);
            }
            if header.iter().all(|&b| b == 0) {
                // Measure this zero run in one sweep (linear total work). A
                // run that reaches the end of the suffix is the terminal
                // EOF/padding; interior runs — including an EOF pair between
                // concatenated members — are gaps and skipped wholesale.
                let mut run_end = self.pos + BLOCK_SIZE;
                loop {
                    let remaining = self.reader_len - run_end;
                    if remaining == 0 {
                        break;
                    }
                    let n = remaining.min(BLOCK_SIZE) as usize;
                    if !region_all_zero(&mut self.reader, run_end, n as u64)? {
                        break;
                    }
                    run_end += n as u64;
                }
                if run_end >= self.reader_len {
                    self.eof_off = Some(self.pos);
                    self.pos = run_end;
                    return Ok(None);
                }
                self.pos = run_end;
                continue;
            }
            if !checksum_ok(&header) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid ustar checksum at suffix offset {}", self.pos),
                ));
            }

            let typeflag = header[156];
            let size = parse_octal(&header[124..136]).unwrap_or(0);

            if typeflag == b'g' {
                // Pathological: g between x/L/K and the file. Folding g into the
                // next file's raw span would drop it; leaving the helper poisons
                // the following member. GNU tar does not emit this layout.
                if self.pending.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "global PAX g between pending extended header and file",
                    ));
                }
                let recs = self.read_helper_body(size, "PAX")?;
                let parsed = parse_pax_records(&recs);
                self.pax_global.extend(parsed.map);
                let raw_start = self.pos;
                let raw_end = self.pos + BLOCK_SIZE + pad512(size);
                self.pos = raw_end;
                return Ok(Some(TarRawMember {
                    raw_start,
                    raw_end,
                    logical_path: String::new(),
                    typeflag: b'g',
                }));
            }

            if typeflag == b'x' || typeflag == b'L' || typeflag == b'K' {
                self.consume_pending_helper(&header, typeflag, size)?;
                continue;
            }

            let helper_start = self
                .pending
                .as_ref()
                .map(|p| p.raw_start)
                .unwrap_or(self.pos);
            let mut pax = self.pax_global.clone();
            if let Some(pend) = self.pending.take() {
                pax.extend(pend.map);
            }

            let name = if let Some(p) = pax.get("path") {
                p.clone()
            } else if let Some(p) = pax.get("GNU.sparse.name") {
                p.clone()
            } else {
                parse_name(&header, &self.encoding)
            };
            let on_tape = pax
                .get("size")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(size);
            // Saturate: a hostile PAX `size` near u64::MAX must not wrap the
            // span back into the payload (wraps would parse junk members).
            let raw_end = self
                .pos
                .saturating_add(BLOCK_SIZE)
                .saturating_add(pad512(on_tape));
            self.pos = raw_end;
            return Ok(Some(TarRawMember {
                raw_start: helper_start,
                raw_end,
                logical_path: normalize_archive_rel_path(&name),
                typeflag,
            }));
        }
    }

    fn at_stop(&self) -> bool {
        if let Some(eof) = self.eof_off {
            if self.pos >= eof {
                return true;
            }
        }
        self.pos + BLOCK_SIZE > self.reader_len
    }

    fn read_helper_body(&mut self, size: u64, kind: &str) -> io::Result<Vec<u8>> {
        check_helper_size(size, kind)?;
        let mut body = vec![0u8; size as usize];
        if size > 0 {
            self.reader.seek(SeekFrom::Start(self.pos + BLOCK_SIZE))?;
            self.reader.read_exact(&mut body)?;
        }
        Ok(body)
    }

    fn consume_pending_helper(
        &mut self,
        _header: &[u8; 512],
        typeflag: u8,
        size: u64,
    ) -> io::Result<()> {
        let kind = match typeflag {
            b'x' => "PAX",
            b'L' => "GNU long name",
            _ => "GNU long link",
        };
        let mut body = self.read_helper_body(size, kind)?;
        let header_pos = self.pos;
        if self.pending.is_none() {
            self.pending = Some(PendingHelper {
                raw_start: header_pos,
                map: HashMap::new(),
            });
        }
        let pending = self.pending.as_mut().expect("pending just inserted");
        match typeflag {
            b'x' => {
                let recs = parse_pax_records(&body);
                pending.map.extend(recs.map);
            }
            b'L' | b'K' => {
                while body.last() == Some(&0) {
                    body.pop();
                }
                let s = decode_bytes(&body, &self.encoding);
                let key = if typeflag == b'L' { "path" } else { "linkpath" };
                pending.map.insert(key.to_string(), s);
            }
            _ => {}
        }
        self.pos = header_pos + BLOCK_SIZE + pad512(size);
        Ok(())
    }
}

/// Inclusive start of the first helper header (PAX `x` / GNU `L`/`K`) or the
/// ustar header if none. Absolute in `suffix`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TarRawMember {
    /// Inclusive start of the first helper header (PAX `x` / GNU `L`/`K`) or the
    /// ustar header if none. Absolute in `suffix`.
    pub raw_start: u64,
    /// Exclusive end of padded body (next header / EOF).
    pub raw_end: u64,
    /// Logical path after PAX `path` / GNU long name / ustar name, decoded with
    /// `encoding`, then [`normalize_archive_rel_path`].
    pub logical_path: String,
    /// Typeflag of the *file* header (`0`/`5`/`2`/…), not of the helper.
    pub typeflag: u8,
}

/// One member to emit as POSIX ustar (PAX when a field does not fit).
#[derive(Clone, Debug)]
pub struct UstarMember<'a> {
    /// Archive-relative path; no leading `/`.
    pub path: &'a str,
    pub payload: UstarPayload<'a>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
}

/// Body of a [`UstarMember`].
#[derive(Clone, Debug)]
pub enum UstarPayload<'a> {
    /// Tests / tiny fixtures only. Persist must not use this for overlay files.
    File {
        bytes: &'a [u8],
    },
    /// Production persist: open with `O_NOFOLLOW` (caller passes already-confined path).
    FileOnDisk {
        path: &'a Path,
        size: u64,
    },
    Directory,
    Symlink {
        target: &'a str,
    },
}

/// Write `members` as ustar/PAX (no EOF blocks).
pub fn write_ustar_members<W: Write>(out: &mut W, members: &[UstarMember<'_>]) -> io::Result<()> {
    for m in members {
        let body_size = match m.payload {
            UstarPayload::File { bytes } => bytes.len() as u64,
            UstarPayload::FileOnDisk { size, .. } => size,
            UstarPayload::Directory | UstarPayload::Symlink { .. } => 0,
        };
        write_member_headers(out, m, body_size)?;
        write_member_body(out, m)?;
    }
    Ok(())
}

/// Two 512-byte zero blocks (POSIX end-of-archive).
pub fn write_tar_eof<W: Write>(out: &mut W) -> io::Result<()> {
    out.write_all(&[0u8; 1024])
}

/// Archive-relative path matching: same collapse as the indexer (`normpath`)
/// with a leading `/` stripped so overlay delete keys line up with tape names.
pub fn normalize_archive_rel_path(path: &str) -> String {
    let mut full = path.trim_end_matches('/').to_string();
    while full.starts_with("./") {
        full = full[2..].to_string();
    }
    normpath(&full).trim_start_matches('/').to_string()
}

fn stream_align(stream_offset: u64) -> u64 {
    (BLOCK_SIZE - (stream_offset % BLOCK_SIZE)) % BLOCK_SIZE
}

fn find_first_valid_header<R: Read + Seek>(
    suffix: &mut R,
    stream_offset: u64,
    scan_end: u64,
) -> io::Result<Option<u64>> {
    let mut i = stream_align(stream_offset);
    let mut header = [0u8; 512];
    while i + BLOCK_SIZE <= scan_end {
        suffix.seek(SeekFrom::Start(i))?;
        suffix.read_exact(&mut header)?;
        if header.iter().all(|&b| b == 0) {
            i += BLOCK_SIZE;
            continue;
        }
        if has_tar_magic(&header) && checksum_ok(&header) {
            return Ok(Some(i));
        }
        i += BLOCK_SIZE;
    }
    Ok(None)
}

/// True when `rewrite_tar_suffix` can safely rewrite this window: either a
/// parseable member header exists, or the whole window is zero padding.
/// Without either, the data end is unknowable (a member spans the window)
/// and rewriting would corrupt the archive — the caller must enlarge the
/// window instead.
pub fn window_has_member_boundary<R: Read + Seek>(
    suffix: &mut R,
    stream_offset: u64,
) -> io::Result<bool> {
    let len = suffix.seek(SeekFrom::End(0))?;
    if find_first_valid_header(suffix, stream_offset, len)?.is_some() {
        return Ok(true);
    }
    region_all_zero(suffix, 0, len)
}

fn has_tar_magic(header: &[u8; 512]) -> bool {
    let magic = &header[257..262];
    magic == b"ustar" || magic == b"GNU  "
}

fn checksum_unsigned(header: &[u8; 512]) -> u32 {
    header
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                b' ' as u32
            } else {
                u32::from(b)
            }
        })
        .sum()
}

fn checksum_signed(header: &[u8; 512]) -> u32 {
    header
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let v = if (148..156).contains(&i) { b' ' } else { b };
            v as i8 as i32 as u32
        })
        .sum()
}

fn checksum_ok(header: &[u8; 512]) -> bool {
    let Some(stored) = parse_octal(&header[148..156]) else {
        return false;
    };
    let stored = stored as u32;
    checksum_unsigned(header) == stored || checksum_signed(header) == stored
}

fn check_helper_size(size: u64, kind: &str) -> io::Result<()> {
    if size > MAX_HEADER_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{kind} header payload size {size} exceeds cap of {MAX_HEADER_PAYLOAD_BYTES} bytes"
            ),
        ));
    }
    Ok(())
}

fn copy_span<R: Read + Seek, W: Write>(
    src: &mut R,
    dst: &mut W,
    start: u64,
    end: u64,
) -> io::Result<u64> {
    if end <= start {
        return Ok(0);
    }
    src.seek(SeekFrom::Start(start))?;
    io::copy(&mut src.by_ref().take(end - start), dst)
}

struct UstarHeaderFields<'a> {
    name: &'a [u8],
    size: u64,
    typeflag: u8,
    linkname: &'a [u8],
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: u64,
}

fn write_raw_ustar_header<W: Write>(out: &mut W, f: UstarHeaderFields<'_>) -> io::Result<()> {
    let mut h = [0u8; 512];
    let nlen = f.name.len().min(USTAR_NAME_LEN);
    h[..nlen].copy_from_slice(&f.name[..nlen]);
    write_octal(&mut h[100..108], u64::from(f.mode))?;
    write_octal(&mut h[108..116], u64::from(f.uid))?;
    write_octal(&mut h[116..124], u64::from(f.gid))?;
    write_octal(&mut h[124..136], f.size)?;
    write_octal(&mut h[136..148], f.mtime)?;
    h[156] = f.typeflag;
    let llen = f.linkname.len().min(USTAR_LINK_LEN);
    h[157..157 + llen].copy_from_slice(&f.linkname[..llen]);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    let ck = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(ck.as_bytes());
    out.write_all(&h)
}

/// Max value that fits in `digits` octal digits (`8^digits - 1`).
fn octal_digit_max(digits: u32) -> u64 {
    (1u64 << (3 * digits)) - 1
}

fn write_octal(dst: &mut [u8], value: u64) -> io::Result<()> {
    let width = dst.len();
    if width == 0 {
        return Ok(());
    }
    let digits = width - 1;
    let s = format!("{value:0digits$o}");
    if s.len() > digits {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("octal value {value} does not fit in {digits} digits"),
        ));
    }
    dst[..s.len()].copy_from_slice(s.as_bytes());
    dst[width - 1] = 0;
    Ok(())
}

fn write_padding<W: Write>(out: &mut W, data_len: u64) -> io::Result<()> {
    let pad = ((BLOCK_SIZE - (data_len % BLOCK_SIZE)) % BLOCK_SIZE) as usize;
    if pad > 0 {
        out.write_all(&[0u8; 512][..pad])?;
    }
    Ok(())
}

fn encode_pax_record(key: &str, value: &[u8]) -> io::Result<Vec<u8>> {
    for len_digits in 1..=20 {
        let mut body = Vec::with_capacity(1 + key.len() + 1 + value.len() + 1);
        body.push(b' ');
        body.extend_from_slice(key.as_bytes());
        body.push(b'=');
        body.extend_from_slice(value);
        body.push(b'\n');
        let total = len_digits + body.len();
        if total.to_string().len() == len_digits {
            let mut rec = total.to_string().into_bytes();
            rec.extend(body);
            return Ok(rec);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("pax record too long for {key}"),
    ))
}

fn pax_header_name(path: &str) -> String {
    let mut take = path.len().min(PAX_HDR_PATH_MAX);
    while take > 0 && !path.is_char_boundary(take) {
        take -= 1;
    }
    format!("{PAX_HDR_PREFIX}{}", &path[..take])
}

fn last_bytes(bytes: &[u8], n: usize) -> &[u8] {
    let start = bytes.len().saturating_sub(n);
    &bytes[start..]
}

fn dir_ustar_name(path: &str) -> Vec<u8> {
    let mut b = path.as_bytes().to_vec();
    if !b.ends_with(b"/") {
        b.push(b'/');
    }
    b
}

fn needs_pax_path(ustar_name: &[u8]) -> bool {
    ustar_name.len() > USTAR_NAME_LEN
}

fn write_member_headers<W: Write>(
    out: &mut W,
    member: &UstarMember<'_>,
    body_size: u64,
) -> io::Result<()> {
    let path = member.path.trim_start_matches('/');
    let (typeflag, link_target, ustar_name) = match member.payload {
        UstarPayload::Directory => (b'5', None, dir_ustar_name(path)),
        UstarPayload::Symlink { target } => (b'2', Some(target), path.as_bytes().to_vec()),
        UstarPayload::File { .. } | UstarPayload::FileOnDisk { .. } => {
            (b'0', None, path.as_bytes().to_vec())
        }
    };

    let need_pax_path = needs_pax_path(&ustar_name);
    let need_pax_link = link_target
        .map(|t| t.len() > USTAR_LINK_LEN)
        .unwrap_or(false);
    let need_pax_size = body_size > USTAR_MAX_SIZE;
    let need_pax_uid = u64::from(member.uid) > octal_digit_max(7);
    let need_pax_gid = u64::from(member.gid) > octal_digit_max(7);
    let need_pax_mtime = member.mtime > octal_digit_max(11);

    if need_pax_path
        || need_pax_link
        || need_pax_size
        || need_pax_uid
        || need_pax_gid
        || need_pax_mtime
    {
        let mut pax_body = Vec::new();
        if need_pax_path {
            pax_body.extend(encode_pax_record("path", path.as_bytes())?);
        }
        if need_pax_link {
            if let Some(t) = link_target {
                pax_body.extend(encode_pax_record("linkpath", t.as_bytes())?);
            }
        }
        let size_txt;
        if need_pax_size {
            size_txt = body_size.to_string();
            pax_body.extend(encode_pax_record("size", size_txt.as_bytes())?);
        }
        let uid_txt;
        if need_pax_uid {
            uid_txt = member.uid.to_string();
            pax_body.extend(encode_pax_record("uid", uid_txt.as_bytes())?);
        }
        let gid_txt;
        if need_pax_gid {
            gid_txt = member.gid.to_string();
            pax_body.extend(encode_pax_record("gid", gid_txt.as_bytes())?);
        }
        let mtime_txt;
        if need_pax_mtime {
            mtime_txt = member.mtime.to_string();
            pax_body.extend(encode_pax_record("mtime", mtime_txt.as_bytes())?);
        }
        let pax_name = pax_header_name(path);
        write_raw_ustar_header(
            out,
            UstarHeaderFields {
                name: pax_name.as_bytes(),
                size: pax_body.len() as u64,
                typeflag: b'x',
                linkname: b"",
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
        )?;
        out.write_all(&pax_body)?;
        write_padding(out, pax_body.len() as u64)?;
    }

    let name_field = if need_pax_path {
        last_bytes(&ustar_name, USTAR_NAME_LEN)
    } else {
        ustar_name.as_slice()
    };
    let link_bytes = link_target.map(|t| t.as_bytes()).unwrap_or(b"");
    let link_field = if need_pax_link {
        last_bytes(link_bytes, USTAR_LINK_LEN)
    } else {
        link_bytes
    };
    let hdr_size = if need_pax_size { 0 } else { body_size };
    write_raw_ustar_header(
        out,
        UstarHeaderFields {
            name: name_field,
            size: hdr_size,
            typeflag,
            linkname: link_field,
            mode: member.mode,
            uid: if need_pax_uid { 0 } else { member.uid },
            gid: if need_pax_gid { 0 } else { member.gid },
            mtime: if need_pax_mtime { 0 } else { member.mtime },
        },
    )
}

fn write_member_body<W: Write>(out: &mut W, member: &UstarMember<'_>) -> io::Result<()> {
    match member.payload {
        UstarPayload::File { bytes } => {
            out.write_all(bytes)?;
            write_padding(out, bytes.len() as u64)
        }
        UstarPayload::FileOnDisk { path, size } => write_file_on_disk(out, path, size),
        UstarPayload::Directory | UstarPayload::Symlink { .. } => Ok(()),
    }
}

fn write_file_on_disk<W: Write>(out: &mut W, path: &Path, size: u64) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if size > 0 {
        let n = io::copy(&mut f.take(size), out)?;
        if n != size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "overlay file {} ended after {n} bytes, expected {size}",
                    path.display()
                ),
            ));
        }
    }
    write_padding(out, size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::path::Path;

    use ratarmount_core::{ListResult, MountSource, OpenOptions};

    use crate::SqliteIndexedTar;

    fn member_file<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
        UstarMember {
            path,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn member_dir(path: &str) -> UstarMember<'_> {
        UstarMember {
            path,
            payload: UstarPayload::Directory,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn member_symlink<'a>(path: &'a str, target: &'a str) -> UstarMember<'a> {
        UstarMember {
            path,
            payload: UstarPayload::Symlink { target },
            mode: 0o777,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn pack(members: &[UstarMember<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        write_ustar_members(&mut out, members).expect("write members");
        write_tar_eof(&mut out).expect("eof");
        out
    }

    fn open_mem(bytes: Vec<u8>) -> SqliteIndexedTar {
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        SqliteIndexedTar::open_from_reader(
            Cursor::new(bytes),
            Path::new("memory://write-test.tar"),
            None,
            &opts,
            "0.1.0",
        )
        .expect("open_from_reader")
    }

    fn read_path(m: &SqliteIndexedTar, path: &str) -> Vec<u8> {
        let fi = m.lookup(path, 0).unwrap_or_else(|| panic!("lookup {path}"));
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        buf
    }

    /// Regression: short-name regular file round-trips through the real indexer.
    #[test]
    fn writer_roundtrip_short_file() {
        let payload = b"hello world\n";
        let bytes = pack(&[member_file("hello.txt", payload)]);
        let m = open_mem(bytes);
        assert_eq!(read_path(&m, "/hello.txt"), payload);
        let fi = m.lookup("/hello.txt", 0).unwrap();
        assert_eq!(fi.size, payload.len() as u64);
        assert_eq!(fi.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFREG);
    }

    /// Regression: path > 100 bytes uses PAX `path=` and indexes under the full name.
    #[test]
    fn writer_roundtrip_pax_long_path() {
        let path = format!("dir/{}/file.txt", "n".repeat(120));
        assert!(path.len() > 100);
        let payload = b"pax-body";
        let bytes = pack(&[member_file(&path, payload)]);
        // PAX helper name is PaxHeaders.0/ + truncated path (prefix kept).
        assert!(bytes.starts_with(b"PaxHeaders.0/"));
        assert_eq!(bytes[156], b'x');
        let pax_name_end = bytes[..100].iter().position(|&b| b == 0).unwrap_or(100);
        assert!(pax_name_end <= 100);
        assert!(std::str::from_utf8(&bytes[..pax_name_end])
            .unwrap()
            .starts_with(PAX_HDR_PREFIX));

        let m = open_mem(bytes);
        assert_eq!(read_path(&m, &format!("/{path}")), payload);
    }

    /// Regression: size ≥ 8 GiB encodes PAX `size=` and ustar size 0 (no 8 GiB alloc).
    #[test]
    fn writer_pax_size_header_encoding() {
        let huge = USTAR_MAX_SIZE + 1;
        let member = member_file("huge.bin", b"");
        let mut headers = Vec::new();
        write_member_headers(&mut headers, &member, huge).expect("headers");
        assert_eq!(headers[156], b'x');
        let pax_size = parse_octal(&headers[124..136]).unwrap();
        let pax_body = &headers[512..512 + pax_size as usize];
        let rec = format!("size={huge}");
        assert!(
            pax_body.windows(rec.len()).any(|w| w == rec.as_bytes()),
            "pax body missing {rec}: {:?}",
            String::from_utf8_lossy(pax_body)
        );
        let file_off = 512 + pad512(pax_size);
        let file_hdr = &headers[file_off as usize..];
        assert_eq!(file_hdr[156], b'0');
        assert_eq!(parse_octal(&file_hdr[124..136]), Some(0));

        // Small file still round-trips without a PAX size record.
        let small = b"tiny";
        let bytes = pack(&[member_file("small.bin", small)]);
        assert!(!bytes.windows(5).any(|w| w == b"size="));
        let m = open_mem(bytes);
        assert_eq!(read_path(&m, "/small.bin"), small);
    }

    /// Regression: symlink typeflag `'2'` and linkname survive the indexer.
    #[test]
    fn writer_roundtrip_symlink() {
        let bytes = pack(&[member_symlink("link", "target/path")]);
        let m = open_mem(bytes);
        let fi = m.lookup("/link", 0).expect("lookup symlink");
        assert_eq!(fi.linkname, "target/path");
        assert_eq!(fi.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFLNK);
    }

    /// Regression: directory typeflag `'5'` and ustar name ends with `/`.
    #[test]
    fn writer_roundtrip_empty_directory() {
        let bytes = pack(&[member_dir("emptydir")]);
        let name_end = bytes[..100].iter().position(|&b| b == 0).unwrap_or(100);
        assert_eq!(&bytes[..name_end], b"emptydir/");
        assert_eq!(bytes[156], b'5');
        let m = open_mem(bytes);
        let fi = m.lookup("/emptydir", 0).expect("lookup dir");
        assert_eq!(fi.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFDIR);
        if let ListResult::Infos(map) = m.list("/").expect("list") {
            assert!(map.contains_key("emptydir"), "keys: {:?}", map.keys());
        }
    }

    /// Regression: last two-zero pair wins; mid-payload `stream_offset` is aligned.
    #[test]
    fn find_last_tar_eof_mid_payload_last_pair_wins() {
        let payload_a = vec![0xab; 600];
        let mut archive = pack(&[member_file("a.bin", &payload_a)]);
        // Concatenate a second frame (second EOF pair).
        let frame_b = pack(&[member_file("b.txt", b"x")]);
        archive.extend_from_slice(&frame_b);

        let eof1 = 512 + pad512(600);
        let eof2 = archive.len() as u64 - 1024;
        assert!(eof2 > eof1);

        let mid = 512 + 50; // inside a.bin payload; not 512-aligned to a member start
        assert_ne!(mid % 512, 0);
        let suffix = archive[mid as usize..].to_vec();
        let mut cur = Cursor::new(suffix);
        let found = find_last_tar_eof(&mut cur, mid).expect("eof scan");
        assert_eq!(found, Some(eof2 - mid));
        assert_ne!(found, Some(eof1 - mid));
    }

    /// Regression: drop a last-window PAX-named member (including its `x` helper).
    #[test]
    fn rewrite_drops_pax_named_member_and_appends() {
        let long = format!("pax-{}", "z".repeat(110));
        let keep_payload = b"keep-bytes";
        let new_payload = b"generated";
        let archive = pack(&[
            member_file(&long, b"drop-me"),
            member_file("keep.txt", keep_payload),
        ]);

        let mut deleted = HashSet::new();
        deleted.insert(normalize_archive_rel_path(&long));
        let append = [member_file("new.txt", new_payload)];
        let opts = RewriteTarSuffix {
            deleted_paths: &deleted,
            append: &append,
            encoding: "utf-8",
        };
        let mut out = Vec::new();
        let stats =
            rewrite_tar_suffix(&mut Cursor::new(archive), 0, &opts, &mut out).expect("rewrite");
        assert_eq!(stats.members_dropped, 1);
        assert_eq!(stats.members_appended, 1);

        let expected = pack(&[
            member_file("keep.txt", keep_payload),
            member_file("new.txt", new_payload),
        ]);
        assert_eq!(out, expected);

        let m = open_mem(out);
        assert!(m.lookup(&format!("/{long}"), 0).is_none());
        assert_eq!(read_path(&m, "/keep.txt"), keep_payload);
        assert_eq!(read_path(&m, "/new.txt"), new_payload);
    }

    /// Regression: FileOnDisk reads the host file; a symlink path fails (O_NOFOLLOW).
    #[test]
    fn file_on_disk_reads_and_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.txt");
        let payload = b"from-disk\n";
        std::fs::write(&real, payload).unwrap();

        let on_disk = UstarMember {
            path: "copied.txt",
            payload: UstarPayload::FileOnDisk {
                path: &real,
                size: payload.len() as u64,
            },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        };
        let bytes = pack(&[on_disk]);
        let m = open_mem(bytes);
        assert_eq!(read_path(&m, "/copied.txt"), payload);

        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let sneaky = [UstarMember {
            path: "escaped.txt",
            payload: UstarPayload::FileOnDisk {
                path: &link,
                size: payload.len() as u64,
            },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }];
        let mut out = Vec::new();
        let err = write_ustar_members(&mut out, &sneaky).expect_err("symlink must not be followed");
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    }

    /// Regression: a mid-member opaque window with nonzero content fails
    /// closed (the data end is unknowable without a member boundary; the old
    /// zero-run cut could silently truncate a zero-tailed member). Delete
    /// without parseable headers also fails.
    #[test]
    fn rewrite_mid_member_opaque_prefix() {
        let payload = vec![0xcd; 600];
        let archive = pack(&[member_file("a.bin", &payload)]);
        let mid = 512 + 50;
        let suffix = archive[mid as usize..].to_vec();
        let extra = b"appended";

        let empty = HashSet::new();
        let append = [member_file("extra.txt", extra)];
        let err = rewrite_tar_suffix(
            &mut Cursor::new(suffix.clone()),
            mid,
            &RewriteTarSuffix {
                deleted_paths: &empty,
                append: &append,
                encoding: "utf-8",
            },
            &mut Vec::new(),
        )
        .expect_err("append into opaque nonzero window must fail closed");
        assert!(
            err.to_string()
                .contains("could not parse last-window TAR headers"),
            "unexpected error: {err}"
        );

        let mut deleted = HashSet::new();
        deleted.insert("a.bin".to_string());
        let err = rewrite_tar_suffix(
            &mut Cursor::new(suffix),
            mid,
            &RewriteTarSuffix {
                deleted_paths: &deleted,
                append: &[],
                encoding: "utf-8",
            },
            &mut Vec::new(),
        )
        .expect_err("delete without parseable headers");
        assert!(
            err.to_string()
                .contains("could not parse last-window TAR headers"),
            "unexpected error: {err}"
        );
    }

    /// Regression: all-zero window (old EOF / record padding) accepts appends;
    /// the padding is dropped so new members are not hidden behind the old
    /// EOF pair.
    #[test]
    fn rewrite_all_zero_window_appends_without_kept_zeros() {
        let suffix = vec![0u8; 2048];
        let extra = b"appended";
        let empty = HashSet::new();
        let append = [member_file("extra.txt", extra)];
        let mut out = Vec::new();
        let stats = rewrite_tar_suffix(
            &mut Cursor::new(suffix),
            0,
            &RewriteTarSuffix {
                deleted_paths: &empty,
                append: &append,
                encoding: "utf-8",
            },
            &mut out,
        )
        .expect("append into zero padding window");
        assert_eq!(stats.bytes_kept, 0, "padding must not be kept");
        assert_eq!(stats.members_appended, 1);
        let expected = pack(&[member_file("extra.txt", extra)]);
        assert_eq!(out, expected);
    }

    /// Regression: zero-tail member must survive a rewrite (the trailing zero
    /// run scan cut into payload zeros, truncating the member and hiding
    /// appends behind the padding).
    #[test]
    fn rewrite_zero_tail_member_not_truncated() {
        // 1024-byte all-zero payload: final payload blocks are all zero and
        // run into the EOF marker contiguously.
        let zeros = vec![0u8; 1024];
        let archive = pack(&[member_file("zeros.bin", &zeros)]);
        let extra = b"new-bytes";
        let appended = [member_file("new.txt", extra)];
        let empty = HashSet::new();
        let mut out = Vec::new();
        let stats = rewrite_tar_suffix(
            &mut Cursor::new(archive.clone()),
            0,
            &RewriteTarSuffix {
                deleted_paths: &empty,
                append: &appended,
                encoding: "utf-8",
            },
            &mut out,
        )
        .expect("rewrite with zero-tail member");
        assert_eq!(stats.members_kept, 1);
        assert_eq!(stats.members_appended, 1);

        // Byte-exact shape: original member span, then the append, then EOF.
        let mut expected = archive[..512 + 1024].to_vec();
        expected.extend_from_slice(&pack(&[member_file("new.txt", extra)]));
        assert_eq!(out, expected);

        // Parse the result with the real indexer: zeros.bin intact, new.txt present.
        let m = open_mem(out);
        assert_eq!(read_path(&m, "/zeros.bin"), zeros.as_slice());
        assert_eq!(read_path(&m, "/new.txt"), extra);
    }

    /// Regression: GNU long-name `L` helper is consumed so a last-window delete works.
    #[test]
    fn rewrite_drops_gnu_long_name_member() {
        let long = "n".repeat(130);
        let payload = b"gnu-body";
        let mut archive = Vec::new();
        let mut lbody = long.as_bytes().to_vec();
        lbody.push(0);
        write_raw_ustar_header(
            &mut archive,
            UstarHeaderFields {
                name: b"././@LongLink",
                size: lbody.len() as u64,
                typeflag: b'L',
                linkname: b"",
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
        )
        .unwrap();
        archive.extend_from_slice(&lbody);
        write_padding(&mut archive, lbody.len() as u64).unwrap();
        write_raw_ustar_header(
            &mut archive,
            UstarHeaderFields {
                name: last_bytes(long.as_bytes(), USTAR_NAME_LEN),
                size: payload.len() as u64,
                typeflag: b'0',
                linkname: b"",
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
        )
        .unwrap();
        archive.extend_from_slice(payload);
        write_padding(&mut archive, payload.len() as u64).unwrap();
        let keep = b"stay";
        write_ustar_members(&mut archive, &[member_file("keep.txt", keep)]).unwrap();
        write_tar_eof(&mut archive).unwrap();

        let mut deleted = HashSet::new();
        deleted.insert(normalize_archive_rel_path(&long));
        let mut out = Vec::new();
        let stats = rewrite_tar_suffix(
            &mut Cursor::new(archive),
            0,
            &RewriteTarSuffix {
                deleted_paths: &deleted,
                append: &[],
                encoding: "utf-8",
            },
            &mut out,
        )
        .expect("rewrite gnu L");
        assert_eq!(stats.members_dropped, 1);

        let m = open_mem(out);
        assert!(m.lookup(&format!("/{long}"), 0).is_none());
        assert_eq!(read_path(&m, "/keep.txt"), keep);
    }

    /// Global PAX `g` is copied even when the next member is dropped.
    #[test]
    fn rewrite_copies_global_pax_before_dropped_member() {
        let mut archive = Vec::new();
        let rec = encode_pax_record("comment", b"global").unwrap();
        write_raw_ustar_header(
            &mut archive,
            UstarHeaderFields {
                name: b"g",
                size: rec.len() as u64,
                typeflag: b'g',
                linkname: b"",
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
        )
        .unwrap();
        archive.extend_from_slice(&rec);
        write_padding(&mut archive, rec.len() as u64).unwrap();
        write_ustar_members(
            &mut archive,
            &[member_file("gone.txt", b"x"), member_file("stay.txt", b"y")],
        )
        .unwrap();
        write_tar_eof(&mut archive).unwrap();

        let mut deleted = HashSet::new();
        deleted.insert("gone.txt".to_string());
        let mut out = Vec::new();
        rewrite_tar_suffix(
            &mut Cursor::new(archive),
            0,
            &RewriteTarSuffix {
                deleted_paths: &deleted,
                append: &[],
                encoding: "utf-8",
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(out[156], b'g');
        let m = open_mem(out);
        assert!(m.lookup("/gone.txt", 0).is_none());
        assert_eq!(read_path(&m, "/stay.txt"), b"y");
    }

    #[test]
    fn normalize_strips_slashes_and_dot_slash() {
        assert_eq!(normalize_archive_rel_path("/./foo/bar/"), "foo/bar");
        assert_eq!(normalize_archive_rel_path("./a"), "a");
        assert_eq!(normalize_archive_rel_path("a/b"), "a/b");
        assert_eq!(normalize_archive_rel_path("foo/./bar"), "foo/bar");
        assert_eq!(normalize_archive_rel_path("foo//bar"), "foo/bar");
        assert_eq!(normalize_archive_rel_path("foo/../bar"), "bar");
    }

    /// Regression: GNU tar record padding (10 KiB / 20-block) must not hide appended members.
    #[test]
    fn rewrite_gnu_record_padding_append_visible() {
        let keep = b"keep-payload";
        let extra = b"after-padding";
        let mut archive = pack(&[member_file("keep.txt", keep)]);
        let real_eof = archive.len() as u64 - 1024;
        archive.extend(std::iter::repeat_n(0u8, 16 * 512));
        let padded_len = archive.len() as u64;

        let found = find_last_tar_eof(&mut Cursor::new(archive.clone()), 0).expect("eof");
        assert_eq!(found, Some(real_eof));
        assert_ne!(found, Some(padded_len - 1024));

        let empty = HashSet::new();
        let append = [member_file("extra.txt", extra)];
        let mut out = Vec::new();
        rewrite_tar_suffix(
            &mut Cursor::new(archive),
            0,
            &RewriteTarSuffix {
                deleted_paths: &empty,
                append: &append,
                encoding: "utf-8",
            },
            &mut out,
        )
        .expect("rewrite padded");

        let expected = pack(&[
            member_file("keep.txt", keep),
            member_file("extra.txt", extra),
        ]);
        assert_eq!(out, expected);

        let m = open_mem(out);
        assert_eq!(read_path(&m, "/keep.txt"), keep);
        assert_eq!(read_path(&m, "/extra.txt"), extra);
    }

    /// Unmatched last-window deletes must fail rather than append a silent second version.
    #[test]
    fn rewrite_unmatched_delete_errors() {
        let archive = pack(&[member_file("keep.txt", b"x")]);
        let mut deleted = HashSet::new();
        deleted.insert("missing.txt".to_string());
        let err = rewrite_tar_suffix(
            &mut Cursor::new(archive),
            0,
            &RewriteTarSuffix {
                deleted_paths: &deleted,
                append: &[],
                encoding: "utf-8",
            },
            &mut Vec::new(),
        )
        .expect_err("unmatched delete");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("missing.txt"),
            "error should name the path: {err}"
        );
    }

    /// Regression: uid/gid/mtime that do not fit ustar octal fields use PAX, not prefix truncation.
    #[test]
    fn writer_pax_uid_gid_mtime_no_octal_prefix_truncate() {
        let uid = octal_digit_max(7) + 1; // 8^7
        let gid = uid + 1;
        let mtime = octal_digit_max(11) + 1;
        let member = UstarMember {
            path: "wide.bin",
            payload: UstarPayload::File { bytes: b"x" },
            mode: 0o644,
            uid: uid as u32,
            gid: gid as u32,
            mtime,
        };
        let mut headers = Vec::new();
        write_member_headers(&mut headers, &member, 1).expect("headers");
        assert_eq!(headers[156], b'x');
        let pax_size = parse_octal(&headers[124..136]).unwrap();
        let pax_body = &headers[512..512 + pax_size as usize];
        let pax = String::from_utf8_lossy(pax_body);
        assert!(pax.contains(&format!("uid={uid}")), "{pax}");
        assert!(pax.contains(&format!("gid={gid}")), "{pax}");
        assert!(pax.contains(&format!("mtime={mtime}")), "{pax}");
        let file_off = 512 + pad512(pax_size);
        let file_hdr = &headers[file_off as usize..];
        assert_eq!(parse_octal(&file_hdr[108..116]), Some(0));
        assert_eq!(parse_octal(&file_hdr[116..124]), Some(0));
        assert_eq!(parse_octal(&file_hdr[136..148]), Some(0));
    }

    /// A global `g` between pending PAX `x` and the file is refused (would swallow `g` or poison the next name).
    #[test]
    fn rewrite_refuses_global_pax_between_helper_and_file() {
        let mut archive = Vec::new();
        let xbody = encode_pax_record("path", b"gone.txt").unwrap();
        write_raw_ustar_header(
            &mut archive,
            UstarHeaderFields {
                name: b"PaxHeaders.0/gone.txt",
                size: xbody.len() as u64,
                typeflag: b'x',
                linkname: b"",
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
        )
        .unwrap();
        archive.extend_from_slice(&xbody);
        write_padding(&mut archive, xbody.len() as u64).unwrap();
        let gbody = encode_pax_record("comment", b"global").unwrap();
        write_raw_ustar_header(
            &mut archive,
            UstarHeaderFields {
                name: b"g",
                size: gbody.len() as u64,
                typeflag: b'g',
                linkname: b"",
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
        )
        .unwrap();
        archive.extend_from_slice(&gbody);
        write_padding(&mut archive, gbody.len() as u64).unwrap();
        write_ustar_members(
            &mut archive,
            &[
                member_file("gone.txt", b"drop"),
                member_file("stay.txt", b"y"),
            ],
        )
        .unwrap();
        write_tar_eof(&mut archive).unwrap();

        let mut deleted = HashSet::new();
        deleted.insert("gone.txt".to_string());
        let err = rewrite_tar_suffix(
            &mut Cursor::new(archive),
            0,
            &RewriteTarSuffix {
                deleted_paths: &deleted,
                append: &[],
                encoding: "utf-8",
            },
            &mut Vec::new(),
        )
        .expect_err("g between helper and file");
        assert!(
            err.to_string().contains("global PAX g between pending"),
            "unexpected error: {err}"
        );
    }

    /// Seek/EOF-scan failure in `TarMemberCursor::new` must surface on `next_member`.
    #[test]
    fn cursor_surfaces_init_seek_error() {
        struct FailSeek;
        impl Read for FailSeek {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Ok(0)
            }
        }
        impl Seek for FailSeek {
            fn seek(&mut self, _from: SeekFrom) -> io::Result<u64> {
                Err(io::Error::other("seek failed"))
            }
        }
        let mut c = TarMemberCursor::new(FailSeek, 0, 0, "utf-8");
        let err = c
            .next_member()
            .expect_err("init seek must not be swallowed");
        assert!(
            err.to_string().contains("seek failed"),
            "unexpected error: {err}"
        );
    }
}
