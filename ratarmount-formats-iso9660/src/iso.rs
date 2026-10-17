//! Directory decoding shared by path and seekable-reader opens.
use super::{IsoError, Result, SECTOR};
use ratarmount_core::{S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};

const MAX_CE_HOPS: usize = 64;
const MAX_CE_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub(super) struct RockRidge {
    pub name: Option<String>,
    pub mode: Option<u32>,
    // FileInfo / the shared index schema do not expose link counts or serials.
    nlink: Option<u32>,
    pub uid: u32,
    pub gid: u32,
    pub link: Option<String>,
    pub mtime: Option<f64>,
    relocated: bool,
    child: Option<u32>,
}

pub(super) struct Record {
    length: usize,
    pub extent: u32,
    pub size: u32,
    pub is_dir: bool,
    pub name: Option<String>,
    pub mtime: f64,
    system_use: Vec<u8>,
    pub rr: RockRidge,
}

impl Record {
    pub fn mode(&self) -> u32 {
        let default = if self.is_dir {
            S_IFDIR | 0o755
        } else {
            S_IFREG | 0o644
        };
        let mode = self.rr.mode.unwrap_or(default);
        if self.rr.link.is_some() {
            (mode & !S_IFMT) | S_IFLNK
        } else {
            mode
        }
    }
}

pub(super) struct Node {
    pub parent: usize,
    pub record: Record,
}

fn le32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

fn parse_record(data: &[u8], joliet: bool) -> Option<Record> {
    let length = usize::from(*data.first()?);
    let rec = data.get(..length)?;
    if length < 34 {
        return None;
    }
    let name_len = usize::from(rec[32]);
    let identifier = rec.get(33..33 + name_len)?;
    let su_start = 33 + name_len + usize::from(name_len % 2 == 0);
    let system_use = rec.get(su_start..)?.to_vec();
    let name = if identifier == [0] || identifier == [1] {
        None
    } else if joliet {
        // Joliet is UCS-2, not UTF-16: each surrogate is an invalid code unit.
        if name_len % 2 != 0 {
            None
        } else {
            let raw: String = identifier
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| {
                    char::from_u32(u32::from(u16::from_be_bytes([b[0], b[1]])))
                        .unwrap_or(char::REPLACEMENT_CHARACTER)
                })
                .collect();
            Some(raw.split(';').next()?.to_owned())
        }
    } else {
        let raw = String::from_utf8_lossy(identifier);
        Some(raw.split(';').next()?.trim_end_matches('.').to_owned())
    }
    .filter(|s| valid_name(s));
    Some(Record {
        length,
        extent: le32(rec, 2),
        size: le32(rec, 10),
        is_dir: rec[25] & 2 != 0,
        name,
        mtime: timestamp(&rec[18..25], false).unwrap_or(0.0),
        system_use,
        rr: RockRidge::default(),
    })
}

// ECMA-119 recording time / volume time, including signed 15-minute GMT offset.
// Pure Gregorian arithmetic avoids local timezone and platform time_t limits.
fn timestamp(data: &[u8], long: bool) -> Option<f64> {
    let decimal = |part: &[u8]| -> Option<i64> {
        part.iter().try_fold(0, |n, &b| {
            b.is_ascii_digit().then(|| n * 10 + i64::from(b - b'0'))
        })
    };
    let (year, month, day, hour, minute, second, centis, zone) = if long {
        if data.len() != 17 {
            return None;
        }
        (
            decimal(&data[..4])?,
            decimal(&data[4..6])?,
            decimal(&data[6..8])?,
            decimal(&data[8..10])?,
            decimal(&data[10..12])?,
            decimal(&data[12..14])?,
            decimal(&data[14..16])?,
            data[16] as i8,
        )
    } else {
        if data.len() != 7 {
            return None;
        }
        (
            i64::from(data[0]) + 1900,
            i64::from(data[1]),
            i64::from(data[2]),
            i64::from(data[3]),
            i64::from(data[4]),
            i64::from(data[5]),
            0,
            data[6] as i8,
        )
    };
    if !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
        || !(-48..=52).contains(&zone)
    {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=days[month as usize - 1]).contains(&day) {
        return None;
    }
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * month + 2) / 5 + day - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    Some(
        (days * 86400 + hour * 3600 + minute * 60 + second - i64::from(zone) * 900) as f64
            + centis as f64 / 100.0,
    )
}

fn susp_skip(dot: &Record) -> Option<usize> {
    // SP is normally the first system-use entry. CD-ROM XA permits a prefix;
    // accept one only when SP's skip byte identifies that exact prefix length.
    dot.system_use
        .windows(7)
        .enumerate()
        .find_map(|(offset, sp)| {
            (sp[..6] == [b'S', b'P', 7, 1, 0xbe, 0xef]
                && (offset == 0 || usize::from(sp[6]) == offset))
                .then_some(usize::from(sp[6]))
        })
}

fn parse_susp<R: Read + Seek>(file: &mut R, area: &[u8], image_size: u64) -> Option<RockRidge> {
    let mut rr = RockRidge::default();
    let mut pending = vec![area.to_vec()];
    let mut visited = HashSet::new();
    let mut total = 0usize;
    let mut nm_bytes = Vec::new();
    let mut nm_continues = false;
    let mut sl_bytes = Vec::new();
    let mut sl_seen = false;
    let mut sl_continues = false;
    let mut component_continues = false;
    while let Some(area) = pending.pop() {
        let mut remaining = area.as_slice();
        let mut continuations = Vec::new();
        while !remaining.is_empty() {
            // A zero-filled tail is padding, not a zero-length entry.
            if remaining.iter().all(|&b| b == 0) {
                break;
            }
            if remaining.len() < 4 {
                return None;
            }
            let length = usize::from(remaining[2]);
            if length < 4 {
                return None;
            }
            let e = remaining.get(..length)?;
            remaining = &remaining[length..];
            if e[3] != 1 {
                continue;
            }
            match &e[..2] {
                b"ST" => break,
                b"CE" => {
                    if length != 28 || visited.len() >= MAX_CE_HOPS {
                        return None;
                    }
                    let start = u64::from(le32(e, 4)) * SECTOR + u64::from(le32(e, 12));
                    let len = le32(e, 20) as usize;
                    total = total.checked_add(len)?;
                    if total > MAX_CE_BYTES
                        || start.checked_add(len as u64)? > image_size
                        || !visited.insert((start, len))
                    {
                        return None;
                    }
                    file.seek(SeekFrom::Start(start)).ok()?;
                    let mut bytes = vec![0; len];
                    file.read_exact(&mut bytes).ok()?;
                    continuations.push(bytes);
                }
                b"NM" => {
                    let flags = *e.get(4)?;
                    if flags & 6 != 0 {
                        continue;
                    } // current / parent identifier
                    if flags & !1 != 0 || (rr.name.is_some() && !nm_continues) {
                        return None;
                    }
                    nm_bytes.extend_from_slice(&e[5..]);
                    nm_continues = flags & 1 != 0;
                    if !nm_continues {
                        let name = String::from_utf8_lossy(&nm_bytes).into_owned();
                        if !valid_name(&name) {
                            return None;
                        }
                        rr.name = Some(name);
                    }
                }
                b"PX" => {
                    if length != 36 && length != 44 {
                        return None;
                    }
                    rr.mode = Some(le32(e, 4));
                    rr.nlink = Some(le32(e, 12));
                    rr.uid = le32(e, 20);
                    rr.gid = le32(e, 28);
                }
                b"SL" => {
                    let flags = *e.get(4)?;
                    if flags & !1 != 0 || (sl_seen && !sl_continues) {
                        return None;
                    }
                    sl_seen = true;
                    sl_continues = flags & 1 != 0;
                    let mut components = &e[5..];
                    while !components.is_empty() {
                        let flags = components[0];
                        let len = usize::from(*components.get(1)?);
                        let bytes = components.get(2..2 + len)?;
                        components = &components[2 + len..];
                        if flags & !15 != 0 {
                            return None;
                        }
                        let special = flags & 14;
                        if special != 0 && (len != 0 || flags & 1 != 0 || component_continues) {
                            return None;
                        }
                        let bytes = match special {
                            0 => {
                                if bytes.contains(&0) || bytes.contains(&b'/') {
                                    return None;
                                }
                                bytes
                            }
                            2 => b".",
                            4 => b"..",
                            8 => {
                                if !sl_bytes.is_empty() {
                                    return None;
                                }
                                b"/"
                            }
                            _ => return None,
                        };
                        if !component_continues && !sl_bytes.is_empty() && !sl_bytes.ends_with(b"/")
                        {
                            sl_bytes.push(b'/');
                        }
                        sl_bytes.extend_from_slice(bytes);
                        component_continues = flags & 1 != 0;
                    }
                }
                b"TF" => {
                    let flags = *e.get(4)?;
                    let long = flags & 128 != 0;
                    let width = if long { 17 } else { 7 };
                    let mut offset = 5;
                    for bit in 0..7 {
                        if flags & (1 << bit) != 0 {
                            let bytes = e.get(offset..offset + width)?;
                            if bit == 1 {
                                rr.mtime = timestamp(bytes, long);
                            }
                            offset += width;
                        }
                    }
                }
                b"RE" => rr.relocated = true,
                b"CL" => {
                    if length != 12 {
                        return None;
                    }
                    rr.child = Some(le32(e, 4));
                }
                // Recognized but not represented by FileInfo; unknown extensions
                // (including AAIP) are likewise skipped using their declared length.
                b"SP" | b"RR" | b"ER" | b"PN" | b"SF" | b"PL" => (),
                _ => (),
            }
        }
        pending.extend(continuations.into_iter().rev());
    }
    if nm_continues || sl_continues || component_continues {
        return None;
    }
    if sl_seen {
        if sl_bytes.is_empty() {
            return None;
        }
        rr.link = Some(String::from_utf8_lossy(&sl_bytes).into_owned());
    }
    Some(rr)
}

fn sector<R: Read + Seek>(file: &mut R, block: u32) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(u64::from(block) * SECTOR))?;
    let mut data = vec![0; SECTOR as usize];
    file.read_exact(&mut data)?;
    Ok(data)
}

/// One work queue visits each directory once, across the primary and optional
/// Joliet namespaces. No name-detection prewalk: parent IDs retain the metadata
/// until we know whether *any* NM exists, including in the last subdirectory.
/// Only directory metadata (not member contents) is retained.
pub(super) fn read_entries<R: Read + Seek>(file: &mut R) -> Result<Vec<Node>> {
    let image_size = file.seek(SeekFrom::End(0))?;
    let pvd = sector(file, 16)?;
    if pvd[0] != 1 || &pvd[1..6] != b"CD001" {
        return Err(IsoError::Msg(
            "Not a valid ISO 9660 image (missing primary volume descriptor)".into(),
        ));
    }
    let root = parse_record(&pvd[156..], false)
        .ok_or_else(|| IsoError::Msg("ISO 9660 PVD has no root directory".into()))?;
    let mut joliet_root = None;
    // Descriptor sequences are bounded even on images without a terminator.
    for block in 17..(image_size / SECTOR).min(16 + 256) as u32 {
        let vd = sector(file, block)?;
        if &vd[1..6] != b"CD001" || vd[0] == 255 {
            break;
        }
        if vd[0] == 2 && matches!(&vd[88..91], b"%/@" | b"%/C" | b"%/E") {
            joliet_root = parse_record(&vd[156..], true);
        }
    }
    let first = sector(file, root.extent)?;
    let skip = if first.get(32..34) == Some(&[1, 0]) {
        parse_record(&first, false).as_ref().and_then(susp_skip)
    } else {
        None
    };
    let mut cached = HashMap::from([(root.extent, first)]);
    let mut trees = [
        vec![Node {
            parent: 0,
            record: root,
        }],
        Vec::new(),
    ];
    let mut pending = Vec::new();
    if skip.is_some() || joliet_root.is_none() {
        pending.push((0, 0));
    }
    if let Some(root) = joliet_root {
        trees[1].push(Node {
            parent: 0,
            record: root,
        });
        pending.push((1, 0));
    }
    let mut seen = [HashSet::new(), HashSet::new()];
    while let Some((tree, parent)) = pending.pop() {
        let dir = &trees[tree][parent].record;
        let extent = dir.extent;
        let size = u64::from(dir.size);
        if !seen[tree].insert(extent) {
            continue;
        }
        if u64::from(extent) * SECTOR + size > image_size {
            return Err(IsoError::Msg("ISO directory extends beyond image".into()));
        }
        let mut consumed = 0;
        while consumed < size {
            let block = extent + (consumed / SECTOR) as u32;
            let data = match cached.remove(&block) {
                Some(data) => data,
                None => sector(file, block)?,
            };
            let data = &data[..(size - consumed).min(SECTOR) as usize];
            let mut offset = 0;
            while offset < data.len() && data[offset] != 0 {
                let Some(mut rec) = parse_record(&data[offset..], tree == 1) else {
                    break;
                };
                offset += rec.length;
                if rec.name.is_none() {
                    continue;
                }
                if tree == 0 {
                    if let Some(area) = skip.and_then(|n| rec.system_use.get(n..)) {
                        rec.rr = parse_susp(file, area, image_size).unwrap_or_default();
                    }
                    if rec.rr.relocated {
                        continue;
                    }
                    if let Some(child) = rec.rr.child {
                        // A CL placeholder's size/flags are not the target's.
                        // Read its '.' record, retaining that sector for the walk.
                        let target = if let Some(bytes) = cached.get(&child) {
                            Ok(bytes.clone())
                        } else {
                            sector(file, child)
                        };
                        if let Ok(bytes) = target {
                            if let Some(dot) = parse_record(&bytes, false).filter(|r| {
                                r.name.is_none()
                                    && r.is_dir
                                    && r.extent == child
                                    && u64::from(child) * SECTOR + u64::from(r.size) <= image_size
                            }) {
                                rec.extent = child;
                                rec.size = dot.size;
                                rec.is_dir = true;
                                cached.insert(child, bytes);
                            } else {
                                rec.rr = RockRidge::default();
                            }
                        } else {
                            rec.rr = RockRidge::default();
                        }
                    }
                }
                rec.system_use.clear();
                let id = trees[tree].len();
                if rec.is_dir && rec.rr.link.is_none() {
                    pending.push((tree, id));
                }
                trees[tree].push(Node {
                    parent,
                    record: rec,
                });
            }
            consumed += SECTOR;
        }
    }
    let [mut primary, mut joliet] = trees;
    if !joliet.is_empty() {
        let matches = apply_joliet_fallback(&mut primary, &joliet);
        if !primary.iter().any(|node| node.record.rr.name.is_some()) {
            // Joliet supplies the namespace, but SUSP may still carry POSIX
            // attributes without a single NM. Keep those attributes and links
            // omitted from the Joliet namespace (which cannot encode symlinks).
            for (id, node) in primary.into_iter().enumerate().skip(1) {
                if let Some(j) = matches[id] {
                    joliet[j].record.rr = node.record.rr;
                } else if node.record.rr.link.is_some() {
                    if let Some(parent) = matches[node.parent] {
                        joliet.push(Node {
                            parent,
                            record: node.record,
                        });
                    }
                }
            }
            return Ok(joliet);
        }
    }
    Ok(primary)
}

/// File data extents are shared by both namespaces; directory extents are not.
/// Unique matching children establish directory correspondence bottom-up. Never
/// guess by directory record order (Joliet and ISO sort names differently).
fn apply_joliet_fallback(primary: &mut [Node], joliet: &[Node]) -> Vec<Option<usize>> {
    let mut by_extent: HashMap<(u32, u32), Vec<usize>> = HashMap::new();
    for (id, node) in joliet.iter().enumerate().skip(1) {
        if !node.record.is_dir {
            by_extent
                .entry((node.record.extent, node.record.size))
                .or_default()
                .push(id);
        }
    }
    let mut matches = vec![None; primary.len()];
    let mut ambiguous = HashSet::new();
    matches[0] = Some(0);
    for id in (1..primary.len()).rev() {
        let rec = &primary[id].record;
        if !rec.is_dir && rec.rr.link.is_none() {
            if let Some(candidates) = by_extent.get(&(rec.extent, rec.size)) {
                matches[id] = match candidates.as_slice() {
                    [only] => Some(*only),
                    _ => candidates.iter().copied().find(|&j| {
                        joliet[j].record.name == rec.rr.name || joliet[j].record.name == rec.name
                    }),
                };
            }
        }
        if let Some(j) = matches[id] {
            let p = primary[id].parent;
            let jp = joliet[j].parent;
            if matches[p].is_some_and(|old| old != jp) {
                ambiguous.insert(p);
            }
            if !ambiguous.contains(&p) {
                matches[p] = Some(jp);
            } else {
                matches[p] = None;
            }
        }
    }
    // Resolve remaining aliases within matched parents. A single unmatched
    // directory on each side is also unambiguous, including an empty directory.
    // Multiple empty siblings with different names have no on-disc shared ID.
    matches[0] = Some(0);
    let mut children = [HashMap::<usize, Vec<usize>>::new(), HashMap::new()];
    for (tree, nodes) in [&*primary, joliet].into_iter().enumerate() {
        for (id, node) in nodes.iter().enumerate().skip(1) {
            children[tree].entry(node.parent).or_default().push(id);
        }
    }
    for parent in 0..primary.len() {
        let Some(jparent) = matches[parent] else {
            continue;
        };
        let Some(pchildren) = children[0].get(&parent) else {
            continue;
        };
        let Some(jchildren) = children[1].get(&jparent) else {
            continue;
        };
        for &id in pchildren {
            if matches[id].is_some() {
                continue;
            }
            let rec = &primary[id].record;
            // SL extents do not identify file contents in the Joliet tree.
            if rec.rr.link.is_some() {
                continue;
            }
            let candidates: Vec<_> = jchildren
                .iter()
                .copied()
                .filter(|&j| {
                    let other = &joliet[j].record;
                    other.is_dir == rec.is_dir
                        && (other.name == rec.rr.name
                            || other.name == rec.name
                            || (!rec.is_dir
                                && other.extent == rec.extent
                                && other.size == rec.size))
                })
                .collect();
            if let [only] = candidates.as_slice() {
                matches[id] = Some(*only);
            }
        }
        let unmatched_primary: Vec<_> = pchildren
            .iter()
            .copied()
            .filter(|&p| primary[p].record.is_dir && matches[p].is_none())
            .collect();
        let used: HashSet<_> = pchildren.iter().filter_map(|&p| matches[p]).collect();
        let unmatched_joliet: Vec<_> = jchildren
            .iter()
            .copied()
            .filter(|&j| joliet[j].record.is_dir && !used.contains(&j))
            .collect();
        if let ([p], [j]) = (unmatched_primary.as_slice(), unmatched_joliet.as_slice()) {
            matches[*p] = Some(*j);
        }
    }
    for (id, node) in primary.iter_mut().enumerate().skip(1) {
        if node.record.rr.name.is_none() {
            if let Some(j) = matches[id] {
                node.record.name.clone_from(&joliet[j].record.name);
            }
        }
    }
    matches
}
