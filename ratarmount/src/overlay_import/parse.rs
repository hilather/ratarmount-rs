//! Byte-oriented unified/Git patch parser. No external patch program is invoked.

use std::io;

#[derive(Debug, Default)]
pub(super) struct FilePatch {
    pub old: Option<String>,
    pub new: Option<String>,
    pub old_mode: Option<u32>,
    pub new_mode: Option<u32>,
    pub added: bool,
    pub deleted: bool,
    pub copy: bool,
    pub hunks: Vec<Hunk>,
    pub literal: Option<Vec<u8>>,
    /// Inflated forward `delta` section, structurally validated against its
    /// own declared sizes; applied to the preimage at import time.
    pub delta: Option<Vec<u8>>,
    /// The `index <old>..<new>` object ids (lowercase hex), when present.
    pub index: Option<(String, String)>,
    /// The raw `GIT binary patch` lines, for a `.rej` file.
    pub binary_raw: Vec<u8>,
    headers: bool,
}

impl FilePatch {
    pub fn path(&self) -> &str {
        self.new
            .as_deref()
            .or(self.old.as_deref())
            .unwrap_or("<unknown>")
    }
}

#[derive(Debug)]
pub(super) struct Hunk {
    pub old_start: usize,
    pub old_count: usize,
    pub new_count: usize,
    pub lines: Vec<(u8, Vec<u8>)>,
    pub raw: Vec<u8>,
}

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

fn trim_lf(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n").unwrap_or(line)
}

/// Decode Git's C quoting before validating or stripping any path component.
fn unquote(input: &[u8]) -> io::Result<(Vec<u8>, usize)> {
    if !input.starts_with(b"\"") {
        return Ok((input.to_vec(), input.len()));
    }
    let mut out = Vec::new();
    let mut pos = 1;
    while let Some(&byte) = input.get(pos) {
        pos += 1;
        match byte {
            b'"' => return Ok((out, pos)),
            b'\\' => {
                let escaped = *input
                    .get(pos)
                    .ok_or_else(|| invalid("unfinished path escape"))?;
                pos += 1;
                out.push(match escaped {
                    b'a' => 7,
                    b'b' => 8,
                    b't' => b'\t',
                    b'n' => b'\n',
                    b'v' => 11,
                    b'f' => 12,
                    b'r' => b'\r',
                    b'\\' | b'"' => escaped,
                    b'0'..=b'3' => {
                        let digits = input
                            .get(pos..pos + 2)
                            .filter(|s| s.iter().all(|b| matches!(b, b'0'..=b'7')))
                            .ok_or_else(|| invalid("invalid octal path escape"))?;
                        pos += 2;
                        (escaped - b'0') * 64 + (digits[0] - b'0') * 8 + digits[1] - b'0'
                    }
                    _ => return Err(invalid("invalid quoted path escape")),
                });
            }
            _ => out.push(byte),
        }
    }
    Err(invalid("unterminated quoted path"))
}

fn validate_bytes(path: &[u8]) -> io::Result<()> {
    if path.is_empty()
        || path.contains(&0)
        || path
            .split(|b| *b == b'/')
            .any(|part| part.is_empty() || part == b".." || part == b".")
    {
        return Err(invalid(format!(
            "unsafe patch path {:?}",
            String::from_utf8_lossy(path)
        )));
    }
    Ok(())
}

fn path(input: &[u8], strip: bool, timestamp: bool) -> io::Result<Option<String>> {
    let (mut bytes, used) = unquote(input)?;
    if input.starts_with(b"\"") {
        let suffix = &input[used..];
        if !suffix.is_empty() && !(timestamp && suffix.starts_with(b"\t")) {
            return Err(invalid("trailing text after quoted path"));
        }
    } else if timestamp {
        bytes.truncate(
            bytes
                .iter()
                .position(|b| *b == b'\t')
                .unwrap_or(bytes.len()),
        );
    }
    if bytes == b"/dev/null" && strip {
        return Ok(None);
    }
    validate_bytes(&bytes)?;
    if strip {
        let slash = bytes
            .iter()
            .position(|b| *b == b'/')
            .ok_or_else(|| invalid("patch path has no component to strip (-p1)"))?;
        bytes.drain(..=slash);
    }
    validate_bytes(&bytes)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| invalid("non-UTF-8 patch path is unsupported by overlay paths (EILSEQ)"))?;
    if ratarmount_compositing::is_overlay_internal_path(&format!("/{text}")) {
        return Err(invalid(format!("reserved overlay path: {text}")));
    }
    // A mount with `--control-interface` serves a virtual folder here (and
    // `sandbox run` always does): imported content would be invisible but
    // still hashed and sealed. Refused whatever the later mount flags are.
    if ratarmount_compositing::is_control_reserved_path(&format!("/{text}")) {
        return Err(invalid(format!(
            "reserved control folder path: {text} (/.ratarmount-control is served by --control-interface)"
        )));
    }
    Ok(Some(text))
}

fn git_paths(input: &[u8]) -> io::Result<(Option<String>, Option<String>)> {
    let split = if input.starts_with(b"\"") {
        unquote(input)?.1
    } else if input.len() % 2 == 1
        && input.get(input.len() / 2) == Some(&b' ')
        && input.starts_with(b"a/")
        && input[input.len() / 2 + 1..].starts_with(b"b/")
        && input[2..input.len() / 2] == input[input.len() / 2 + 3..]
    {
        // An unchanged name can itself contain " b/"; mode-only diffs have
        // no ---/+++ headers to disambiguate that case later.
        input.len() / 2
    } else {
        // Git leaves spaces unquoted. Prefer its canonical b/ separator.
        input
            .windows(3)
            .position(|s| s == b" b/")
            .or_else(|| input.windows(4).position(|s| s == b" \"b/"))
            .or_else(|| input.iter().position(|b| *b == b' '))
            .ok_or_else(|| invalid("missing second diff --git path"))?
    };
    if input.get(split) != Some(&b' ') {
        return Err(invalid("missing space between diff --git paths"));
    }
    let old = path(&input[..split], true, false)?;
    let new = path(&input[split + 1..], true, false)?;
    if old.is_none() || new.is_none() {
        return Err(invalid("diff --git paths must not be /dev/null"));
    }
    Ok((old, new))
}

fn number(input: &[u8]) -> io::Result<usize> {
    if input.is_empty() || !input.iter().all(u8::is_ascii_digit) {
        return Err(invalid("invalid patch count"));
    }
    std::str::from_utf8(input).unwrap().parse().map_err(invalid)
}

fn range(input: &[u8], sign: u8) -> io::Result<(usize, usize)> {
    let input = input
        .strip_prefix(&[sign])
        .ok_or_else(|| invalid("invalid hunk range"))?;
    let mut parts = input.split(|b| *b == b',');
    let start = number(parts.next().unwrap())?;
    let count = parts.next().map(number).transpose()?.unwrap_or(1);
    if parts.next().is_some() || (count > 0 && start == 0) || start.checked_add(count).is_none() {
        return Err(invalid("invalid hunk range"));
    }
    Ok((start, count))
}

fn hunk(lines: &[&[u8]], pos: &mut usize) -> io::Result<Hunk> {
    let header = trim_lf(lines[*pos]);
    let mut fields = header.split(|b| *b == b' ');
    if fields.next() != Some(b"@@") {
        return Err(invalid("invalid hunk header"));
    }
    let (old_start, old_count) = range(fields.next().unwrap_or_default(), b'-')?;
    let (_new_start, new_count) = range(fields.next().unwrap_or_default(), b'+')?;
    if fields.next() != Some(b"@@") {
        return Err(invalid("invalid hunk header"));
    }
    let mut hunk = Hunk {
        old_start,
        old_count,
        new_count,
        lines: Vec::new(),
        raw: lines[*pos].to_vec(),
    };
    *pos += 1;
    let (mut old, mut new) = (0, 0);
    while old < old_count || new < new_count {
        let line = *lines.get(*pos).ok_or_else(|| invalid("truncated hunk"))?;
        let tag = *line.first().ok_or_else(|| invalid("empty hunk line"))?;
        match tag {
            b' ' => {
                old += 1;
                new += 1;
            }
            b'-' => old += 1,
            b'+' => new += 1,
            _ => return Err(invalid("invalid hunk line or truncated hunk")),
        }
        if old > old_count || new > new_count || !line.ends_with(b"\n") {
            return Err(invalid("hunk line count or terminator mismatch"));
        }
        hunk.lines.push((tag, line[1..].to_vec()));
        hunk.raw.extend_from_slice(line);
        *pos += 1;
        if lines
            .get(*pos)
            .is_some_and(|l| trim_lf(l) == b"\\ No newline at end of file")
        {
            hunk.lines.last_mut().unwrap().1.pop();
            hunk.raw.extend_from_slice(lines[*pos]);
            *pos += 1;
        }
    }
    Ok(hunk)
}

fn mode(input: &[u8]) -> io::Result<u32> {
    let value = std::str::from_utf8(input).map_err(invalid)?;
    let value = u32::from_str_radix(value, 8).map_err(invalid)?;
    if !matches!(
        value & ratarmount_core::S_IFMT,
        ratarmount_core::S_IFREG | ratarmount_core::S_IFLNK
    ) || value & !0o177777 != 0
    {
        return Err(invalid(
            "unsupported patch mode (expected regular file or symlink)",
        ));
    }
    Ok(value)
}

fn decode85(line: &[u8]) -> io::Result<Vec<u8>> {
    const ALPHABET: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    let size = match line.first() {
        Some(b'A'..=b'Z') => (line[0] - b'A' + 1) as usize,
        Some(b'a'..=b'z') => (line[0] - b'a' + 27) as usize,
        _ => return Err(invalid("invalid Git base85 length")),
    };
    if line.len() != 1 + size.div_ceil(4) * 5 {
        return Err(invalid("invalid Git base85 line length"));
    }
    let mut bytes = Vec::new();
    for word in line[1..].as_chunks::<5>().0 {
        let mut value = 0u32;
        for b in word {
            let digit = ALPHABET
                .iter()
                .position(|c| c == b)
                .ok_or_else(|| invalid("invalid Git base85 digit"))? as u32;
            value = value
                .checked_mul(85)
                .and_then(|v| v.checked_add(digit))
                .ok_or_else(|| invalid("Git base85 word overflow"))?;
        }
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.truncate(size);
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Literal,
    Delta,
}

/// Read one `literal N` or `delta N` section: base85 lines up to a blank
/// line, zlib-inflated to exactly N bytes.
fn binary_section(
    lines: &[&[u8]],
    pos: &mut usize,
    max_bytes: u64,
) -> io::Result<(Section, Vec<u8>)> {
    let header = trim_lf(
        lines
            .get(*pos)
            .ok_or_else(|| invalid("missing binary literal"))?,
    );
    let (kind, name, size) = if let Some(size) = header.strip_prefix(b"literal ") {
        (Section::Literal, "binary literal", size)
    } else if let Some(size) = header.strip_prefix(b"delta ") {
        (Section::Delta, "delta", size)
    } else {
        return Err(invalid("missing binary literal"));
    };
    let size = number(size)?;
    if size as u64 > max_bytes {
        return Err(invalid(format!("{name} exceeds --max-patch-bytes")));
    }
    *pos += 1;
    let mut compressed = Vec::new();
    while let Some(line) = lines.get(*pos) {
        *pos += 1;
        let line = trim_lf(line);
        if line.is_empty() {
            break;
        }
        compressed.extend(decode85(line)?);
    }
    let capacity = size
        .checked_add(1)
        .ok_or_else(|| invalid(format!("{name} size overflow")))?;
    let mut data = Vec::new();
    data.try_reserve_exact(capacity).map_err(invalid)?;
    let mut decoder = flate2::Decompress::new(true);
    let status = decoder
        .decompress_vec(&compressed, &mut data, flate2::FlushDecompress::Finish)
        .map_err(invalid)?;
    if status != flate2::Status::StreamEnd
        || data.len() != size
        || decoder.total_in() != compressed.len() as u64
    {
        return Err(invalid(format!(
            "{name} size or compressed stream mismatch"
        )));
    }
    Ok((kind, data))
}

/// Git's delta header size: little-endian base-128, continuation bit 0x80.
fn varint(data: &[u8], pos: &mut usize) -> io::Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data
            .get(*pos)
            .ok_or_else(|| invalid("truncated delta size header"))?;
        *pos += 1;
        let bits = u64::from(byte & 0x7f);
        if shift >= 64 || (shift > 0 && bits >> (64 - shift) != 0) {
            return Err(invalid("delta size header overflows"));
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

/// Walk a Git delta (git's `patch_delta`). With `source`, its length must
/// equal the declared source size and the target is built; without it, only
/// the opcodes are checked against the declared sizes and nothing is
/// allocated. The declared target must be within `limit` before allocation.
pub(super) fn walk_delta(
    delta: &[u8],
    source: Option<&[u8]>,
    limit: u64,
) -> io::Result<(u64, u64, Option<Vec<u8>>)> {
    let mut pos = 0;
    let source_size = varint(delta, &mut pos)?;
    let target_size = varint(delta, &mut pos)?;
    if let Some(source) = source {
        if source.len() as u64 != source_size {
            return Err(invalid(format!(
                "delta source size {source_size} does not match the preimage size {}",
                source.len()
            )));
        }
    }
    if target_size > limit {
        return Err(invalid(format!(
            "delta target size {target_size} exceeds --max-patch-bytes"
        )));
    }
    let mut out = match source {
        Some(_) => {
            let mut out = Vec::new();
            out.try_reserve_exact(
                usize::try_from(target_size).map_err(|_| invalid("delta target size overflow"))?,
            )
            .map_err(invalid)?;
            Some(out)
        }
        None => None,
    };
    let mut remaining = target_size;
    while let Some(&cmd) = delta.get(pos) {
        pos += 1;
        let mut operand = |bit: u8, shift: u32| -> io::Result<u64> {
            if cmd & bit == 0 {
                return Ok(0);
            }
            let byte = *delta
                .get(pos)
                .ok_or_else(|| invalid("truncated delta copy operand"))?;
            pos += 1;
            Ok(u64::from(byte) << shift)
        };
        if cmd & 0x80 != 0 {
            let offset =
                operand(0x01, 0)? | operand(0x02, 8)? | operand(0x04, 16)? | operand(0x08, 24)?;
            let mut size = operand(0x10, 0)? | operand(0x20, 8)? | operand(0x40, 16)?;
            if size == 0 {
                size = 0x10000;
            }
            let end = offset
                .checked_add(size)
                .filter(|end| *end <= source_size)
                .ok_or_else(|| invalid("delta copy lies outside the source"))?;
            if size > remaining {
                return Err(invalid("delta output exceeds its target size"));
            }
            if let (Some(out), Some(source)) = (&mut out, source) {
                out.extend_from_slice(&source[offset as usize..end as usize]);
            }
            remaining -= size;
        } else if cmd != 0 {
            let insert = delta
                .get(pos..pos + usize::from(cmd))
                .ok_or_else(|| invalid("truncated delta insert"))?;
            if u64::from(cmd) > remaining {
                return Err(invalid("delta output exceeds its target size"));
            }
            if let Some(out) = &mut out {
                out.extend_from_slice(insert);
            }
            pos += usize::from(cmd);
            remaining -= u64::from(cmd);
        } else {
            return Err(invalid("reserved delta opcode 0"));
        }
    }
    if remaining != 0 {
        return Err(invalid("delta output is shorter than its target size"));
    }
    Ok((source_size, target_size, out))
}

/// Git blob object ids of `data`: SHA-1 and SHA-256 (lowercase hex).
pub(super) fn blob_ids(data: &[u8]) -> [String; 2] {
    use sha1::Digest as _;
    let header = format!("blob {}\0", data.len());
    let mut sha1 = sha1::Sha1::new();
    sha1.update(header.as_bytes());
    sha1.update(data);
    let mut sha256 = sha2::Sha256::new();
    sha256.update(header.as_bytes());
    sha256.update(data);
    [hex(&sha1.finalize()), hex(&sha256.finalize())]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Apply a forward delta to `preimage`, as `git apply` does: the preimage's
/// blob id must match the index line's old id, and the result's the new id.
/// An abbreviated id is a prefix of a full SHA-1 or SHA-256 id (both ids
/// under one object format); `git apply` itself requires full ids.
pub(super) fn apply_delta(
    preimage: &[u8],
    delta: &[u8],
    index: &(String, String),
    limit: u64,
) -> Result<Vec<u8>, String> {
    let (old, new) = index;
    let before = blob_ids(preimage);
    let formats: Vec<usize> = (0..2)
        .filter(|&i| before[i].starts_with(old.as_str()))
        .collect();
    if formats.is_empty() {
        return Err(format!(
            "delta preimage blob {} does not match index {old} (sha1 information is lacking or useless)",
            before[0]
        ));
    }
    let (_, _, out) = walk_delta(delta, Some(preimage), limit).map_err(|e| e.to_string())?;
    let out = out.expect("built with a source");
    let after = blob_ids(&out);
    if !formats.iter().any(|&i| after[i].starts_with(new.as_str())) {
        return Err(format!(
            "delta creates blob {} but index expects {new}",
            after[formats[0]]
        ));
    }
    Ok(out)
}

/// `index <old>..<new>[ <mode>]`: two hex object ids, lowercased.
fn index_line(value: &[u8]) -> Option<(String, String)> {
    let value = std::str::from_utf8(value).ok()?;
    let ids = value.split(' ').next()?;
    let (old, new) = ids.split_once("..")?;
    let id = |s: &str| {
        (!s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| s.to_ascii_lowercase())
    };
    Some((id(old)?, id(new)?))
}

fn finish(mut patch: FilePatch, patches: &mut Vec<FilePatch>) -> io::Result<()> {
    if patch.old.is_none() && patch.new.is_none() {
        return Err(invalid("patch has no file paths"));
    }
    if patch.added {
        patch.old = None;
    }
    if patch.deleted {
        patch.new = None;
    }
    if patch.old.is_none() && patch.new.is_none() {
        return Err(invalid("patch deletes and adds no path"));
    }
    if patch.delta.is_some() {
        let refuse = |why: &str| invalid(format!("{}: {why}", patch.path()));
        if patch.old.is_none() || patch.new.is_none() {
            return Err(refuse(
                "a delta binary section needs an existing preimage and a postimage",
            ));
        }
        if !patch.hunks.is_empty() {
            return Err(refuse(
                "a delta binary section cannot be combined with text hunks",
            ));
        }
        let Some((old, new)) = &patch.index else {
            return Err(refuse(
                "a delta binary section needs an index line with blob ids (sha1 information is lacking or useless)",
            ));
        };
        let zero = |id: &str| id.bytes().all(|b| b == b'0');
        if old.len() < 4 || new.len() < 4 || zero(old) || zero(new) {
            return Err(refuse(
                "a delta binary section needs non-zero index blob ids of at least 4 hex digits (sha1 information is lacking or useless)",
            ));
        }
    }
    patches.push(patch);
    Ok(())
}

pub(super) fn parse(input: &[u8], max_bytes: u64) -> io::Result<Vec<FilePatch>> {
    let lines: Vec<_> = input.split_inclusive(|b| *b == b'\n').collect();
    let mut patches = Vec::new();
    let mut literal_budget = max_bytes;
    let mut current: Option<FilePatch> = None;
    let mut pos = 0;
    while pos < lines.len() {
        let line = trim_lf(lines[pos]);
        if let Some(names) = line.strip_prefix(b"diff --git ") {
            if let Some(patch) = current.take() {
                finish(patch, &mut patches)?;
            }
            let (old, new) = git_paths(names)?;
            current = Some(FilePatch {
                old,
                new,
                ..Default::default()
            });
            pos += 1;
            continue;
        }
        if (line.starts_with(b"--- ")
            || line.starts_with(b"old mode ")
            || line.starts_with(b"new file mode ")
            || line.starts_with(b"deleted file mode "))
            && current.as_ref().is_some_and(|p| p.headers)
        {
            finish(current.take().unwrap(), &mut patches)?;
        }
        if current.is_none()
            && (line.starts_with(b"--- ")
                || line.starts_with(b"new file mode ")
                || line.starts_with(b"deleted file mode ")
                || line.starts_with(b"old mode "))
        {
            current = Some(FilePatch::default());
        }
        let Some(patch) = &mut current else {
            if line.starts_with(b"Binary files ") {
                return Err(invalid(format!(
                    "{}: binary patch has no content",
                    String::from_utf8_lossy(line)
                )));
            }
            if line.starts_with(b"@@")
                || line.starts_with(b"+++")
                || line.starts_with(b"GIT binary")
            {
                return Err(invalid("patch content without file headers"));
            }
            pos += 1; // Mail headers, diff -u command lines and commit prose.
            continue;
        };
        let result = (|| -> io::Result<()> {
            if let Some(name) = line.strip_prefix(b"--- ") {
                patch.old = path(name, true, true)?;
                pos += 1;
                let next = trim_lf(
                    lines
                        .get(pos)
                        .ok_or_else(|| invalid("missing +++ header"))?,
                );
                patch.new = path(
                    next.strip_prefix(b"+++ ")
                        .ok_or_else(|| invalid("missing +++ header"))?,
                    true,
                    true,
                )?;
                patch.added |= patch.old.is_none();
                patch.deleted |= patch.new.is_none();
                patch.headers = true;
            } else if let Some(value) = line.strip_prefix(b"new file mode ") {
                patch.new_mode = Some(mode(value)?);
                patch.added = true;
            } else if let Some(value) = line.strip_prefix(b"deleted file mode ") {
                patch.old_mode = Some(mode(value)?);
                patch.deleted = true;
            } else if let Some(value) = line.strip_prefix(b"old mode ") {
                patch.old_mode = Some(mode(value)?);
            } else if let Some(value) = line.strip_prefix(b"new mode ") {
                patch.new_mode = Some(mode(value)?);
            } else if let Some(value) = line
                .strip_prefix(b"rename from ")
                .or_else(|| line.strip_prefix(b"copy from "))
            {
                patch.old = path(value, false, false)?;
                patch.copy |= line.starts_with(b"copy ");
            } else if let Some(value) = line
                .strip_prefix(b"rename to ")
                .or_else(|| line.strip_prefix(b"copy to "))
            {
                patch.new = path(value, false, false)?;
                patch.copy |= line.starts_with(b"copy ");
            } else if line.starts_with(b"@@ ") {
                patch.hunks.push(hunk(&lines, &mut pos)?);
                return Ok(());
            } else if line == b"GIT binary patch" {
                if patch.literal.is_some() || patch.delta.is_some() {
                    return Err(invalid("repeated binary patch for one file"));
                }
                let start = pos;
                pos += 1;
                let (kind, data) = binary_section(&lines, &mut pos, literal_budget)?;
                literal_budget -= data.len() as u64;
                match kind {
                    Section::Literal => patch.literal = Some(data),
                    Section::Delta => {
                        // Structure and declared sizes need no preimage.
                        walk_delta(&data, None, max_bytes)?;
                        patch.delta = Some(data);
                    }
                }
                if lines
                    .get(pos)
                    .is_some_and(|l| l.starts_with(b"literal ") || l.starts_with(b"delta "))
                {
                    // Validate reverse; only apply forward.
                    let (kind, data) = binary_section(&lines, &mut pos, max_bytes)?;
                    if kind == Section::Delta {
                        walk_delta(&data, None, max_bytes)?;
                    }
                }
                patch.binary_raw = lines[start..pos].concat();
                return Ok(());
            } else if let Some(value) = line.strip_prefix(b"index ") {
                // Only the extended header's line, before any content.
                if patch.hunks.is_empty() && patch.literal.is_none() && patch.delta.is_none() {
                    patch.index = index_line(value);
                }
            } else if line.starts_with(b"Binary files ") {
                return Err(invalid("binary patch has no content"));
            } else if line.starts_with(b"delta ")
                || line.starts_with(b"literal ")
                || line.starts_with(b"@@")
                || line.starts_with(b"\\ No newline")
                || line.starts_with(b"+++")
                || line.starts_with(b"+")
                || line.starts_with(b"-") && line != b"-- "
                || line.starts_with(b" ")
            {
                return Err(invalid("unexpected patch content"));
            }
            pos += 1;
            Ok(())
        })();
        result.map_err(|e| invalid(format!("{}: {e}", patch.path())))?;
    }
    if let Some(patch) = current {
        finish(patch, &mut patches)?;
    }
    if patches.is_empty() && input.iter().any(|b| !b.is_ascii_whitespace()) {
        return Err(invalid("input contains no supported file patches"));
    }
    Ok(patches)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// Regression: base85 padding, invalid digits, length and integer overflow.
    #[test]
    fn regression_import_base85_invalid_and_padding() {
        assert_eq!(decode85(b"A00000").unwrap(), [0]);
        assert_eq!(decode85(b"D00000").unwrap(), [0, 0, 0, 0]);
        for line in [
            b"000000".as_slice(),
            b"A0000",
            b"A000000",
            b"A.....",
            b"D~~~~~",
        ] {
            assert!(decode85(line).is_err(), "{line:?}");
        }
    }

    /// Git base85 lines (one per 52 bytes) followed by the blank terminator.
    pub(crate) fn encode85(data: &[u8]) -> Vec<u8> {
        const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
        let mut out = Vec::new();
        for chunk in data.chunks(52) {
            let n = chunk.len() as u8;
            out.push(if n <= 26 { b'A' + n - 1 } else { b'a' + n - 27 });
            for word in chunk.chunks(4) {
                let mut bytes = [0; 4];
                bytes[..word.len()].copy_from_slice(word);
                let mut value = u32::from_be_bytes(bytes);
                let mut digits = [0; 5];
                for digit in digits.iter_mut().rev() {
                    *digit = ALPHABET[(value % 85) as usize];
                    value /= 85;
                }
                out.extend_from_slice(&digits);
            }
            out.push(b'\n');
        }
        out.push(b'\n');
        out
    }

    pub(crate) fn zlib(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn binary_patch(compressed: &[u8], size: usize) -> Vec<u8> {
        let mut patch = format!(
            "diff --git a/bin b/bin\nnew file mode 100644\nGIT binary patch\nliteral {size}\n"
        )
        .into_bytes();
        patch.extend(encode85(compressed));
        patch
    }

    /// Regression: a complete payload with a truncated checksum is not a valid zlib literal.
    #[test]
    fn regression_import_truncated_zlib_and_literal_budget() {
        use std::io::Write;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[0; 128]).unwrap();
        let compressed = encoder.finish().unwrap();
        let valid = binary_patch(&compressed, 128);
        assert_eq!(
            parse(&valid, 128).unwrap()[0]
                .literal
                .as_ref()
                .unwrap()
                .len(),
            128
        );
        assert!(parse(&binary_patch(&compressed[..compressed.len() - 1], 128), 128).is_err());
        assert!(parse(&binary_patch(&compressed, 127), 128).is_err());
        let mut two = valid.clone();
        two.extend_from_slice(&valid);
        assert!(parse(&two, 128).is_err());
        let mut delta = valid;
        delta.extend_from_slice(b"delta 0\n\n");
        let error = parse(&delta, 128).unwrap_err().to_string();
        assert!(error.contains("bin: delta"), "{error}");
    }

    pub(crate) fn varint_bytes(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    /// A minimal git delta from `pre` to `post`: copy the common prefix,
    /// insert the changed middle, copy the common suffix.
    pub(crate) fn make_delta(pre: &[u8], post: &[u8]) -> Vec<u8> {
        fn copy(out: &mut Vec<u8>, offset: usize, size: usize) {
            for (start, len) in (0..size)
                .step_by(0xff_ffff)
                .map(|s| (s, (size - s).min(0xff_ffff)))
            {
                let (offset, len) = ((offset + start) as u32, len as u32);
                let mut cmd = 0x80u8;
                let mut operands = Vec::new();
                for i in 0..4 {
                    let byte = (offset >> (8 * i)) as u8;
                    if byte != 0 {
                        cmd |= 1 << i;
                        operands.push(byte);
                    }
                }
                for i in 0..3 {
                    let byte = (len >> (8 * i)) as u8;
                    if byte != 0 {
                        cmd |= 0x10 << i;
                        operands.push(byte);
                    }
                }
                out.push(cmd);
                out.extend(operands);
            }
        }
        let prefix = pre.iter().zip(post).take_while(|(a, b)| a == b).count();
        let suffix = pre[prefix..]
            .iter()
            .rev()
            .zip(post[prefix..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        let mut ops = Vec::new();
        copy(&mut ops, 0, prefix);
        for chunk in post[prefix..post.len() - suffix].chunks(127) {
            ops.push(chunk.len() as u8);
            ops.extend(chunk);
        }
        copy(&mut ops, pre.len() - suffix, suffix);
        delta(pre.len() as u64, post.len() as u64, &ops)
    }

    fn delta(source: u64, target: u64, ops: &[u8]) -> Vec<u8> {
        [varint_bytes(source), varint_bytes(target), ops.to_vec()].concat()
    }

    fn source() -> Vec<u8> {
        (0..0x10000 + 64u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect()
    }

    fn apply(source: &[u8], delta: &[u8]) -> io::Result<Vec<u8>> {
        walk_delta(delta, Some(source), u64::MAX).map(|(_, _, out)| out.unwrap())
    }

    /// Regression: every copy opcode encoding (each offset/size byte selected,
    /// including selected zero bytes; size 0 means 0x10000) applies like git (#343).
    #[test]
    fn regression_delta_copy_every_operand_combination() {
        let src = source();
        for cmd in 0x80u8..=0xff {
            // Nonzero low byte when selected; higher selected bytes are zero.
            let mut ops = vec![cmd];
            let mut offset = 0usize;
            for bit in 0..4 {
                if cmd & (1 << bit) != 0 {
                    let byte = if bit == 0 { 7 } else { 0 };
                    offset |= (byte as usize) << (8 * bit);
                    ops.push(byte);
                }
            }
            let mut size = 0usize;
            for bit in 0..3 {
                if cmd & (0x10 << bit) != 0 {
                    let byte = if bit == 0 { 9 } else { 0 };
                    size |= (byte as usize) << (8 * bit);
                    ops.push(byte);
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let d = delta(src.len() as u64, size as u64, &ops);
            assert_eq!(
                apply(&src, &d).unwrap(),
                &src[offset..offset + size],
                "{cmd:#x}"
            );
        }
        // Multi-byte operands: offset 0x0102, size 0x0304, and 3-byte sizes.
        let d = delta(src.len() as u64, 0x0304, &[0xb3, 0x02, 0x01, 0x04, 0x03]);
        assert_eq!(apply(&src, &d).unwrap(), &src[0x0102..0x0102 + 0x0304]);
        let d = delta(src.len() as u64, 0x01_0041, &[0xf0, 0x41, 0x00, 0x01]);
        assert!(apply(&src, &d).is_err(), "0x10041 exceeds the source");
        let d = delta(src.len() as u64, 0x01_0010, &[0xf0, 0x10, 0x00, 0x01]);
        assert_eq!(apply(&src, &d).unwrap(), &src[..0x01_0010]);
        // 4-byte offsets are read in full.
        let d = delta(src.len() as u64, 1, &[0x9f, 0, 0, 0, 1, 1]);
        assert!(apply(&src, &d).unwrap_err().to_string().contains("outside"));
    }

    /// Regression: inserts of 1 and 127 bytes, mixed with copies (#343).
    #[test]
    fn regression_delta_inserts_and_mixed_ops() {
        let src = b"0123456789".to_vec();
        let long: Vec<u8> = (0..127).collect();
        let mut ops = vec![1, b'x', 127];
        ops.extend(&long);
        ops.extend([0x91, 2, 3]);
        let d = delta(10, 1 + 127 + 3, &ops);
        let mut expected = b"x".to_vec();
        expected.extend(&long);
        expected.extend(b"234");
        assert_eq!(apply(&src, &d).unwrap(), expected);
        // Without a source only the declared sizes are checked.
        let (s, t, out) = walk_delta(&d, None, u64::MAX).unwrap();
        assert_eq!((s, t, out), (10, 131, None));
        assert_eq!(apply(b"", &delta(0, 0, &[])).unwrap(), b"");
    }

    /// Regression: malformed deltas are refused, never panic or over-allocate (#343).
    #[test]
    fn regression_delta_malformed_vectors() {
        let src = b"0123456789".to_vec();
        let cases: &[(&str, Vec<u8>, &str)] = &[
            ("opcode 0", delta(10, 1, &[0]), "reserved delta opcode 0"),
            ("empty", Vec::new(), "truncated delta size"),
            (
                "truncated source varint",
                vec![0x8a],
                "truncated delta size",
            ),
            (
                "truncated target varint",
                vec![10, 0x81],
                "truncated delta size",
            ),
            (
                "overflowing varint",
                [vec![0xff; 9], vec![0x7f]].concat(),
                "overflows",
            ),
            ("copy out of range", delta(10, 5, &[0x91, 8, 5]), "outside"),
            (
                "offset+size overflow",
                delta(
                    10,
                    0xff_ffff,
                    &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                ),
                "outside",
            ),
            (
                "truncated copy operand",
                delta(10, 1, &[0x91, 1]),
                "truncated delta copy",
            ),
            (
                "truncated insert",
                delta(10, 3, &[3, b'a']),
                "truncated delta insert",
            ),
            (
                "trailing bytes",
                delta(10, 1, &[1, b'a', 1, b'b']),
                "exceeds its target",
            ),
            (
                "trailing copy",
                delta(10, 1, &[1, b'a', 0x91, 0, 1]),
                "exceeds its target",
            ),
            (
                "short output",
                delta(10, 4, &[1, b'a']),
                "shorter than its target",
            ),
            (
                "copy beyond target",
                delta(10, 2, &[0x91, 0, 3]),
                "exceeds its target",
            ),
        ];
        for (name, d, message) in cases {
            let error = apply(&src, d).unwrap_err().to_string();
            assert!(error.contains(message), "{name}: {error}");
            // Structural checks do not need the source.
            assert!(walk_delta(d, None, u64::MAX).is_err(), "{name}");
        }
        let error = apply(&src, &delta(9, 0, &[])).unwrap_err().to_string();
        assert!(
            error.contains("does not match the preimage size 10"),
            "{error}"
        );
        // A huge declared target is refused before any allocation.
        let huge = delta(10, u64::MAX >> 1, &[0x91, 0, 1]);
        let error = walk_delta(&huge, Some(&src), 1 << 20)
            .unwrap_err()
            .to_string();
        assert!(error.contains("exceeds --max-patch-bytes"), "{error}");
        assert!(walk_delta(&huge, None, 1 << 20).is_err());
    }

    /// Regression: base85 line lengths at the 1/4/5/26/27/52-byte edges round-trip;
    /// a length character that disagrees with the line is refused (#343).
    #[test]
    fn regression_import_base85_line_length_edges() {
        for len in [1usize, 3, 4, 5, 26, 27, 51, 52] {
            let data: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37) ^ 0xa5).collect();
            let encoded = encode85(&data);
            let line = trim_lf(encoded.split_inclusive(|b| *b == b'\n').next().unwrap());
            assert_eq!(decode85(line).unwrap(), data, "{len}");
            // A length character one five-digit group off is refused.
            let mut wrong = line.to_vec();
            let other = if len + 4 <= 52 { len + 4 } else { len - 4 } as u8;
            wrong[0] = if other <= 26 {
                b'A' + other - 1
            } else {
                b'a' + other - 27
            };
            assert!(decode85(&wrong).is_err(), "{len}");
        }
        assert!(decode85(b"{00000").is_err());
        let two = encode85(&[7; 53]);
        assert_eq!(two.split(|b| *b == b'\n').next().unwrap()[0], b'z');
    }

    fn delta_patch(index: Option<&str>, d: &[u8]) -> Vec<u8> {
        let mut patch = b"diff --git a/bin b/bin\n".to_vec();
        if let Some(index) = index {
            patch.extend(format!("index {index} 100644\n").as_bytes());
        }
        patch.extend(format!("GIT binary patch\ndelta {}\n", d.len()).as_bytes());
        patch.extend(encode85(&zlib(d)));
        patch
    }

    /// Regression: blob ids are checked like `git apply` (full SHA-1 or SHA-256,
    /// or a prefix of either); a missing or zero index line refuses the delta (#343).
    #[test]
    fn regression_delta_index_blob_ids() {
        let pre = b"\x00preimage bytes".to_vec();
        let d = delta(pre.len() as u64, 4, &[0x91, 1, 3, 1, b'!']);
        let post = apply(&pre, &d).unwrap();
        assert_eq!(post, b"pre!");
        let [old1, old256] = blob_ids(&pre);
        let [new1, new256] = blob_ids(&post);
        // `git hash-object` (SHA-1 and SHA-256 object formats) of an empty blob.
        assert_eq!(
            blob_ids(b""),
            [
                "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
                "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"
            ]
        );
        for (old, new) in [
            (old1.clone(), new1.clone()),
            (old1[..7].to_string(), new1[..7].to_string()),
            (old256.clone(), new256.clone()),
            (old256[..50].to_string(), new256[..50].to_string()),
            (old1.to_uppercase(), new1.to_uppercase()),
        ] {
            let patch = delta_patch(Some(&format!("{old}..{new}")), &d);
            let parsed = parse(&patch, 1 << 20).unwrap();
            let p = &parsed[0];
            assert_eq!(
                apply_delta(
                    &pre,
                    p.delta.as_ref().unwrap(),
                    p.index.as_ref().unwrap(),
                    1 << 20
                )
                .unwrap(),
                post
            );
        }
        let check = |index: (String, String), pre: &[u8]| apply_delta(pre, &d, &index, 1 << 20);
        let error = check((old1.clone(), new1.clone()), b"\x00preimage bytez").unwrap_err();
        assert!(
            error.contains("sha1 information is lacking or useless"),
            "{error}"
        );
        let error = check((old1.clone(), old1.clone()), &pre).unwrap_err();
        assert!(error.contains("index expects"), "{error}");
        // Mixed object formats do not verify.
        assert!(check((old1.clone(), new256[..40].to_string()), &pre).is_err());
        for index in [
            None,
            Some(format!("0000000..{}", &new1[..7])),
            Some(format!("{}..{}", "0".repeat(40), new1)),
            Some(format!("{}..{}", &old1[..3], &new1[..7])),
            Some(format!("{old1}..xyz")),
        ] {
            let error = parse(&delta_patch(index.as_deref(), &d), 1 << 20)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("bin: a delta binary section needs"),
                "{index:?}: {error}"
            );
        }
        // A delta needs a preimage and a postimage.
        for header in ["new file mode 100644\n", "deleted file mode 100644\n"] {
            let mut patch = b"diff --git a/bin b/bin\n".to_vec();
            patch.extend(header.as_bytes());
            patch.extend(format!("index {old1}..{new1}\n").as_bytes());
            patch.extend(&delta_patch(None, &d)[b"diff --git a/bin b/bin\n".len()..]);
            let error = parse(&patch, 1 << 20).unwrap_err().to_string();
            assert!(error.contains("existing preimage"), "{error}");
        }
    }

    /// Regression: a delta's declared target over --max-patch-bytes is refused at
    /// parse time, before any target allocation; the delta stream is charged to
    /// the decoded-literal budget, and a reverse delta is validated (#343).
    #[test]
    fn regression_delta_budget_and_reverse_section() {
        let d = delta(4, 1 << 40, &[0x80 | 0x40, 1]);
        let patch = delta_patch(Some("abcd..ef01"), &d);
        let error = parse(&patch, 1 << 20).unwrap_err().to_string();
        assert!(error.contains("exceeds --max-patch-bytes"), "{error}");
        let small = delta(4, 2, &[0x90, 2]);
        let patch = delta_patch(Some("abcd..ef01"), &small);
        parse(&patch, 1 << 20).unwrap();
        // The retained delta itself counts toward the budget.
        assert!(parse(&patch, small.len() as u64 - 1).is_err());
        let mut two = patch.clone();
        two.extend(&delta_patch(Some("abcd..ef01"), &small)["diff --git a/bin b/bin\n".len()..]);
        assert!(parse(&two, 1 << 20)
            .unwrap_err()
            .to_string()
            .contains("repeated"));
        // Reverse section: a valid delta passes, a malformed one is refused.
        let mut ok = patch.clone();
        ok.extend(format!("delta {}\n", small.len()).as_bytes());
        ok.extend(encode85(&zlib(&small)));
        assert!(parse(&ok, 1 << 20).unwrap()[0].delta.is_some());
        let bad = delta(4, 2, &[0]);
        let mut ko = patch;
        ko.extend(format!("delta {}\n", bad.len()).as_bytes());
        ko.extend(encode85(&zlib(&bad)));
        let error = parse(&ko, 1 << 20).unwrap_err().to_string();
        assert!(error.contains("bin: reserved delta opcode 0"), "{error}");
    }
}
