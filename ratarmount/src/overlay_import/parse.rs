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

fn literal(lines: &[&[u8]], pos: &mut usize, max_bytes: u64) -> io::Result<Vec<u8>> {
    let header = trim_lf(
        lines
            .get(*pos)
            .ok_or_else(|| invalid("missing binary literal"))?,
    );
    if header.starts_with(b"delta ") {
        return Err(invalid(
            "delta binary sections are unsupported; supply literal sections",
        ));
    }
    let size = number(
        header
            .strip_prefix(b"literal ")
            .ok_or_else(|| invalid("missing binary literal"))?,
    )?;
    if size as u64 > max_bytes {
        return Err(invalid("binary literal exceeds --max-patch-bytes"));
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
        .ok_or_else(|| invalid("binary literal size overflow"))?;
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
        return Err(invalid("binary literal size or compressed stream mismatch"));
    }
    Ok(data)
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
                pos += 1;
                let data = literal(&lines, &mut pos, literal_budget)?;
                literal_budget -= data.len() as u64;
                patch.literal = Some(data);
                if lines
                    .get(pos)
                    .is_some_and(|l| l.starts_with(b"literal ") || l.starts_with(b"delta "))
                {
                    literal(&lines, &mut pos, max_bytes)?; // Validate reverse; only apply forward.
                }
                return Ok(());
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
mod tests {
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

    fn binary_patch(compressed: &[u8], size: usize) -> Vec<u8> {
        const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
        let mut patch = format!(
            "diff --git a/bin b/bin\nnew file mode 100644\nGIT binary patch\nliteral {size}\n"
        )
        .into_bytes();
        for chunk in compressed.chunks(52) {
            let n = chunk.len() as u8;
            patch.push(if n <= 26 { b'A' + n - 1 } else { b'a' + n - 27 });
            for word in chunk.chunks(4) {
                let mut bytes = [0; 4];
                bytes[..word.len()].copy_from_slice(word);
                let mut value = u32::from_be_bytes(bytes);
                let mut digits = [0; 5];
                for digit in digits.iter_mut().rev() {
                    *digit = ALPHABET[(value % 85) as usize];
                    value /= 85;
                }
                patch.extend_from_slice(&digits);
            }
            patch.push(b'\n');
        }
        patch.push(b'\n');
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
}
