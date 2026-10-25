//! Unified byte hunks and streaming Git literal binary patches (zlib + Git base85).

use std::io::{self, Read, Seek, Write};

use flate2::{write::ZlibEncoder, Compression};
use ratarmount_compositing::overlay_changes::{binary, Entry};
use ratarmount_core::{S_IFDIR, S_IFMT};
use sha1::{Digest, Sha1};

use super::{Change, DiffArgs};

const BASE85: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

pub(super) fn quote(path: &str) -> String {
    quote_bytes(path.as_bytes())
}

pub(super) fn quote_bytes(path: &[u8]) -> String {
    if path
        .iter()
        .all(|b| b.is_ascii_graphic() && *b != b'"' && *b != b'\\')
    {
        return String::from_utf8(path.to_vec()).expect("ASCII path");
    }
    use std::fmt::Write as _;
    let mut out = String::from("\"");
    for &b in path {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            b' '..=b'~' => out.push(b as char),
            _ => {
                let _ = write!(out, "\\{b:03o}");
            }
        }
    }
    out.push('"');
    out
}

fn bytes(entry: &Option<Entry>) -> io::Result<Vec<u8>> {
    entry
        .as_ref()
        .map_or_else(|| Ok(Vec::new()), Entry::read_bytes)
}

fn blob_id(entry: &Option<Entry>) -> io::Result<String> {
    let Some(entry) = entry else {
        return Ok("0".repeat(40));
    };
    let mut hash = Sha1::new();
    hash.update(format!("blob {}\0", entry.size).as_bytes());
    let mut reader = entry.open()?.take(entry.size.saturating_add(1));
    let mut block = [0; 64 * 1024];
    loop {
        let n = reader.read(&mut block)?;
        if n == 0 {
            break;
        }
        hash.update(&block[..n]);
    }
    if reader.limit() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "content changed during Git blob hashing",
        ));
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn literal(out: &mut dyn Write, entry: &Option<Entry>) -> io::Result<()> {
    // Spool compressed data, never the uncompressed payload. This keeps a
    // size-fallback literal bounded even for a multi-gigabyte file.
    #[cfg_attr(
        internal_read_inventory,
        expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0105-M01","item":"ratarmount::diff::patch::literal","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
        )
    )]
    let mut zlib = ZlibEncoder::new(tempfile::tempfile()?, Compression::default());
    let size = entry.as_ref().map_or(0, |e| e.size);
    if let Some(entry) = entry {
        let copied = io::copy(&mut entry.open()?.take(size.saturating_add(1)), &mut zlib)?;
        if copied != size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "content changed during binary patch",
            ));
        }
    }
    let mut compressed = zlib.finish()?;
    compressed.rewind()?;
    writeln!(out, "literal {size}")?;
    let mut block = [0; 52];
    loop {
        let mut n = 0;
        while n < block.len() {
            let read = compressed.read(&mut block[n..])?;
            if read == 0 {
                break;
            }
            n += read;
        }
        if n == 0 {
            break;
        }
        out.write_all(&[if n <= 26 {
            b'A' + n as u8 - 1
        } else {
            b'a' + n as u8 - 27
        }])?;
        for word in block[..n].chunks(4) {
            let mut padded = [0; 4];
            padded[..word.len()].copy_from_slice(word);
            let mut value = u32::from_be_bytes(padded);
            let mut encoded = [0; 5];
            for digit in encoded.iter_mut().rev() {
                *digit = BASE85[(value % 85) as usize];
                value /= 85;
            }
            out.write_all(&encoded)?;
        }
        out.write_all(b"\n")?;
    }
    out.write_all(b"\n")
}

fn is_binary(entry: &Option<Entry>, max_text: u64) -> io::Result<bool> {
    let Some(entry) = entry else {
        return Ok(false);
    };
    if entry.size > max_text {
        return Ok(true);
    }
    let mut prefix = Vec::new();
    entry.open()?.take(8192).read_to_end(&mut prefix)?;
    Ok(binary(&prefix))
}

#[derive(Clone, Copy, Debug)]
struct Line<'a> {
    tag: char,
    text: &'a [u8],
}

fn lines<'a>(old: &'a [u8], new: &'a [u8]) -> Vec<Line<'a>> {
    let a: Vec<_> = old
        .split_inclusive(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    let b: Vec<_> = new
        .split_inclusive(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    let prefix = a.iter().zip(&b).take_while(|(a, b)| a == b).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let mut result: Vec<_> = a[..prefix]
        .iter()
        .map(|text| Line { tag: ' ', text })
        .collect();
    result.extend(myers(
        &a[prefix..a.len() - suffix],
        &b[prefix..b.len() - suffix],
    ));
    result.extend(
        a[a.len() - suffix..]
            .iter()
            .map(|text| Line { tag: ' ', text }),
    );
    result
}

fn myers<'a>(a: &[&'a [u8]], b: &[&'a [u8]]) -> Vec<Line<'a>> {
    let fallback = || {
        a.iter()
            .map(|text| Line { tag: '-', text })
            .chain(b.iter().map(|text| Line { tag: '+', text }))
            .collect()
    };
    if a.is_empty() || b.is_empty() {
        return fallback();
    }
    let max = a.len() + b.len();
    let width = 2 * max + 3;
    let offset = max + 1;
    let mut v = vec![0usize; width];
    let mut trace = Vec::new();
    for d in 0..=max {
        // Bound traceback storage on unrelated large files. A full replacement
        // still yields an exact, applicable patch, though not a minimal one.
        if width.saturating_mul(d + 1) > 4_000_000 {
            return fallback();
        }
        trace.push(v.clone());
        for k in (-(d as isize)..=d as isize).step_by(2) {
            let i = (offset as isize + k) as usize;
            let mut x = if k == -(d as isize) || (k != d as isize && v[i - 1] < v[i + 1]) {
                v[i + 1]
            } else {
                v[i - 1] + 1
            };
            let mut y = (x as isize - k) as usize;
            while x < a.len() && y < b.len() && a[x] == b[y] {
                x += 1;
                y += 1;
            }
            v[i] = x;
            if x >= a.len() && y >= b.len() {
                let (mut x, mut y) = (a.len(), b.len());
                let mut out = Vec::new();
                for depth in (0..=d).rev() {
                    let k = x as isize - y as isize;
                    let i = (offset as isize + k) as usize;
                    let previous = &trace[depth];
                    let prev_k = if k == -(depth as isize)
                        || (k != depth as isize && previous[i - 1] < previous[i + 1])
                    {
                        k + 1
                    } else {
                        k - 1
                    };
                    let prev_x = previous[(offset as isize + prev_k) as usize];
                    let prev_y = (prev_x as isize - prev_k) as usize;
                    while x > prev_x && y > prev_y {
                        x -= 1;
                        y -= 1;
                        out.push(Line {
                            tag: ' ',
                            text: a[x],
                        });
                    }
                    if depth == 0 {
                        break;
                    }
                    if x == prev_x {
                        y -= 1;
                        out.push(Line {
                            tag: '+',
                            text: b[y],
                        });
                    } else {
                        x -= 1;
                        out.push(Line {
                            tag: '-',
                            text: a[x],
                        });
                    }
                }
                out.reverse();
                return out;
            }
        }
    }
    unreachable!("edit distance is bounded by the two line counts")
}

fn range(before: usize, count: usize) -> String {
    let start = before + usize::from(count != 0);
    if count == 1 {
        start.to_string()
    } else {
        format!("{start},{count}")
    }
}

fn hunks(out: &mut dyn Write, lines: &[Line<'_>], context: usize) -> io::Result<()> {
    let changed: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| (line.tag != ' ').then_some(i))
        .collect();
    let mut groups: Vec<(usize, usize)> = Vec::new();
    for i in changed {
        let start = i.saturating_sub(context);
        let end = i.saturating_add(context).saturating_add(1).min(lines.len());
        if let Some(last) = groups.last_mut().filter(|last| start <= last.1) {
            last.1 = end;
        } else {
            groups.push((start, end));
        }
    }
    let (mut old_before, mut new_before, mut previous) = (0, 0, 0);
    for (start, end) in groups {
        for line in &lines[previous..start] {
            old_before += usize::from(line.tag != '+');
            new_before += usize::from(line.tag != '-');
        }
        let old_count = lines[start..end].iter().filter(|l| l.tag != '+').count();
        let new_count = lines[start..end].iter().filter(|l| l.tag != '-').count();
        writeln!(
            out,
            "@@ -{} +{} @@",
            range(old_before, old_count),
            range(new_before, new_count)
        )?;
        for line in &lines[start..end] {
            out.write_all(&[line.tag as u8])?;
            out.write_all(line.text)?;
            if !line.text.ends_with(b"\n") {
                out.write_all(b"\n\\ No newline at end of file\n")?;
            }
        }
        old_before += old_count;
        new_before += new_count;
        previous = end;
    }
    Ok(())
}

fn file_patch(out: &mut dyn Write, change: &Change, args: &DiffArgs) -> io::Result<()> {
    let Change { from, to, old, new } = change;
    if old
        .as_ref()
        .zip(new.as_ref())
        .is_some_and(|(a, b)| a.mode & S_IFMT != b.mode & S_IFMT)
    {
        file_patch(
            out,
            &Change {
                from: from.clone(),
                to: from.clone(),
                old: old.clone(),
                new: None,
            },
            args,
        )?;
        return file_patch(
            out,
            &Change {
                from: to.clone(),
                to: to.clone(),
                old: None,
                new: new.clone(),
            },
            args,
        );
    }
    if old
        .as_ref()
        .or(new.as_ref())
        .is_some_and(|e| e.mode & S_IFMT == S_IFDIR)
    {
        return Ok(());
    }
    let a = quote(&format!("a/{from}"));
    let b = quote(&format!("b/{to}"));
    let mode = |entry: &Entry| {
        if args.git {
            entry.git_mode()
        } else {
            entry.mode
        }
    };
    let content_changed =
        old.as_ref().and_then(|e| e.hash.as_ref()) != new.as_ref().and_then(|e| e.hash.as_ref());
    let mode_changed = old
        .as_ref()
        .zip(new.as_ref())
        .is_some_and(|(a, b)| mode(a) != mode(b));
    if !content_changed && (!mode_changed || args.ignore_mode) && from == to {
        return Ok(());
    }
    if args.git {
        writeln!(out, "diff --git {a} {b}")?;
    }
    match (old, new) {
        (None, Some(new)) => writeln!(out, "new file mode {:06o}", mode(new))?,
        (Some(old), None) => writeln!(out, "deleted file mode {:06o}", mode(old))?,
        (Some(old), Some(new)) if mode_changed && !args.ignore_mode => writeln!(
            out,
            "old mode {:06o}\nnew mode {:06o}",
            mode(old),
            mode(new)
        )?,
        _ => {}
    }
    if from != to {
        writeln!(
            out,
            "similarity index 100%\nrename from {}\nrename to {}",
            quote(from),
            quote(to)
        )?;
    }
    if args.git && (content_changed || old.is_none() || new.is_none()) {
        let common_mode = old
            .as_ref()
            .zip(new.as_ref())
            .filter(|(a, b)| a.git_mode() == b.git_mode())
            .map(|(e, _)| format!(" {:06o}", e.git_mode()))
            .unwrap_or_default();
        writeln!(
            out,
            "index {}..{}{common_mode}",
            blob_id(old)?,
            blob_id(new)?
        )?;
    }
    if !content_changed && old.is_some() && new.is_some() {
        if !args.git {
            writeln!(out, "--- {a}\n+++ {b}")?;
        }
        return Ok(());
    }
    if is_binary(old, args.max_diff_bytes)? || is_binary(new, args.max_diff_bytes)? {
        if args.git {
            out.write_all(b"GIT binary patch\n")?;
            literal(out, new)?;
            literal(out, old)?;
        } else {
            writeln!(out, "Binary files {a} and {b} differ")?;
        }
    } else {
        let before = bytes(old)?;
        let after = bytes(new)?;
        if before != after || !args.git {
            writeln!(
                out,
                "--- {}\n+++ {}",
                if old.is_none() { "/dev/null" } else { &a },
                if new.is_none() { "/dev/null" } else { &b }
            )?;
            hunks(out, &lines(&before, &after), args.context)?;
        }
    }
    Ok(())
}

pub(super) fn render(changes: &[Change], args: &DiffArgs, out: &mut dyn Write) -> io::Result<()> {
    let (mut inserted, mut removed, mut written) = (0, 0, 0u64);
    let mut stats = Vec::new();
    for change in changes {
        if args.name_status {
            if change.from != change.to {
                writeln!(out, "R100\t{}\t{}", quote(&change.from), quote(&change.to))?;
            } else {
                writeln!(out, "{}\t{}", change.status(), quote(&change.to))?;
            }
        } else if args.stat {
            let path = if change.from == change.to {
                quote(&change.to)
            } else {
                format!("{} => {}", quote(&change.from), quote(&change.to))
            };
            let before_size = change.old.as_ref().map_or(0, |e| e.size);
            let after_size = change.new.as_ref().map_or(0, |e| e.size);
            written += after_size;
            let binary = is_binary(&change.old, args.max_diff_bytes)?
                || is_binary(&change.new, args.max_diff_bytes)?;
            let (adds, dels) = if binary {
                (0, 0)
            } else {
                let before = bytes(&change.old)?;
                let after = bytes(&change.new)?;
                let edits = lines(&before, &after);
                (
                    edits.iter().filter(|l| l.tag == '+').count(),
                    edits.iter().filter(|l| l.tag == '-').count(),
                )
            };
            inserted += adds;
            removed += dels;
            if args.json {
                stats.push(serde_json::json!({"path":change.to,"insertions":adds,"deletions":dels,"binary":binary,"bytes_written":after_size}));
            } else if binary {
                writeln!(out, " {path} | Bin {before_size} -> {after_size} bytes")?;
            } else {
                writeln!(out, " {path} | {} (+{adds} -{dels})", adds + dels)?;
            }
        } else {
            file_patch(out, change, args)?;
        }
    }
    if args.stat {
        if args.json {
            serde_json::to_writer(
                &mut *out,
                &serde_json::json!({"files":changes.len(),"insertions":inserted,"deletions":removed,"bytes_written":written,"paths":stats}),
            )?;
            out.write_all(b"\n")?;
        } else if !changes.is_empty() {
            writeln!(out, " {} files changed, {inserted} insertions(+), {removed} deletions(-), {written} bytes written", changes.len())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
