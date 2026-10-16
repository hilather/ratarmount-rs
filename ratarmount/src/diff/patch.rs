//! Unified hunks and Git literal binary patches (zlib + Git base85).

use std::fmt::Write as _;
use std::io::{self, Write};

use flate2::{write::ZlibEncoder, Compression};
use sha1::{Digest, Sha1};

use super::{Change, DiffArgs, Entry};

const BASE85: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

pub(super) fn quote(path: &str) -> String {
    if path
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
    {
        return path.to_owned();
    }
    let mut out = String::from("\"");
    for b in path.bytes() {
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

fn bytes(entry: &Option<Entry>) -> &[u8] {
    entry.as_ref().map_or(&[], |e| e.data.as_slice())
}

fn binary(data: &[u8]) -> bool {
    data.contains(&0) || std::str::from_utf8(data).is_err()
}

fn blob_id(entry: &Option<Entry>) -> String {
    match entry {
        None => "0".repeat(40),
        Some(entry) => {
            let mut hash = Sha1::new();
            hash.update(format!("blob {}\0", entry.data.len()).as_bytes());
            hash.update(&entry.data);
            format!("{:x}", hash.finalize())
        }
    }
}

fn literal(out: &mut String, data: &[u8]) -> io::Result<()> {
    let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
    zlib.write_all(data)?;
    let compressed = zlib.finish()?;
    let _ = writeln!(out, "literal {}", data.len());
    for chunk in compressed.chunks(52) {
        out.push(if chunk.len() <= 26 {
            b'A' + chunk.len() as u8 - 1
        } else {
            b'a' + chunk.len() as u8 - 27
        } as char);
        for word in chunk.chunks(4) {
            let mut padded = [0; 4];
            padded[..word.len()].copy_from_slice(word);
            let mut value = u32::from_be_bytes(padded);
            let mut encoded = [0; 5];
            for digit in encoded.iter_mut().rev() {
                *digit = BASE85[(value % 85) as usize];
                value /= 85;
            }
            for digit in encoded {
                out.push(digit as char);
            }
        }
        out.push('\n');
    }
    out.push('\n');
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Line<'a> {
    tag: char,
    text: &'a str,
}

fn lines<'a>(old: &'a str, new: &'a str) -> Vec<Line<'a>> {
    let a: Vec<_> = old.split_inclusive('\n').collect();
    let b: Vec<_> = new.split_inclusive('\n').collect();
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

fn myers<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<Line<'a>> {
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

fn hunks(out: &mut String, lines: &[Line<'_>], context: usize) {
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
        let _ = writeln!(
            out,
            "@@ -{} +{} @@",
            range(old_before, old_count),
            range(new_before, new_count)
        );
        for line in &lines[start..end] {
            out.push(line.tag);
            out.push_str(line.text);
            if !line.text.ends_with('\n') {
                out.push_str("\n\\ No newline at end of file\n");
            }
        }
        old_before += old_count;
        new_before += new_count;
        previous = end;
    }
}

fn file_patch(out: &mut String, change: &Change, args: &DiffArgs) -> io::Result<()> {
    let Change { from, to, old, new } = change;
    // Git represents a type change as a deletion followed by an addition.
    if args.git
        && old
            .as_ref()
            .zip(new.as_ref())
            .is_some_and(|(a, b)| a.git_mode() & 0o170000 != b.git_mode() & 0o170000)
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
    let a = quote(&format!("a/{from}"));
    let b = quote(&format!("b/{to}"));
    if args.git {
        let _ = writeln!(out, "diff --git {a} {b}");
    }
    let mode = |entry: &Entry| {
        if args.git {
            entry.git_mode()
        } else {
            entry.mode
        }
    };
    match (old, new) {
        (None, Some(new)) => {
            let _ = writeln!(out, "new file mode {:06o}", mode(new));
        }
        (Some(old), None) => {
            let _ = writeln!(out, "deleted file mode {:06o}", mode(old));
        }
        (Some(old), Some(new)) if mode(old) != mode(new) => {
            let _ = writeln!(
                out,
                "old mode {:06o}\nnew mode {:06o}",
                mode(old),
                mode(new)
            );
        }
        _ => {}
    }
    if from != to {
        let _ = writeln!(
            out,
            "similarity index 100%\nrename from {}\nrename to {}",
            quote(from),
            quote(to)
        );
    }
    let before = bytes(old);
    let after = bytes(new);
    let content_changed = before != after;
    if args.git && (content_changed || old.is_none() || new.is_none()) {
        let common_mode = old
            .as_ref()
            .zip(new.as_ref())
            .filter(|(a, b)| a.git_mode() == b.git_mode())
            .map(|(entry, _)| format!(" {:06o}", entry.git_mode()))
            .unwrap_or_default();
        let _ = writeln!(out, "index {}..{}{common_mode}", blob_id(old), blob_id(new));
    }
    if !content_changed && old.is_some() && new.is_some() {
        if !args.git {
            let _ = writeln!(out, "--- {a}\n+++ {b}");
        }
        return Ok(());
    }
    if binary(before) || binary(after) {
        if args.git {
            out.push_str("GIT binary patch\n");
            literal(out, after)?;
            literal(out, before)?;
        } else {
            let _ = writeln!(out, "Binary files {a} and {b} differ");
        }
    } else if content_changed || !args.git {
        let _ = writeln!(
            out,
            "--- {}\n+++ {}",
            if old.is_none() { "/dev/null" } else { &a },
            if new.is_none() { "/dev/null" } else { &b }
        );
        hunks(
            out,
            &lines(
                std::str::from_utf8(before).expect("text"),
                std::str::from_utf8(after).expect("text"),
            ),
            args.context,
        );
    }
    Ok(())
}

pub(super) fn render(changes: &[Change], args: &DiffArgs) -> io::Result<String> {
    let mut out = String::new();
    let (mut inserted, mut removed) = (0, 0);
    for change in changes {
        if args.name_status {
            if change.from != change.to {
                let _ = writeln!(out, "R100\t{}\t{}", quote(&change.from), quote(&change.to));
            } else {
                let _ = writeln!(out, "{}\t{}", change.status(), quote(&change.to));
            }
        } else if args.stat {
            let before = bytes(&change.old);
            let after = bytes(&change.new);
            let path = if change.from == change.to {
                quote(&change.to)
            } else {
                format!("{} => {}", quote(&change.from), quote(&change.to))
            };
            if binary(before) || binary(after) {
                let _ = writeln!(
                    out,
                    " {path} | Bin {} -> {} bytes",
                    before.len(),
                    after.len()
                );
            } else {
                let edits = lines(
                    std::str::from_utf8(before).expect("text"),
                    std::str::from_utf8(after).expect("text"),
                );
                let adds = edits.iter().filter(|l| l.tag == '+').count();
                let dels = edits.iter().filter(|l| l.tag == '-').count();
                inserted += adds;
                removed += dels;
                let _ = writeln!(out, " {path} | {} (+{adds} -{dels})", adds + dels);
            }
        } else {
            file_patch(&mut out, change, args)?;
        }
    }
    if args.stat && !changes.is_empty() {
        let _ = writeln!(
            out,
            " {} files changed, {inserted} insertions(+), {removed} deletions(-)",
            changes.len()
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Regression: binary literals must round-trip without an installed Git.
    #[test]
    fn regression_diff_binary_literal_roundtrip() {
        for data in [vec![], vec![0], (0..=255).cycle().take(10_000).collect()] {
            let args = DiffArgs {
                directory: "unused".into(),
                base: None,
                git: true,
                context: 3,
                stat: false,
                name_status: false,
                include_git_dir: false,
            };
            let change = Change {
                from: "bin".into(),
                to: "bin".into(),
                old: Some(Entry {
                    mode: 0o100644,
                    data: vec![0xff, 0],
                }),
                new: Some(Entry {
                    mode: 0o100644,
                    data: data.clone(),
                }),
            };
            let patch = render(&[change], &args).unwrap();
            let encoded = patch.split_once("GIT binary patch\n").unwrap().1;
            let mut lines = encoded.lines();
            assert_eq!(lines.next().unwrap(), format!("literal {}", data.len()));
            let mut compressed = Vec::new();
            for line in lines.take_while(|line| !line.is_empty()) {
                let len = match line.as_bytes()[0] {
                    b'A'..=b'Z' => line.as_bytes()[0] - b'A' + 1,
                    n => n - b'a' + 27,
                } as usize;
                let mut block = Vec::new();
                for word in line.as_bytes()[1..].as_chunks::<5>().0 {
                    let value = word.iter().fold(0u32, |n, digit| {
                        n * 85 + BASE85.iter().position(|v| v == digit).unwrap() as u32
                    });
                    block.extend_from_slice(&value.to_be_bytes());
                }
                compressed.extend_from_slice(&block[..len]);
            }
            let mut decoded = Vec::new();
            flate2::read::ZlibDecoder::new(compressed.as_slice())
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, data);
        }
        assert_eq!(
            blob_id(&Some(Entry {
                mode: 0o100644,
                data: vec![]
            })),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
    }

    /// Regression: separated edits, zero context and missing newlines retain exact ranges.
    #[test]
    fn regression_diff_context_and_missing_newline() {
        let mut out = String::new();
        hunks(
            &mut out,
            &lines("a\nb\nc\nd\ne\nf\ng\nh\n", "A\nb\nc\nd\ne\nf\ng\nH"),
            1,
        );
        assert_eq!(out, "@@ -1,2 +1,2 @@\n-a\n+A\n b\n@@ -7,2 +7,2 @@\n g\n-h\n+H\n\\ No newline at end of file\n");
        out.clear();
        hunks(&mut out, &lines("a\nb\n", "a\nx\nb\n"), 0);
        assert_eq!(out, "@@ -1,0 +2 @@\n+x\n");
    }

    /// Regression: edit scripts must preserve both inputs for repeated and empty lines.
    #[test]
    fn regression_diff_edit_script_preserves_inputs() {
        let samples = [
            "",
            "a",
            "a\n",
            "\n",
            "a\nb\na\n",
            "b\na\nb",
            "\n\na\na\nb\n",
        ];
        for a in samples {
            for b in samples {
                let script = lines(a, b);
                assert_eq!(
                    script
                        .iter()
                        .filter(|l| l.tag != '+')
                        .map(|l| l.text)
                        .collect::<String>(),
                    a
                );
                assert_eq!(
                    script
                        .iter()
                        .filter(|l| l.tag != '-')
                        .map(|l| l.text)
                        .collect::<String>(),
                    b
                );
            }
        }
    }

    /// Regression: unrelated large text must produce an exact replacement with bounded traceback.
    #[test]
    fn regression_diff_large_replacement_bounds_traceback() {
        let a = vec!["old\n"; 2000];
        let b = vec!["new\n"; 2000];
        let script = myers(&a, &b);
        assert_eq!(script.len(), 4000);
        assert!(script[..2000]
            .iter()
            .all(|line| line.tag == '-' && line.text == "old\n"));
        assert!(script[2000..]
            .iter()
            .all(|line| line.tag == '+' && line.text == "new\n"));
    }
}
