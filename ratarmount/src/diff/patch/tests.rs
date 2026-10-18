use super::*;
use ratarmount_compositing::overlay_changes::ChangeOptions;
fn entry(mode: u32, data: Vec<u8>) -> Entry {
    Entry::from_bytes(mode, data, &ChangeOptions::default()).unwrap()
}
fn render(changes: &[Change], args: &DiffArgs) -> io::Result<String> {
    let mut out = Vec::new();
    super::render(changes, args, &mut out)?;
    String::from_utf8(out).map_err(io::Error::other)
}

/// Regression: binary literals must round-trip without an installed Git.
#[test]
fn regression_diff_binary_literal_roundtrip() {
    for data in [vec![], vec![0], (0..=255).cycle().take(10_000).collect()] {
        let args = DiffArgs {
            git: true,
            ..Default::default()
        };
        let change = Change {
            from: "bin".into(),
            to: "bin".into(),
            old: Some(entry(0o100644, vec![0xff, 0])),
            new: Some(entry(0o100644, data.clone())),
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
        blob_id(&Some(entry(0o100644, vec![]))).unwrap(),
        "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    );
}

/// Regression: separated edits, zero context and missing newlines retain exact ranges.
#[test]
fn regression_diff_context_and_missing_newline() {
    let mut out = Vec::new();
    hunks(
        &mut out,
        &lines(b"a\nb\nc\nd\ne\nf\ng\nh\n", b"A\nb\nc\nd\ne\nf\ng\nH"),
        1,
    )
    .unwrap();
    assert_eq!(
        out,
        b"@@ -1,2 +1,2 @@\n-a\n+A\n b\n@@ -7,2 +7,2 @@\n g\n-h\n+H\n\\ No newline at end of file\n"
    );
    out.clear();
    hunks(&mut out, &lines(b"a\nb\n", b"a\nx\nb\n"), 0).unwrap();
    assert_eq!(out, b"@@ -1,0 +2 @@\n+x\n");
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
            let script = lines(a.as_bytes(), b.as_bytes());
            assert_eq!(
                script
                    .iter()
                    .filter(|l| l.tag != '+')
                    .flat_map(|l| l.text.iter().copied())
                    .collect::<Vec<u8>>(),
                a.as_bytes()
            );
            assert_eq!(
                script
                    .iter()
                    .filter(|l| l.tag != '-')
                    .flat_map(|l| l.text.iter().copied())
                    .collect::<Vec<u8>>(),
                b.as_bytes()
            );
        }
    }
}

/// Regression: unrelated large text must produce an exact replacement with bounded traceback.
#[test]
fn regression_diff_large_replacement_bounds_traceback() {
    let a = vec![b"old\n".as_slice(); 2000];
    let b = vec![b"new\n".as_slice(); 2000];
    let script = myers(&a, &b);
    assert_eq!(script.len(), 4000);
    assert!(script[..2000]
        .iter()
        .all(|line| line.tag == '-' && line.text == b"old\n"));
    assert!(script[2000..]
        .iter()
        .all(|line| line.tag == '+' && line.text == b"new\n"));
}
/// Regression: Latin-1 and CRLF hunks retain bytes without triggering the binary heuristic.
#[test]
fn regression_diff_byte_hunks_latin1_crlf() {
    let mut out = Vec::new();
    hunks(&mut out, &lines(b"caf\xe9\r\n", b"CAF\xe9\r\n"), 3).unwrap();
    assert_eq!(out, b"@@ -1 +1 @@\n-caf\xe9\r\n+CAF\xe9\r\n");
    assert!(!binary(b"caf\xe9\r\n"));
}

/// Regression: canonical mode can differ from Git's limited executable-bit modes.
#[test]
fn regression_diff_quote_and_git_modes() {
    assert_eq!(quote_bytes(b"bad\xff\t\"\\"), "\"bad\\377\\t\\\"\\\\\"");
    assert_eq!(entry(0o100644, vec![]).git_mode(), 0o100644);
    assert_eq!(entry(0o100754, vec![]).git_mode(), 0o100755);
    assert_eq!(entry(0o120777, b"target".to_vec()).git_mode(), 0o120000);
}
