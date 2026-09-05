//! Offline `--repack-seekable` CLI wrapper around [`ratarmount_compress::repack_seekable`].
//!
//! v1 is local files only (remote PUT is F-7). Clap exclusivity lives in `main.rs`.

use std::path::Path;

use ratarmount_compress::{repack_seekable, RepackOptions, RepackOutcome};

/// Reject remote URLs and missing IN / OUT parent, then call the compress engine.
pub fn run(input: &Path, output: &Path, opts: &RepackOptions) -> Result<RepackOutcome, String> {
    validate_local_paths(input, output)?;
    let mut opts = opts.clone();
    // `--repack-gzidx` implies a gzip sidecar; the engine requires keep_gzip.
    if opts.write_gzidx {
        opts.keep_gzip = true;
    }
    repack_seekable(input, output, &opts).map_err(|e| e.to_string())
}

pub fn validate_local_paths(input: &Path, output: &Path) -> Result<(), String> {
    reject_remote(input, "IN")?;
    reject_remote(output, "OUT")?;
    if !input.is_file() {
        return Err(format!(
            "--repack-seekable IN is not a local file: {}",
            input.display()
        ));
    }
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(format!(
                "--repack-seekable OUT parent is not a directory: {}",
                parent.display()
            ));
        }
    }
    Ok(())
}

pub fn describe_outcome(outcome: &RepackOutcome) -> String {
    match outcome {
        RepackOutcome::DidNothing => "repack: already seekable (no change)".into(),
        RepackOutcome::CopiedExistingSeekable => "repack: copied existing seekable archive".into(),
        RepackOutcome::AppendedSeekTable => "repack: appended zstd seek table".into(),
        RepackOutcome::CopiedWithoutSeekTable => {
            "repack: copied multi-frame zstd without seek table (a frame exceeded u32); \
             use --repack-force to split"
                .into()
        }
        RepackOutcome::Recompressed {
            frames,
            uncompressed,
            wrote_seek_table,
        } => {
            if *wrote_seek_table {
                format!("repack: recompressed {frames} frames ({uncompressed} uncompressed bytes)")
            } else {
                format!(
                    "repack: recompressed {frames} frames ({uncompressed} uncompressed bytes); \
                     omitted seek table (a frame exceeded u32)"
                )
            }
        }
        RepackOutcome::WroteGzipSidecar { points } => {
            format!("repack: wrote gzip sidecar ({points} seek points)")
        }
    }
}

fn reject_remote(path: &Path, which: &str) -> Result<(), String> {
    let Some(s) = path.to_str() else {
        return Ok(());
    };
    if ratarmount_remote::is_remote_url(s) {
        return Err(format!(
            "--repack-seekable {which} must be a local file (remote URLs are F-7)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    use ratarmount_compress::{open_seekable_zstd, RepackOptions, RepackOutcome};
    use ratarmount_core::OpenOptions;
    use ratarmount_formats_tar::{
        write_tar_eof, write_ustar_members, SqliteIndexedTar, UstarMember, UstarPayload,
    };

    fn backward_start_count(starts: &[u64]) -> usize {
        starts.windows(2).filter(|w| w[1] < w[0]).count()
    }

    fn member_path(path: &str, name: &str) -> String {
        if path.is_empty() || path == "/" {
            format!("/{name}")
        } else {
            format!("{path}/{name}")
        }
    }

    /// Regression: clap must not treat OUT as a FUSE mountpoint (see main tests);
    /// tar-in-order repack keeps member offset order (zero backward flatten seeks).
    #[test]
    fn repack_preserves_tar_offset_order() {
        const N_PER_DIR: usize = 16;
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("interleaved.tar");
        let output = dir.path().join("interleaved.tar.zst");

        let mut payloads: Vec<(String, Vec<u8>)> = Vec::new();
        for i in 0..N_PER_DIR {
            payloads.push((format!("z/m{i:02}"), vec![b'z'; 8 + i]));
            payloads.push((format!("a/m{i:02}"), vec![b'a'; 8 + i]));
        }
        assert_eq!(payloads.len(), 32);
        let members: Vec<UstarMember<'_>> = payloads
            .iter()
            .map(|(p, b)| UstarMember {
                path: p,
                payload: UstarPayload::File { bytes: b },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            })
            .collect();
        {
            let mut f = std::fs::File::create(&input).unwrap();
            write_ustar_members(&mut f, &members).unwrap();
            write_tar_eof(&mut f).unwrap();
        }

        let opts = RepackOptions {
            frame_size: 64,
            level: 3,
            keep_gzip: false,
            write_gzidx: false,
            force: false,
        };
        let outcome = run(&input, &output, &opts).expect("repack");
        match outcome {
            RepackOutcome::Recompressed {
                wrote_seek_table, ..
            } => {
                assert!(wrote_seek_table);
            }
            other => panic!("expected Recompressed, got {other:?}"),
        }

        let body = open_seekable_zstd(&output).unwrap();
        assert_eq!(body.kind(), "zstd-seek-table");
        let mut uncompressed = Vec::new();
        body.open_reader()
            .unwrap()
            .read_to_end(&mut uncompressed)
            .unwrap();

        let m = SqliteIndexedTar::create_index_from_reader(
            std::io::Cursor::new(uncompressed.clone()),
            Path::new("interleaved.tar.zst"),
            None,
            &OpenOptions::default(),
            "0.1.0",
        )
        .expect("index repacked tar");
        let flat = m.index().list_visible_files_by_offset().expect("flatten");
        assert!(
            flat.len() >= 32,
            "flatten must include all payload files, got {}",
            flat.len()
        );

        let got: Vec<String> = flat
            .iter()
            .map(|mem| member_path(&mem.path, &mem.name))
            .collect();
        let want: Vec<String> = payloads.iter().map(|(p, _)| format!("/{p}")).collect();
        assert_eq!(
            got[..32],
            want[..],
            "repack must keep TAR member offset order, got {got:?}"
        );

        struct StartLog {
            inner: std::io::Cursor<Vec<u8>>,
            starts: Vec<u64>,
        }
        impl Read for StartLog {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.inner.read(buf)
            }
        }
        impl Seek for StartLog {
            fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
                if let SeekFrom::Start(n) = from {
                    self.starts.push(n);
                }
                self.inner.seek(from)
            }
        }

        let mut offset_reader = StartLog {
            inner: std::io::Cursor::new(uncompressed.clone()),
            starts: Vec::new(),
        };
        for mem in &flat {
            offset_reader
                .seek(SeekFrom::Start(mem.cookie.offset))
                .unwrap();
            let mut buf = vec![0u8; mem.cookie.size as usize];
            offset_reader.read_exact(&mut buf).unwrap();
        }
        let offset_back = backward_start_count(&offset_reader.starts);
        assert_eq!(
            offset_back, 0,
            "flatten must have zero backward Start, starts={:?}",
            offset_reader.starts
        );

        let mut by_name = flat.clone();
        by_name.sort_by_key(|a| member_path(&a.path, &a.name));
        let mut name_reader = StartLog {
            inner: std::io::Cursor::new(uncompressed),
            starts: Vec::new(),
        };
        for mem in &by_name {
            name_reader
                .seek(SeekFrom::Start(mem.cookie.offset))
                .unwrap();
            let mut buf = vec![0u8; mem.cookie.size as usize];
            name_reader.read_exact(&mut buf).unwrap();
        }
        let name_back = backward_start_count(&name_reader.starts);
        assert!(
            name_back >= 1,
            "name-order control must have ≥1 backward Start (fixture shuffled), starts={:?}",
            name_reader.starts
        );
    }

    #[test]
    fn repack_rejects_remote_url() {
        let err = validate_local_paths(Path::new("s3://bucket/a.tar"), Path::new("out.tar.zst"))
            .unwrap_err();
        assert!(err.contains("local file"), "{err}");
        assert!(err.contains("IN"), "{err}");

        let err = validate_local_paths(Path::new("in.tar"), Path::new("s3://bucket/out.tar.zst"))
            .unwrap_err();
        assert!(err.contains("local file"), "{err}");
        assert!(err.contains("OUT"), "{err}");
    }

    #[test]
    fn repack_rejects_missing_input() {
        let err = validate_local_paths(
            Path::new("/no/such/repack-in.tar"),
            Path::new("/tmp/out.tar.zst"),
        )
        .unwrap_err();
        assert!(err.contains("not a local file"), "{err}");
    }

    #[test]
    fn repack_rejects_missing_out_parent() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.tar");
        std::fs::write(&input, b"x").unwrap();
        let output = dir.path().join("no-such-dir").join("out.tar.zst");
        let err = validate_local_paths(&input, &output).unwrap_err();
        assert!(err.contains("not a directory"), "{err}");
        assert!(!err.contains("writable"), "{err}");
    }

    #[test]
    fn repack_rejects_out_parent_that_is_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.tar");
        std::fs::write(&input, b"x").unwrap();
        let parent = dir.path().join("not-a-dir");
        std::fs::write(&parent, b"x").unwrap();
        let output = parent.join("out.tar.zst");
        let err = validate_local_paths(&input, &output).unwrap_err();
        assert!(err.contains("not a directory"), "{err}");
    }

    #[test]
    fn describe_outcome_mentions_force_on_u32_overflow() {
        let msg = describe_outcome(&RepackOutcome::CopiedWithoutSeekTable);
        assert!(msg.contains("--repack-force"), "{msg}");
    }
}
