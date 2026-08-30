//! List the first page of `/` in a TAR via [`ratarmount_session::Session`] (no FUSE).
//!
//! ```text
//! cargo run -p ratarmount-session --example session-list -- archive.tar
//! cargo run -p ratarmount-session --example session-list
//! ```
//!
//! With no argument, writes a tiny TAR in a temp dir so the example is runnable
//! as-is. Index policy is [`IndexPolicy::Temp`] (unlinked on `Session` drop).

use std::io::Write;
use std::path::PathBuf;

use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
use ratarmount_session::{DirCursor, IndexPolicy, OpenRequest, Recreate, Session, SourceSpec};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_keep, archive) = match std::env::args_os().nth(1) {
        Some(p) => (None, PathBuf::from(p)),
        None => {
            let dir = tempfile::tempdir()?;
            let tar = dir.path().join("example.tar");
            let mut f = std::fs::File::create(&tar)?;
            write_ustar_members(
                &mut f,
                &[UstarMember {
                    path: "hello.txt",
                    payload: UstarPayload::File {
                        bytes: b"hello from session-list\n",
                    },
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                }],
            )?;
            write_tar_eof(&mut f)?;
            f.flush()?;
            (Some(dir), tar)
        }
    };

    let session = Session::open(OpenRequest {
        source: SourceSpec::Path(archive),
        index: IndexPolicy::Temp,
        explicit_index: None,
        extra_dirs: Vec::new(),
        password: None,
        recursive: false,
        recursion_depth: None,
        recreate: Recreate::IfInvalid,
    })?;

    // limit 0 → engine default 200
    let page = session.list_dirents_page("/", DirCursor::Start, 0)?;
    for ent in &page.entries {
        let kind = if ent.is_dir { "dir" } else { "file" };
        println!("{kind}\t{}\t{}", ent.size, ent.name);
    }
    if let Some(next) = page.next_cursor {
        eprintln!("(more pages after {next:?})");
    }
    Ok(())
}
