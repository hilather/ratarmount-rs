//! Streaming index export; no FUSE or payload reads are required for sidecars.

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use ratarmount_compress::{scan_zstd_frames_path, ZstdFrameInfo};
use ratarmount_index::{IndexLocation, SqliteIndex};
use ratarmount_session::{resolve_index, IndexPolicy, Session};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

use crate::shard::{index_request, Manifest, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(super) enum Format {
    Parquet,
    Jsonl,
    Csv,
}

#[derive(Clone, Debug, Parser)]
#[command(
    name = "ratarmount export-index",
    about = "Export archive metadata and seekable-zstd frame locations"
)]
pub(super) struct ExportArgs {
    #[arg(required = true, num_args = 1..)]
    pub inputs: Vec<PathBuf>,
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "parquet")]
    format: Format,
}

#[derive(Debug, Serialize)]
struct ExportRow {
    path: String,
    name: String,
    size: Option<i64>,
    mode: Option<i64>,
    mtime: Option<f64>,
    #[serde(rename = "type")]
    kind: Option<i64>,
    link_target: Option<String>,
    offsetheader: Option<i64>,
    offset: Option<i64>,
    sha256: Option<String>,
    shard: Option<String>,
    frame: Option<u64>,
    /// Compressed byte offset, also exposed with an explicit column name.
    frame_offset: Option<u64>,
    frame_compressed_offset: Option<u64>,
    frame_compressed_size: Option<u64>,
    frame_decompressed_offset: Option<u64>,
    offset_within_frame: Option<u64>,
}

const COLUMNS: &[&str] = &[
    "path",
    "name",
    "size",
    "mode",
    "mtime",
    "type",
    "link_target",
    "offsetheader",
    "offset",
    "sha256",
    "shard",
    "frame",
    "frame_offset",
    "frame_compressed_offset",
    "frame_compressed_size",
    "frame_decompressed_offset",
    "offset_within_frame",
];
struct Input {
    archive: Option<PathBuf>,
    index: Option<PathBuf>,
    shard: Option<String>,
}

fn safe_manifest_path(base: &Path, name: &str) -> Result<PathBuf> {
    let path = Path::new(name);
    if path
        .components()
        .any(|c| !matches!(c, std::path::Component::Normal(_)))
        || path.as_os_str().is_empty()
    {
        return Err(format!("unsafe manifest path: {name}").into());
    }
    Ok(base.join(path))
}

fn inputs(args: &ExportArgs) -> Result<Vec<Input>> {
    let mut result = Vec::new();
    for path in &args.inputs {
        if path.file_name().is_some_and(|s| s == "shards.json") {
            // Managed (#151): every internal input of export-index.
            let manifest: Manifest =
                serde_json::from_slice(&ratarmount_index::managed_read::read(path)?)?;
            if manifest.format != "ratarmount-shards-v1" {
                return Err("unsupported shard manifest format".into());
            }
            let base = path.parent().unwrap_or(Path::new("."));
            for entry in manifest.shards {
                result.push(Input {
                    archive: Some(safe_manifest_path(base, &entry.name)?),
                    index: entry
                        .index
                        .as_deref()
                        .map(|i| safe_manifest_path(base, i))
                        .transpose()?,
                    shard: Some(entry.name),
                });
            }
        } else {
            // Accept named or anonymous SQLite sidecars; do not rely on suffixes.
            let magic = ratarmount_index::managed_read::read_prefix(path, 16)?;
            let sqlite = magic.as_slice() == b"SQLite format 3\0";
            let sidecar = if sqlite {
                let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='files')", [], |r| r.get::<_, bool>(0))?
            } else {
                false
            };
            let (archive, index) = if sidecar {
                let archive = ratarmount_index::archive_base_from_index_path(path);
                (archive.is_file().then_some(archive), Some(path.clone()))
            } else {
                (Some(path.clone()), None)
            };
            let shard = (args.inputs.len() > 1).then(|| {
                archive
                    .as_ref()
                    .unwrap_or(path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            });
            result.push(Input {
                archive,
                index,
                shard,
            });
        }
    }
    Ok(result)
}

fn index_path(input: &Input) -> Result<PathBuf> {
    if let Some(index) = &input.index {
        return Ok(index.clone());
    }
    let archive = input
        .archive
        .as_ref()
        .ok_or("archive or sidecar required")?;
    let location = resolve_index(
        archive,
        IndexPolicy::CliCompat,
        None,
        &ratarmount_index::default_index_folders(),
        false,
    )?;
    let IndexLocation::Path(index) = location else {
        return Err("export requires a writable index location; pass an existing sidecar".into());
    };
    if let Ok(existing) = SqliteIndex::open_catalog_read_only(&index) {
        if existing.check_tarstats_matches_archive(archive).is_ok() {
            return Ok(index);
        }
    }
    drop(Session::open(index_request(archive, &index))?);
    Ok(index)
}

fn frame_map(index: &SqliteIndex, archive: Option<&Path>) -> Result<Vec<ZstdFrameInfo>> {
    // The EOF sentinel gives sizes without requiring the archive beside a sidecar.
    if index.has_compression_table("zstdblocks")? {
        let blocks = index.get_zstd_blocks()?;
        if !blocks.is_empty() {
            let mut frames = Vec::new();
            for pair in blocks.windows(2) {
                let (c, d) = pair[0];
                let (end_c, end_d) = pair[1];
                if c < 0 || d < 0 || end_c <= c || end_d < d {
                    return Err("invalid zstdblocks offset map".into());
                }
                frames.push(ZstdFrameInfo {
                    compressed_offset: c as u64,
                    uncompressed_offset: d as u64,
                    compressed_size: (end_c - c) as u64,
                    uncompressed_size: (end_d - d) as u64,
                });
            }
            if !frames.is_empty() {
                return Ok(frames);
            }
        }
    }
    if let Some(archive) = archive {
        let magic = ratarmount_index::managed_read::read_prefix(archive, 4)?;
        if magic.as_slice() == [0x28, 0xb5, 0x2f, 0xfd] {
            return Ok(scan_zstd_frames_path(archive)?.frames);
        }
    }
    Ok(Vec::new())
}

fn read_rows(input: &Input, mut emit: impl FnMut(ExportRow) -> Result<()>) -> Result<()> {
    let path = index_path(input)?;
    let index = SqliteIndex::open_catalog_read_only(&path)?;
    let frames = frame_map(&index, input.archive.as_deref())?;
    let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let has_xattrs: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='xattrs')",
        [],
        |r| r.get(0),
    )?;
    let hash_sql = if has_xattrs {
        "(SELECT CAST(x.value AS TEXT) FROM xattrs x WHERE x.offsetheader=f.offsetheader AND x.key='user.hash.sha256')"
    } else {
        "NULL"
    };
    let mut query = conn.prepare(&format!("SELECT f.path,f.name,f.size,f.mode,f.mtime,f.type,f.linkname,f.offsetheader,f.offset,{hash_sql} FROM files f ORDER BY f.path COLLATE BINARY,f.name COLLATE BINARY,f.offsetheader"))?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        let parent: String = row.get(0)?;
        let name: String = row.get(1)?;
        let offset: Option<i64> = row.get(8)?;
        let frame = offset
            .and_then(|o| u64::try_from(o).ok())
            .and_then(|offset| {
                let i = frames
                    .partition_point(|f| f.uncompressed_offset <= offset)
                    .checked_sub(1)?;
                let f = &frames[i];
                (offset - f.uncompressed_offset < f.uncompressed_size).then_some((
                    i as u64,
                    f,
                    offset - f.uncompressed_offset,
                ))
            });
        emit(ExportRow {
            path: format!("{}/{name}", parent.trim_end_matches('/')),
            name,
            size: row.get(2)?,
            mode: row.get(3)?,
            mtime: row.get(4)?,
            kind: row.get(5)?,
            link_target: row.get(6)?,
            offsetheader: row.get(7)?,
            offset,
            sha256: row.get(9)?,
            shard: input.shard.clone(),
            frame: frame.map(|(i, _, _)| i),
            frame_offset: frame.map(|(_, f, _)| f.compressed_offset),
            frame_compressed_offset: frame.map(|(_, f, _)| f.compressed_offset),
            frame_compressed_size: frame.map(|(_, f, _)| f.compressed_size),
            frame_decompressed_offset: frame.map(|(_, f, _)| f.uncompressed_offset),
            offset_within_frame: frame.map(|(_, _, o)| o),
        })?;
    }
    Ok(())
}

fn csv_field(out: &mut dyn Write, text: &str) -> Result<()> {
    if text.contains([',', '"', '\r', '\n']) {
        write!(out, "\"{}\"", text.replace('"', "\"\""))?;
    } else {
        out.write_all(text.as_bytes())?;
    }
    Ok(())
}

fn export(inputs: &[Input], format: Format, out: &mut dyn Write) -> Result<()> {
    if format == Format::Parquet {
        return parquet_export(inputs, out);
    }
    if format == Format::Csv {
        write!(out, "{}\r\n", COLUMNS.join(","))?;
    }
    for input in inputs {
        read_rows(input, |row| {
            if format == Format::Jsonl {
                serde_json::to_writer(&mut *out, &row)?;
                out.write_all(b"\n")?;
            } else {
                let value = serde_json::to_value(row)?;
                for (i, column) in COLUMNS.iter().enumerate() {
                    if i != 0 {
                        out.write_all(b",")?;
                    }
                    let value = &value[column];
                    if let Some(text) = value.as_str() {
                        csv_field(out, text)?;
                    } else if !value.is_null() {
                        csv_field(out, &value.to_string())?;
                    }
                }
                out.write_all(b"\r\n")?;
            }
            Ok(())
        })?;
    }
    out.flush()?;
    Ok(())
}

#[cfg(not(feature = "export-parquet"))]
fn parquet_export(_inputs: &[Input], _out: &mut dyn Write) -> Result<()> {
    Err("Parquet export requires the export-parquet Cargo feature; jsonl and csv are always available".into())
}

#[cfg(feature = "export-parquet")]
fn parquet_export(inputs: &[Input], out: &mut dyn Write) -> Result<()> {
    use arrow::array::{ArrayRef, Float64Array, Int64Array, StringArray, UInt64Array};
    use arrow::datatypes::{DataType, Field, Schema};
    use arrow::record_batch::RecordBatch;
    use parquet::arrow::ArrowWriter;
    use std::sync::Arc;
    // Spool binary output so stdout remains streaming and need not implement Send.
    let mut spool = tempfile::tempfile()?;
    let mut fields = Vec::new();
    for (i, name) in COLUMNS.iter().enumerate() {
        let ty = match i {
            0 | 1 | 6 | 9 | 10 => DataType::Utf8,
            4 => DataType::Float64,
            11.. => DataType::UInt64,
            _ => DataType::Int64,
        };
        fields.push(Field::new(*name, ty, true));
    }
    let schema = Arc::new(Schema::new(fields));
    let properties = parquet::file::properties::WriterProperties::builder()
        .set_max_row_group_row_count(Some(32_768))
        .build();
    let mut writer = ArrowWriter::try_new(&mut spool, Arc::clone(&schema), Some(properties))?;
    let flush = |rows: &mut Vec<ExportRow>, writer: &mut ArrowWriter<&mut File>| -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let strings = |get: fn(&ExportRow) -> Option<&str>| -> ArrayRef {
            Arc::new(StringArray::from(rows.iter().map(get).collect::<Vec<_>>()))
        };
        let ints = |get: fn(&ExportRow) -> Option<i64>| -> ArrayRef {
            Arc::new(Int64Array::from(rows.iter().map(get).collect::<Vec<_>>()))
        };
        let uints = |get: fn(&ExportRow) -> Option<u64>| -> ArrayRef {
            Arc::new(UInt64Array::from(rows.iter().map(get).collect::<Vec<_>>()))
        };
        let columns = vec![
            strings(|r| Some(&r.path)),
            strings(|r| Some(&r.name)),
            ints(|r| r.size),
            ints(|r| r.mode),
            Arc::new(Float64Array::from(
                rows.iter().map(|r| r.mtime).collect::<Vec<_>>(),
            )) as ArrayRef,
            ints(|r| r.kind),
            strings(|r| r.link_target.as_deref()),
            ints(|r| r.offsetheader),
            ints(|r| r.offset),
            strings(|r| r.sha256.as_deref()),
            strings(|r| r.shard.as_deref()),
            uints(|r| r.frame),
            uints(|r| r.frame_offset),
            uints(|r| r.frame_compressed_offset),
            uints(|r| r.frame_compressed_size),
            uints(|r| r.frame_decompressed_offset),
            uints(|r| r.offset_within_frame),
        ];
        writer.write(&RecordBatch::try_new(Arc::clone(&schema), columns)?)?;
        rows.clear();
        Ok(())
    };
    let mut batch = Vec::new();
    for input in inputs {
        read_rows(input, |row| {
            batch.push(row);
            if batch.len() == 4096 {
                flush(&mut batch, &mut writer)?;
            }
            Ok(())
        })?;
    }
    flush(&mut batch, &mut writer)?;
    writer.close()?;
    use std::io::{Seek, SeekFrom};
    spool.seek(SeekFrom::Start(0))?;
    io::copy(&mut spool, &mut *out)?;
    out.flush()?;
    Ok(())
}

/// Preserve the data stream while legacy factory status lines use stderr.
/// Called once by main before starting any shard/index workers.
pub(super) fn cli_stdout() -> io::Result<File> {
    use std::os::fd::FromRawFd;
    io::stdout().flush()?;
    let fd = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stdout = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stdout)
}

pub(super) fn run(args: &ExportArgs, stdout: &mut dyn Write) -> Result<()> {
    #[cfg(not(feature = "export-parquet"))]
    if args.format == Format::Parquet {
        return parquet_export(&[], &mut io::sink());
    }
    let mut inputs = inputs(args)?;
    // Resolve before checking destinations, including sidecars created for archives.
    for input in &mut inputs {
        input.index = Some(index_path(input)?);
    }
    if let Some(path) = &args.output {
        // Publish only after all rows and the format footer are complete.
        let target = if path.exists() {
            Some(fs::canonicalize(path)?)
        } else {
            None
        };
        for input in &inputs {
            for source in input
                .index
                .iter()
                .chain(input.archive.iter())
                .chain(args.inputs.iter())
            {
                if target
                    .as_ref()
                    .is_some_and(|p| fs::canonicalize(source).is_ok_and(|s| &s == p))
                {
                    return Err("export output must differ from every input".into());
                }
            }
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        export(
            &inputs,
            args.format,
            &mut BufWriter::new(temp.as_file_mut()),
        )?;
        temp.persist(path)?;
    } else {
        export(&inputs, args.format, stdout)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard;

    fn run(args: &ExportArgs) -> Result<()> {
        super::run(args, &mut io::sink())
    }

    fn args(inputs: &[PathBuf], output: &Path, format: &str) -> ExportArgs {
        let mut argv = vec![
            "ratarmount export-index".as_ref(),
            "--format".as_ref(),
            format.as_ref(),
            "-o".as_ref(),
            output.as_os_str(),
        ];
        argv.extend(inputs.iter().map(|p| p.as_os_str()));
        ExportArgs::try_parse_from(argv).unwrap()
    }
    fn json_rows(path: &Path) -> Vec<serde_json::Value> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// Regression: exported offsets/hashes must match the catalog and locate the sample's frame.
    #[test]
    fn regression_export_jsonl_offsets_hashes_and_frame_columns() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        shard::tests::dataset(&input);
        let output = temp.path().join("shards");
        let manifest = shard::run(&shard::tests::args(
            &input,
            &output,
            &["--frame-per-sample"],
        ))
        .unwrap();
        let shard = &manifest.shards[0];
        let index_path = output.join(shard.index.as_ref().unwrap());
        let index = SqliteIndex::open_writable(&index_path).unwrap();
        let conn = Connection::open(&index_path).unwrap();
        let offsetheader: i64 = conn
            .query_row(
                "SELECT offsetheader FROM files WHERE name='0000.jpg'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        index
            .insert_xattr(offsetheader, "user.hash.sha256", b"0123456789abcdef")
            .unwrap();
        index.wal_checkpoint_truncate().unwrap();
        drop(index);
        let target = temp.path().join("rows.jsonl");
        run(&args(&[output.join("shards.json")], &target, "jsonl")).unwrap();
        let rows = json_rows(&target);
        let mut total = 0;
        for shard in &manifest.shards {
            let conn = Connection::open(output.join(shard.index.as_ref().unwrap())).unwrap();
            let expected: i64 = conn
                .query_row("SELECT COUNT(*) FROM files", [], |r| r.get(0))
                .unwrap();
            let shard_rows: Vec<_> = rows.iter().filter(|r| r["shard"] == shard.name).collect();
            assert_eq!(shard_rows.len() as i64, expected);
            total += expected;
            let frames = scan_zstd_frames_path(&output.join(&shard.name)).unwrap();
            for row in shard_rows {
                let (offset, header, size): (Option<i64>, Option<i64>, Option<i64>) = conn.query_row("SELECT offset,offsetheader,size FROM files WHERE name=?1 AND offsetheader IS ?2", rusqlite::params![row["name"].as_str().unwrap(), row["offsetheader"].as_i64()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                assert_eq!(row["offset"].as_i64(), offset);
                assert_eq!(row["offsetheader"].as_i64(), header);
                assert_eq!(row["size"].as_i64(), size);
                if let Some(i) = row["frame"].as_u64() {
                    let frame = &frames.frames[i as usize];
                    assert_eq!(row["frame_compressed_offset"], frame.compressed_offset);
                    assert_eq!(row["frame_offset"], frame.compressed_offset);
                    assert_eq!(row["frame_compressed_size"], frame.compressed_size);
                    assert_eq!(row["frame_decompressed_offset"], frame.uncompressed_offset);
                    assert_eq!(
                        row["offset_within_frame"].as_u64().unwrap() + frame.uncompressed_offset,
                        offset.unwrap() as u64
                    );
                }
            }
        }
        assert_eq!(rows.len() as i64, total);
        assert_eq!(
            rows.iter().find(|r| r["name"] == "0000.jpg").unwrap()["sha256"],
            "0123456789abcdef"
        );
        assert!(rows
            .iter()
            .any(|r| r["frame"].as_u64().is_some_and(|i| i > 0)));
        assert_eq!(
            rows.iter().find(|r| r["name"] == "link.jpg").unwrap()["link_target"],
            "dir/0000.jpg"
        );
        // Close the last connection so copying the SQLite body includes WAL writes.
        drop(conn);
        // A moved sidecar remains useful without any archive payload or frame scan.
        let detached = temp.path().join("detached.sqlite");
        fs::copy(&index_path, &detached).unwrap();
        let side_rows = temp.path().join("side.jsonl");
        run(&args(&[detached], &side_rows, "jsonl")).unwrap();
        let detached = json_rows(&side_rows);
        assert_eq!(
            detached.iter().find(|r| r["name"] == "0000.jpg").unwrap()["frame"],
            0
        );
        // Scanning is the fallback when a foreign index has no zstdblocks map.
        Connection::open(&index_path)
            .unwrap()
            .execute("DELETE FROM zstdblocks", [])
            .unwrap();
        let scan_rows = temp.path().join("scan.jsonl");
        run(&args(&[index_path], &scan_rows, "jsonl")).unwrap();
        let scanned = json_rows(&scan_rows);
        for row in scanned {
            let original = detached.iter().find(|r| r["path"] == row["path"]).unwrap();
            assert_eq!(row["frame"], original["frame"]);
            assert_eq!(
                row["frame_compressed_size"],
                original["frame_compressed_size"]
            );
        }
    }

    /// Regression: CSV quoting must retain commas, quotes, newlines and nullable frame fields.
    #[test]
    fn regression_export_csv_quotes_paths_and_archive_builds_index() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        fs::write(input.join("a,\"line\n.txt"), b"contents").unwrap();
        let output = temp.path().join("out");
        let manifest = shard::run(&shard::tests::args(
            &input,
            &output,
            &["--codec", "none", "--no-index"],
        ))
        .unwrap();
        let archive = output.join(&manifest.shards[0].name);
        let target = temp.path().join("rows.csv");
        run(&args(std::slice::from_ref(&archive), &target, "csv")).unwrap();
        let csv = fs::read_to_string(&target).unwrap();
        assert!(csv.starts_with(&COLUMNS.join(",")));
        assert!(csv.contains("\"/a,\"\"line\n.txt\""));
        let json = temp.path().join("rows.jsonl");
        run(&args(&[archive.clone(), archive], &json, "jsonl")).unwrap();
        let rows = json_rows(&json);
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .all(|r| r["frame"].is_null() && r["shard"].as_str().unwrap().ends_with(".tar")));
    }

    #[cfg(feature = "export-parquet")]
    /// Regression: Parquet must retain numeric types and columns and be readable by Arrow.
    #[test]
    fn regression_export_parquet_readable_schema_and_row_count() {
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        shard::tests::dataset(&input);
        let output = temp.path().join("shards");
        shard::run(&shard::tests::args(
            &input,
            &output,
            &["--frame-size", "1K"],
        ))
        .unwrap();
        let target = temp.path().join("rows.parquet");
        run(&args(&[output.join("shards.json")], &target, "parquet")).unwrap();
        let json = temp.path().join("rows.jsonl");
        run(&args(&[output.join("shards.json")], &json, "jsonl")).unwrap();
        let expected = json_rows(&json);
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(File::open(&target).unwrap()).unwrap();
        let schema = builder.schema();
        assert_eq!(
            schema
                .fields()
                .iter()
                .map(|f| f.name().as_str())
                .collect::<Vec<_>>(),
            COLUMNS
        );
        assert_eq!(
            schema.field_with_name("offset").unwrap().data_type(),
            &arrow::datatypes::DataType::Int64
        );
        assert_eq!(
            schema.field_with_name("frame").unwrap().data_type(),
            &arrow::datatypes::DataType::UInt64
        );
        let mut offset = 0;
        for batch in builder.build().unwrap() {
            let batch = batch.unwrap();
            let paths = batch
                .column(0)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();
            for i in 0..batch.num_rows() {
                assert_eq!(
                    paths.value(i),
                    expected[offset + i]["path"].as_str().unwrap()
                );
            }
            offset += batch.num_rows();
        }
        assert_eq!(offset, expected.len());
    }

    #[cfg(not(feature = "export-parquet"))]
    /// Regression: minimal builds must give an actionable Parquet error.
    #[test]
    fn regression_export_parquet_feature_disabled() {
        assert!(parquet_export(&[], &mut Vec::new())
            .unwrap_err()
            .to_string()
            .contains("export-parquet"));
    }

    /// Regression: a verb must not consume mount arguments, and unsafe manifests must fail closed.
    #[test]
    fn regression_export_index_verb_does_not_steal_positionals() {
        let parsed = crate::parse_args_from([
            "ratarmount",
            "export-index",
            "a.tar",
            "b.tar",
            "-o",
            "rows",
            "--format",
            "jsonl",
        ])
        .unwrap();
        assert_eq!(
            parsed.export_index.unwrap().inputs,
            [Path::new("a.tar"), Path::new("b.tar")]
        );
        assert!(parsed.paths.is_empty());
        let mount = crate::parse_args_from(["ratarmount", "--no-mount", "export-index"]).unwrap();
        assert!(mount.export_index.is_none());
        assert_eq!(mount.paths, [Path::new("export-index")]);
        assert!(
            crate::parse_args_from(["ratarmount", "export-index", "--format", "jsonl"]).is_err()
        );
        assert!(crate::parse_args_from(["ratarmount", "export-index", "a.tar", "--nfs"]).is_err());
        assert!(safe_manifest_path(Path::new("base"), "../escape").is_err());
        assert!(safe_manifest_path(Path::new("base"), "/absolute").is_err());
    }

    /// Regression: factory status banners must not corrupt JSONL/CSV/Parquet stdout.
    #[test]
    fn regression_export_stdout_has_no_index_status_banners() {
        const CHILD: &str = "RATARMOUNT_EXPORT_STDOUT_TEST";
        if std::env::var_os(CHILD).is_some() {
            let mut stdout = cli_stdout().unwrap();
            let temp = tempfile::tempdir().unwrap();
            let input = temp.path().join("input");
            fs::create_dir(&input).unwrap();
            fs::write(input.join("file.txt"), b"payload").unwrap();
            let output = temp.path().join("out");
            let manifest = shard::run(&shard::tests::args(&input, &output, &[])).unwrap();
            let args = ExportArgs {
                inputs: vec![output.join(&manifest.shards[0].name)],
                output: None,
                format: Format::Jsonl,
            };
            super::run(&args, &mut stdout).unwrap();
            std::process::exit(0);
        }
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .env(CHILD, "1")
            .args([
                "export_index::tests::regression_export_stdout_has_no_index_status_banners",
                "--exact",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let stdout = String::from_utf8(result.stdout).unwrap();
        assert!(!stdout.contains("Creating offset dictionary"));
        assert!(!stdout.contains("Successfully loaded"));
        let row: serde_json::Value =
            serde_json::from_str(stdout.lines().find(|l| l.starts_with('{')).unwrap()).unwrap();
        assert_eq!(row["path"], "/file.txt");
        assert!(String::from_utf8_lossy(&result.stderr).contains("Creating offset dictionary"));
    }

    #[cfg(feature = "export-parquet")]
    /// Regression: a buffered output failure must not publish a truncated export.
    #[test]
    fn regression_export_propagates_output_flush_errors() {
        struct FailFlush;
        impl Write for FailFlush {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("injected output flush failure"))
            }
        }
        for format in [Format::Jsonl, Format::Csv, Format::Parquet] {
            assert!(export(&[], format, &mut FailFlush)
                .unwrap_err()
                .to_string()
                .contains("injected output flush failure"));
        }
    }

    /// Regression: SQLite archive payloads must not be mistaken for index sidecars.
    #[test]
    fn regression_export_distinguishes_sqlite_archive_and_sidecar() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("files.sqlar");
        Connection::open(&archive)
            .unwrap()
            .execute_batch("CREATE TABLE sqlar(name TEXT,mode INT,mtime INT,sz INT,data BLOB)")
            .unwrap();
        let parsed = inputs(&args(
            std::slice::from_ref(&archive),
            &temp.path().join("out"),
            "jsonl",
        ))
        .unwrap();
        assert_eq!(parsed[0].archive.as_ref().unwrap(), &archive);
        assert!(parsed[0].index.is_none());
    }

    /// Regression: exporting must never overwrite its input archive, sidecar or manifest.
    #[test]
    fn regression_export_rejects_output_equal_to_input() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        fs::write(input.join("file"), b"data").unwrap();
        let output = temp.path().join("out");
        let manifest = shard::run(&shard::tests::args(&input, &output, &[])).unwrap();
        let index = output.join(manifest.shards[0].index.as_ref().unwrap());
        let bytes = fs::read(&index).unwrap();
        assert!(run(&args(std::slice::from_ref(&index), &index, "jsonl")).is_err());
        assert_eq!(fs::read(&index).unwrap(), bytes);
        let archive = output.join(&manifest.shards[0].name);
        assert!(run(&args(&[archive], &index, "jsonl")).is_err());
        assert_eq!(fs::read(&index).unwrap(), bytes);
    }

    /// Regression (R11-S7, #151): export-index read its internal inputs (the
    /// shards.json manifest, the SQLite magic of each sidecar, the zstd magic
    /// of each archive) with raw `File`s; the index a session holds open lost
    /// its lock. Every managed close keeps a lock taken on the file.
    #[cfg(unix)]
    #[test]
    fn regression_export_index_input_reads_keep_index_lock() {
        use ratarmount_index::managed_read::{
            lock_probe::other_process_sees_lock, with_close_probes,
        };
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        shard::tests::dataset(&input);
        let output = temp.path().join("shards");
        let manifest = shard::run(&shard::tests::args(&input, &output, &[])).unwrap();
        let index_path = output.join(manifest.shards[0].index.as_ref().unwrap());
        let holder = Connection::open(&index_path).unwrap();
        holder.execute_batch("BEGIN").unwrap();
        let _: i64 = holder
            .query_row("SELECT count(*) FROM files", [], |r| r.get(0))
            .unwrap();
        assert!(other_process_sees_lock(&index_path));
        let target = temp.path().join("rows.jsonl");
        let (got, probes) = with_close_probes(
            |_| true,
            || {
                run(&args(
                    &[output.join("shards.json"), index_path.clone()],
                    &target,
                    "jsonl",
                ))
            },
        );
        got.unwrap();
        assert!(!probes.is_empty());
        assert!(probes.iter().all(|(_, kept)| *kept), "{probes:?}");
        for what in ["shards.json", ".index.sqlite"] {
            assert!(
                probes
                    .iter()
                    .any(|(p, _)| p.to_string_lossy().ends_with(what)),
                "{what} read through a managed reader: {probes:?}"
            );
        }
        assert!(other_process_sees_lock(&index_path), "session lock kept");
        drop(holder);
        // The frame map's zstd magic probe (an index without zstd blocks);
        // the frame scan after it is a residual format reader (#196).
        let archive = output.join(&manifest.shards[0].name);
        let empty = SqliteIndex::create_writable(None).unwrap();
        let (frames, probes) = with_close_probes(|_| true, || frame_map(&empty, Some(&archive)));
        assert!(!frames.unwrap().is_empty());
        assert_eq!(probes.len(), 1, "{probes:?}");
        assert!(probes[0].1, "magic probe kept the lock: {probes:?}");
    }
}
