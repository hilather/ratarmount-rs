//! Deterministic dataset sharding, independent of the mount CLI.

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use clap::{ArgAction, Parser, ValueEnum};
use ratarmount_compress::{ZstdFrameWriter, DEFAULT_REPACK_FRAME_SIZE};
use ratarmount_session::{IndexJob, IndexPolicy, OpenRequest, Recreate, SourceSpec};
use serde::{Deserialize, Serialize};

pub(super) type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(super) enum Codec {
    Zstd,
    None,
}

#[derive(Clone, Debug, Parser, Serialize)]
#[command(
    name = "ratarmount shard",
    about = "Pack a dataset into reproducible indexed TAR shards"
)]
pub(super) struct ShardArgs {
    #[serde(skip)]
    pub input_dir: PathBuf,
    #[arg(short = 'o', long)]
    #[serde(skip)]
    pub output: PathBuf,
    #[arg(long, default_value = "shard", value_parser = parse_prefix)]
    prefix: String,
    /// Maximum encoded shard bytes; an oversized sample gets its own shard.
    #[arg(long, default_value = "1G", value_parser = parse_size)]
    size: u64,
    #[arg(long, default_value = "0", allow_hyphen_values = true)]
    mtime: i64,
    #[arg(long)]
    keep_metadata: bool,
    /// Keep basename.{jpg,json,...} together. Use --group-by-key=false to disable.
    #[arg(long, default_value_t = true, action = ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    group_by_key: bool,
    #[arg(long, value_parser = parse_frame_size, conflicts_with = "frame_per_sample")]
    frame_size: Option<u64>,
    #[arg(long)]
    frame_per_sample: bool,
    #[arg(long, default_value_t = 3, allow_hyphen_values = true, value_parser = clap::value_parser!(i32).range(-7..=22))]
    level: i32,
    /// Align data with a PAX comment; must be a multiple of 512.
    #[arg(long, value_parser = parse_alignment)]
    align_members: Option<u64>,
    #[arg(long, value_enum, default_value = "zstd")]
    codec: Codec,
    #[arg(long)]
    no_index: bool,
    #[arg(short = 'j', default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    #[serde(skip)]
    jobs: u32,
}

fn parse_size(s: &str) -> std::result::Result<u64, String> {
    let n = ratarmount_fuse::parse_byte_size(s)?;
    if n == 0 {
        return Err("size must be positive".into());
    }
    Ok(n)
}
fn parse_frame_size(s: &str) -> std::result::Result<u64, String> {
    let n = parse_size(s)?;
    if n > u64::from(u32::MAX) {
        return Err("frame size must fit u32".into());
    }
    Ok(n)
}
fn parse_alignment(s: &str) -> std::result::Result<u64, String> {
    let n = parse_size(s)?;
    if n % 512 != 0 || n > 16 * 1024 * 1024 {
        return Err("alignment must be a multiple of 512, at most 16 MiB".into());
    }
    Ok(n)
}
fn parse_prefix(s: &str) -> std::result::Result<String, String> {
    if s.is_empty() || s == "." || s == ".." || s.contains(['/', '\\']) {
        return Err("prefix must be a nonempty filename component".into());
    }
    Ok(s.to_owned())
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Manifest {
    pub format: String,
    pub shards: Vec<ShardInfo>,
    pub total_members: u64,
    /// Sum of encoded archive sizes (not sidecars).
    pub total_bytes: u64,
    pub options: serde_json::Value,
}
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ShardInfo {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub members: u64,
    pub samples: u64,
    pub first_key: String,
    pub last_key: String,
    pub index: Option<String>,
    pub index_sha256: Option<String>,
}

#[derive(Debug)]
struct Member {
    path: String,
    disk: PathBuf,
    meta: Metadata,
    link: Option<String>,
}
impl Member {
    fn size(&self) -> u64 {
        if self.link.is_some() {
            0
        } else {
            self.meta.len()
        }
    }
}
#[derive(Debug)]
struct Sample {
    key: String,
    members: Vec<Member>,
}
struct Artifact {
    file: tempfile::NamedTempFile,
    start: usize,
    end: usize,
}

fn sample_key(path: &str) -> String {
    let base = path.rfind('/').map_or(0, |i| i + 1);
    let dot = path[base..].find('.').map_or(path.len(), |i| base + i);
    path[..dot].to_owned()
}

fn collect(root: &Path, dir: &Path, members: &mut Vec<Member>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let disk = entry?.path();
        let meta = fs::symlink_metadata(&disk)?;
        if meta.is_dir() {
            collect(root, &disk, members)?;
            continue;
        }
        if !meta.is_file() && !meta.file_type().is_symlink() {
            return Err(format!("unsupported dataset file: {}", disk.display()).into());
        }
        let path = disk
            .strip_prefix(root)?
            .to_str()
            .ok_or("dataset paths must be UTF-8")?
            .to_owned();
        let link = if meta.file_type().is_symlink() {
            Some(
                fs::read_link(&disk)?
                    .to_str()
                    .ok_or("symlink targets must be UTF-8")?
                    .to_owned(),
            )
        } else {
            None
        };
        members.push(Member {
            path,
            disk,
            meta,
            link,
        });
    }
    Ok(())
}

// PAX record lengths include their own decimal length and trailing newline.
fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!(" {key}={value}\n");
    let mut n = body.len() + 1;
    loop {
        let next = body.len() + n.to_string().len();
        if n == next {
            return format!("{n}{body}").into_bytes();
        }
        n = next;
    }
}
fn round_block(n: u64) -> u64 {
    n.div_ceil(512) * 512
}
fn header(name: &[u8], size: u64, kind: u8, mode: u32, uid: u32, gid: u32) -> [u8; 512] {
    let mut h = [0; 512];
    let name_len = name.len().min(100);
    h[..name_len].copy_from_slice(&name[..name_len]);
    for (start, len, value) in [
        (100, 8, u64::from(mode & 0o7777)),
        (108, 8, u64::from(uid)),
        (116, 8, u64::from(gid)),
        (124, 12, size),
        (136, 12, 0),
    ] {
        let text = format!("{:0width$o}", value, width = len - 1);
        if text.len() < len {
            h[start..start + len - 1].copy_from_slice(text.as_bytes());
        } else {
            // Positive GNU base-256 keeps even simple header scanners in sync.
            let count = len.min(8);
            h[start + len - count..start + len].copy_from_slice(&value.to_be_bytes()[8 - count..]);
            h[start] |= 0x80;
        }
    }
    h[148..156].fill(b' ');
    h[156] = kind;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

fn member_headers(member: &Member, offset: u64, args: &ShardArgs) -> Result<Vec<u8>> {
    let mut pax = pax_record("path", &member.path);
    pax.extend(pax_record("size", &member.size().to_string()));
    let (uid, gid, mode, mtime) = if args.keep_metadata {
        let ns =
            i128::from(member.meta.mtime()) * 1_000_000_000 + i128::from(member.meta.mtime_nsec());
        let sign = if ns < 0 { "-" } else { "" };
        (
            member.meta.uid(),
            member.meta.gid(),
            member.meta.mode(),
            format!(
                "{sign}{}.{:09}",
                ns.abs() / 1_000_000_000,
                ns.abs() % 1_000_000_000
            ),
        )
    } else {
        (
            0,
            0,
            if member.link.is_some() { 0o777 } else { 0o644 },
            args.mtime.to_string(),
        )
    };
    pax.extend(pax_record("uid", &uid.to_string()));
    pax.extend(pax_record("gid", &gid.to_string()));
    pax.extend(pax_record("mtime", &mtime));
    if let Some(link) = &member.link {
        pax.extend(pax_record("linkpath", link));
    }
    if let Some(align) = args.align_members {
        let min_len = pax.len() as u64 + pax_record("comment", "").len() as u64;
        let min_data = offset
            .checked_add(1024 + round_block(min_len))
            .ok_or("TAR offset overflow")?;
        let data = min_data
            .div_ceil(align)
            .checked_mul(align)
            .ok_or("TAR alignment overflow")?;
        let target_body = data - offset - 1024;
        // Pick a valid record whose padded size fills exactly the chosen PAX span.
        let mut padding = (target_body - pax.len() as u64) as usize;
        loop {
            let comment = pax_record("comment", &" ".repeat(padding));
            if round_block((pax.len() + comment.len()) as u64) == target_body {
                pax.extend(comment);
                break;
            }
            padding -= 1;
        }
    }
    let mut bytes = Vec::with_capacity(1024 + round_block(pax.len() as u64) as usize);
    bytes.extend(header(
        b"PaxHeaders/member",
        pax.len() as u64,
        b'x',
        0o644,
        0,
        0,
    ));
    bytes.extend(&pax);
    bytes.resize(512 + round_block(pax.len() as u64) as usize, 0);
    // Duplicate size and IDs in the raw header for readers that probe without PAX.
    bytes.extend(header(
        b"member",
        member.size(),
        if member.link.is_some() { b'2' } else { b'0' },
        mode,
        uid,
        gid,
    ));
    Ok(bytes)
}

fn sample_end(sample: &Sample, mut offset: u64, args: &ShardArgs) -> Result<u64> {
    for member in &sample.members {
        let headers = member_headers(member, offset, args)?;
        offset = offset
            .checked_add(headers.len() as u64)
            .and_then(|n| n.checked_add(round_block(member.size())))
            .ok_or("TAR size overflow")?;
    }
    Ok(offset)
}

fn build(
    samples: &[Sample],
    start: usize,
    end: usize,
    stage: &Path,
    args: &ShardArgs,
) -> Result<Vec<Artifact>> {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0091-M01","item":"ratarmount::shard::build","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let mut tar = tempfile::tempfile_in(stage)?;
    let mut boundaries = Vec::new();
    {
        let mut out = BufWriter::new(&mut tar);
        let mut offset = 0;
        for sample in &samples[start..end] {
            for member in &sample.members {
                let headers = member_headers(member, offset, args)?;
                out.write_all(&headers)?;
                if member.link.is_none() {
                    let mut file = {
                        #[expect(
                            clippy::disallowed_types,
                            reason = r###"internal-read:v1 {"id":"IR-B0092-T01","item":"ratarmount::shard::build","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-type-support","reason":"Builder type support: Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
                        )]
                        #[expect(
                            clippy::disallowed_methods,
                            reason = r###"internal-read:v1 {"id":"IR-B0092-M01","item":"ratarmount::shard::build","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"output-owner","baseline_reason":"Preserve this reviewed output acquisition and its existing permissions."}"###
                        )]
                        let mut __inventory_value_0 = fs::OpenOptions::new();
                        #[expect(
                            clippy::disallowed_methods,
                            reason = r###"internal-read:v1 {"id":"IR-B0092-M02","item":"ratarmount::shard::build","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
                        )]
                        let __inventory_value_1 = __inventory_value_0
                            .read(true)
                            .custom_flags(libc::O_NOFOLLOW)
                            .open(&member.disk);
                        __inventory_value_1
                    }?;
                    let meta = file.metadata()?;
                    if meta.ino() != member.meta.ino()
                        || meta.dev() != member.meta.dev()
                        || meta.len() != member.size()
                        || meta.mtime() != member.meta.mtime()
                        || meta.mtime_nsec() != member.meta.mtime_nsec()
                    {
                        return Err(
                            format!("dataset file changed: {}", member.disk.display()).into()
                        );
                    }
                    if io::copy(&mut (&mut file).take(member.size()), &mut out)? != member.size() {
                        return Err(
                            format!("dataset file truncated: {}", member.disk.display()).into()
                        );
                    }
                    io::copy(
                        &mut io::repeat(0).take(round_block(member.size()) - member.size()),
                        &mut out,
                    )?;
                }
                offset += headers.len() as u64 + round_block(member.size());
            }
            boundaries.push(offset);
        }
        out.write_all(&[0; 1024])?;
        out.flush()?;
    }
    // Keep EOF with the final sample, so frame-per-sample has no extra EOF frame.
    *boundaries.last_mut().ok_or("cannot build an empty shard")? += 1024;
    tar.seek(SeekFrom::Start(0))?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0093-M01","item":"ratarmount::shard::build","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let mut file = tempfile::NamedTempFile::new_in(stage)?;
    if args.codec == Codec::None {
        io::copy(&mut tar, &mut file)?;
    } else {
        let mut writer = ZstdFrameWriter::new(BufWriter::new(file.as_file_mut()), args.level);
        let mut previous = 0;
        let len = tar.metadata()?.len();
        let ends = if args.frame_per_sample {
            boundaries
        } else {
            let step = args.frame_size.unwrap_or(DEFAULT_REPACK_FRAME_SIZE);
            (1..=len.div_ceil(step))
                .map(|i| (i * step).min(len))
                .collect()
        };
        for end in ends {
            writer.write_frame((&mut tar).take(end - previous))?;
            previous = end;
        }
        writer.finish()?;
    }
    file.flush()?;
    if file.as_file().metadata()?.len() > args.size && end - start > 1 {
        drop((file, tar));
        let mid = start + (end - start) / 2;
        let mut left = build(samples, start, mid, stage, args)?;
        left.extend(build(samples, mid, end, stage, args)?);
        return Ok(left);
    }
    Ok(vec![Artifact { file, start, end }])
}

pub(super) fn index_request(archive: &Path, index: &Path) -> OpenRequest {
    OpenRequest {
        source: SourceSpec::Path(archive.to_owned()),
        index: IndexPolicy::Explicit,
        explicit_index: Some(index.to_owned()),
        extra_dirs: Vec::new(),
        password: None,
        recursive: false,
        recursion_depth: None,
        parallelization: Default::default(),
        recreate: Recreate::IfInvalid,
    }
}
pub(super) fn sha256(path: &Path) -> Result<String> {
    // Managed (#151): an artifact may be an index open in this process.
    Ok({
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0094-M01","item":"ratarmount::shard::sha256","disposition":"managed-read","regression":"regression_shard_artifact_hash_keeps_aliased_database_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let __inventory_value_0 = ratarmount_index::managed_read::sha256_hex(path);
        __inventory_value_0
    }?)
}

fn parallel_map<T: Sync, U: Send>(
    items: &[T],
    jobs: u32,
    f: impl Fn(usize, &T) -> Result<U> + Sync,
) -> Result<Vec<U>> {
    let next = AtomicUsize::new(0);
    let mut results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..(jobs as usize).min(items.len()))
            .map(|_| {
                let f = &f;
                let next = &next;
                scope.spawn(move || {
                    let mut done = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= items.len() {
                            break;
                        }
                        done.push((i, f(i, &items[i])));
                    }
                    done
                })
            })
            .collect();
        let mut results = Vec::new();
        for handle in handles {
            results.extend(handle.join().map_err(|_| "shard worker panicked")?);
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(results)
    })?;
    results.sort_by_key(|(i, _)| *i);
    results.into_iter().map(|(_, result)| result).collect()
}

pub(super) fn run(args: &ShardArgs) -> Result<Manifest> {
    let root = fs::canonicalize(&args.input_dir)?;
    if !root.is_dir() {
        return Err("input must be a directory".into());
    }
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-E0141-M01","item":"ratarmount::shard::run","disposition":"output-owner","category":"shard-output-directory","reason":"Create the caller-selected shard output directory before validating its relation to the input tree.","creation":{"policy":"recursive-directory","basis":"The sharding command owns output creation, rejects output inside the canonical input and refuses an existing shards.json; default modes remain unchanged."}}"###
    )]
    fs::create_dir_all(&args.output)?;
    let output = fs::canonicalize(&args.output)?;
    if output.starts_with(&root) {
        return Err("output directory must be outside the input tree".into());
    }
    if output.join("shards.json").exists() {
        return Err("shards.json already exists".into());
    }
    let mut members = Vec::new();
    collect(&root, &root, &mut members)?;
    members.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let mut groups: BTreeMap<String, Vec<Member>> = BTreeMap::new();
    for member in members {
        let key = if args.group_by_key {
            sample_key(&member.path)
        } else {
            member.path.clone()
        };
        groups.entry(key).or_default().push(member);
    }
    let samples: Vec<_> = groups
        .into_iter()
        .map(|(key, members)| Sample { key, members })
        .collect();
    let mut plans = Vec::new();
    let (mut start, mut offset) = (0, 0);
    for (i, sample) in samples.iter().enumerate() {
        let end = sample_end(sample, offset, args)?;
        if end.saturating_add(1024) > args.size && i > start {
            plans.push((start, i));
            start = i;
            offset = sample_end(sample, 0, args)?;
        } else {
            offset = end;
        }
    }
    if start < samples.len() {
        plans.push((start, samples.len()));
    }
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0095-M01","item":"ratarmount::shard::run","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let stage = tempfile::tempdir_in(&output)?;
    let artifacts: Vec<_> = parallel_map(&plans, args.jobs, |_, &(start, end)| {
        build(&samples, start, end, stage.path(), args)
    })?
    .into_iter()
    .flatten()
    .collect();
    let extension = if args.codec == Codec::Zstd {
        "tar.zst"
    } else {
        "tar"
    };
    let names: Vec<_> = (0..artifacts.len())
        .map(|i| format!("{}-{i:06}.{extension}", args.prefix))
        .collect();
    for name in &names {
        if output.join(name).symlink_metadata().is_ok()
            || output
                .join(format!("{name}.index.sqlite"))
                .symlink_metadata()
                .is_ok()
        {
            return Err(format!("output already exists: {name}").into());
        }
    }
    // Index at the staged final basename, then publish the completed set.
    let entries = parallel_map(&artifacts, args.jobs, |i, artifact| {
        let name = &names[i];
        let path = stage.path().join(name);
        fs::rename(artifact.file.path(), &path)?;
        let time = if args.mtime >= 0 {
            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(args.mtime as u64))
        } else {
            SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(args.mtime.unsigned_abs()))
        }
        .ok_or("mtime out of range")?;
        {
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0096-M01","item":"ratarmount::shard::run","disposition":"support","mode_policy":"unchanged-from-e6ca64e","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."},"supports_disposition":"output-owner","baseline_reason":"Preserve this reviewed output acquisition and its existing permissions."}"###)]
let mut __inventory_value_0 = File::options();
#[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0096-M02","item":"ratarmount::shard::run","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###)]
let __inventory_value_1 = __inventory_value_0
            .write(true)
            .open(&path);
__inventory_value_1
}?
            .set_times(fs::FileTimes::new().set_modified(time))?;
        let index = (!args.no_index).then(|| format!("{name}.index.sqlite"));
        let index_sha256 = if let Some(index) = &index {
            let index_path = stage.path().join(index);
            IndexJob::run(index_request(&path, &index_path), Default::default())?;
            // Compression maps can still live in the staged path's WAL. Publish
            // and hash a self-contained SQLite body, as --publish-index does.
            ratarmount_index::SqliteIndex::open_writable(&index_path)?.wal_checkpoint_truncate()?;
            Some(sha256(&index_path)?)
        } else {
            None
        };
        ratarmount_core::eprintln!("shard {name}: {} samples", artifact.end - artifact.start);
        Ok(ShardInfo {
            name: name.clone(),
            size: fs::metadata(&path)?.len(),
            sha256: sha256(&path)?,
            members: samples[artifact.start..artifact.end]
                .iter()
                .map(|s| s.members.len() as u64)
                .sum(),
            samples: (artifact.end - artifact.start) as u64,
            first_key: samples[artifact.start].key.clone(),
            last_key: samples[artifact.end - 1].key.clone(),
            index,
            index_sha256,
        })
    })?;
    let manifest = Manifest {
        format: "ratarmount-shards-v1".into(),
        total_members: entries.iter().map(|e| e.members).sum(),
        total_bytes: entries.iter().map(|e| e.size).sum(),
        shards: entries,
        options: serde_json::to_value(args)?,
    };
    for entry in &manifest.shards {
        fs::hard_link(stage.path().join(&entry.name), output.join(&entry.name))?;
        if let Some(index) = &entry.index {
            fs::hard_link(stage.path().join(index), output.join(index))?;
        }
    }
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0097-M01","item":"ratarmount::shard::run","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let mut json = tempfile::NamedTempFile::new_in(&output)?;
    serde_json::to_writer_pretty(&mut json, &manifest)?;
    json.write_all(b"\n")?;
    json.persist_noclobber(output.join("shards.json"))?;
    Ok(manifest)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use ratarmount_session::{ReadRequest, Session};

    pub fn dataset(root: &Path) -> BTreeMap<String, Vec<u8>> {
        fs::create_dir_all(root.join("dir")).unwrap();
        let mut expected = BTreeMap::new();
        let mut seed = 17u64;
        for i in 0..6 {
            for (ext, size) in [("jpg", 1800), ("json", 900)] {
                let bytes = random_bytes(&mut seed, size);
                let name = format!("dir/{i:04}.{ext}");
                fs::write(root.join(&name), &bytes).unwrap();
                expected.insert(name, bytes);
            }
        }
        let long_dir = "long".repeat(35);
        fs::create_dir(root.join(&long_dir)).unwrap();
        let name = format!("{long_dir}/{}.txt", "name".repeat(35));
        fs::write(root.join(&name), b"long name bytes").unwrap();
        expected.insert(name, b"long name bytes".to_vec());
        let bytes = random_bytes(&mut seed, 40_000);
        fs::write(root.join("huge.bin"), &bytes).unwrap();
        expected.insert("huge.bin".into(), bytes);
        std::os::unix::fs::symlink("dir/0000.jpg", root.join("link.jpg")).unwrap();
        expected
    }
    fn random_bytes(seed: &mut u64, n: usize) -> Vec<u8> {
        (0..n)
            .map(|_| {
                *seed ^= *seed << 13;
                *seed ^= *seed >> 7;
                *seed ^= *seed << 17;
                *seed as u8
            })
            .collect()
    }
    pub fn args(input: &Path, output: &Path, extra: &[&str]) -> ShardArgs {
        ShardArgs::try_parse_from(
            [
                "ratarmount shard".as_ref(),
                input.as_os_str(),
                "-o".as_ref(),
                output.as_os_str(),
                "--size".as_ref(),
                "15K".as_ref(),
            ]
            .into_iter()
            .chain(extra.iter().map(std::ffi::OsStr::new)),
        )
        .unwrap()
    }
    pub fn session(archive: &Path) -> Session {
        let index = archive.with_file_name(format!(
            "{}.index.sqlite",
            archive.file_name().unwrap().to_str().unwrap()
        ));
        let mut req = index_request(archive, &index);
        req.recreate = Recreate::Never;
        Session::open(req).unwrap()
    }

    /// Regression: sharding must keep groups intact, preserve bytes and long names,
    /// and emit exactly one independent frame per sample, including TAR EOF.
    #[test]
    fn regression_shards_keep_samples_and_seekable_frames() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        let expected = dataset(&input);
        let output = temp.path().join("out");
        let manifest = run(&args(&input, &output, &["--frame-per-sample"])).unwrap();
        assert_eq!(manifest.format, "ratarmount-shards-v1");
        assert!(manifest.shards.len() >= 3);
        assert_eq!(manifest.total_members, expected.len() as u64 + 1);
        assert_eq!(
            manifest.total_bytes,
            manifest.shards.iter().map(|s| s.size).sum::<u64>()
        );
        let mut found = BTreeMap::new();
        let mut keys = BTreeMap::new();
        let mut symlinks = 0;
        let disk: Manifest =
            serde_json::from_reader(File::open(output.join("shards.json")).unwrap()).unwrap();
        assert_eq!(disk.total_members, manifest.total_members);
        for shard in &manifest.shards {
            assert!(shard.size <= 15 * 1024 || shard.samples == 1);
            assert_eq!(shard.sha256, sha256(&output.join(&shard.name)).unwrap());
            assert_eq!(
                shard.index_sha256.as_ref().unwrap(),
                &sha256(&output.join(shard.index.as_ref().unwrap())).unwrap()
            );
            let frames =
                ratarmount_compress::scan_zstd_frames_path(&output.join(&shard.name)).unwrap();
            assert!(frames.seek_table.is_some());
            assert_eq!(frames.frames.len() as u64, shard.samples);
            let mounted = session(&output.join(&shard.name));
            let conn =
                rusqlite::Connection::open(output.join(shard.index.as_ref().unwrap())).unwrap();
            let mut query = conn.prepare("SELECT path,name,linkname,mode,mtime,uid,gid,offset FROM files WHERE COALESCE(isgenerated,0)=0 ORDER BY offset").unwrap();
            let mut rows = query.query([]).unwrap();
            let mut local_keys = Vec::new();
            let mut key_frames = BTreeMap::new();
            let mut key_names: BTreeMap<String, Vec<String>> = BTreeMap::new();
            while let Some(row) = rows.next().unwrap() {
                let name = format!(
                    "{}/{}",
                    row.get::<_, String>(0).unwrap().trim_start_matches('/'),
                    row.get::<_, String>(1).unwrap()
                )
                .trim_start_matches('/')
                .to_string();
                let key = sample_key(&name);
                if let Some(previous) = keys.insert(key.clone(), shard.name.clone()) {
                    assert_eq!(previous, shard.name);
                }
                let offset: u64 = row.get(7).unwrap();
                let frame = frames
                    .frames
                    .partition_point(|f| f.uncompressed_offset <= offset)
                    - 1;
                if let Some(previous) = key_frames.insert(key.clone(), frame) {
                    assert_eq!(previous, frame);
                }
                key_names.entry(key.clone()).or_default().push(name.clone());
                local_keys.push(key);
                assert_eq!(row.get::<_, f64>(4).unwrap(), 0.0);
                assert_eq!(row.get::<_, u32>(5).unwrap(), 0);
                assert_eq!(row.get::<_, u32>(6).unwrap(), 0);
                if name == "link.jpg" {
                    assert_eq!(row.get::<_, String>(2).unwrap(), "dir/0000.jpg");
                    symlinks += 1;
                    continue;
                }
                let mut bytes = Vec::new();
                mounted
                    .read_range(ReadRequest {
                        path: name.clone(),
                        offset: 0,
                        max_len: 100_000,
                    })
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert!(found.insert(name.clone(), bytes).is_none());
                assert_eq!(&found[&name], &expected[&name]);
            }
            assert_eq!(key_frames.len() as u64, shard.samples);
            for names in key_names.values() {
                assert!(names.windows(2).all(|p| p[0] <= p[1]));
            }
            let mut sorted = local_keys.clone();
            sorted.sort();
            assert_eq!(local_keys, sorted);
            assert_eq!(local_keys.first().unwrap(), &shard.first_key);
            assert_eq!(local_keys.last().unwrap(), &shard.last_key);
        }
        assert_eq!(found, expected);
        assert_eq!(symlinks, 1);
        let huge = manifest
            .shards
            .iter()
            .find(|s| s.first_key == "huge")
            .unwrap();
        assert_eq!(huge.samples, 1);
        assert!(huge.size > 15 * 1024);
    }

    /// Regression: scheduling must not change archive bytes, sidecars or manifests.
    #[test]
    fn regression_shards_identical_across_worker_counts() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        dataset(&input);
        for mode in [vec!["--frame-per-sample"], vec!["--frame-size", "1K"]] {
            let one = temp.path().join(format!("one{}", mode.len()));
            let four = temp.path().join(format!("four{}", mode.len()));
            let a = run(&args(&input, &one, &mode)).unwrap();
            let mut other = mode.clone();
            other.extend(["-j", "4"]);
            let b = run(&args(&input, &four, &other)).unwrap();
            assert_eq!(a.shards.len(), b.shards.len());
            for shard in &a.shards {
                if mode.len() == 2 {
                    let map =
                        ratarmount_compress::scan_zstd_frames_path(&one.join(&shard.name)).unwrap();
                    assert!(map.frames.len() > 1);
                    assert!(map.frames.iter().all(|f| f.uncompressed_size <= 1024));
                }
                assert_eq!(
                    fs::read(one.join(&shard.name)).unwrap(),
                    fs::read(four.join(&shard.name)).unwrap()
                );
            }
            assert_eq!(
                fs::read(one.join("shards.json")).unwrap(),
                fs::read(four.join("shards.json")).unwrap()
            );
        }
    }

    /// Regression: uncompressed TAR data extents must be block-aligned even with PAX long names.
    #[test]
    fn regression_shards_align_member_data_extents() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        let expected = dataset(&input);
        let output = temp.path().join("out");
        let manifest = run(&args(
            &input,
            &output,
            &["--codec", "none", "--align-members", "4096"],
        ))
        .unwrap();
        let mut count = 0;
        for shard in &manifest.shards {
            assert!(shard.name.ends_with(".tar"));
            let conn =
                rusqlite::Connection::open(output.join(shard.index.as_ref().unwrap())).unwrap();
            let unaligned: u64 = conn.query_row("SELECT COUNT(*) FROM files WHERE COALESCE(isgenerated,0)=0 AND offset % 4096 != 0", [], |r| r.get(0)).unwrap();
            assert_eq!(unaligned, 0);
            let session = session(&output.join(&shard.name));
            for (name, bytes) in &expected {
                if session.lookup(name).unwrap().is_none() {
                    continue;
                }
                let extent = session.member_extent(name).unwrap().unwrap();
                assert_eq!(extent.offset % 4096, 0, "{name}");
                assert_eq!(extent.len, bytes.len() as u64);
                count += 1;
                let mut actual = Vec::new();
                session
                    .read_range(ReadRequest {
                        path: name.clone(),
                        offset: 0,
                        max_len: extent.len,
                    })
                    .unwrap()
                    .read_to_end(&mut actual)
                    .unwrap();
                assert_eq!(&actual, bytes);
            }
        }
        assert_eq!(count, expected.len());
    }

    /// Regression: metadata mode and disabled grouping must not silently use deterministic defaults.
    #[test]
    fn regression_shards_preserve_metadata_and_no_index() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        for name in ["x.json", "x.jpg"] {
            let path = input.join(name);
            fs::write(&path, b"payload").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(
                    fs::FileTimes::new()
                        .set_modified(SystemTime::UNIX_EPOCH + Duration::new(123, 456_000_000)),
                )
                .unwrap();
        }
        let output = temp.path().join("out");
        let manifest = run(&args(
            &input,
            &output,
            &[
                "--keep-metadata",
                "--group-by-key=false",
                "--frame-per-sample",
                "--no-index",
            ],
        ))
        .unwrap();
        assert_eq!(manifest.shards[0].samples, 2);
        assert!(manifest.shards[0].index.is_none());
        assert!(!output
            .join(format!("{}.index.sqlite", manifest.shards[0].name))
            .exists());
        let archive = output.join(&manifest.shards[0].name);
        let req = index_request(&archive, &output.join("verify.sqlite"));
        drop(Session::open(req).unwrap());
        let conn = rusqlite::Connection::open(output.join("verify.sqlite")).unwrap();
        let (mode, mtime, uid, gid): (i64, f64, u32, u32) = conn
            .query_row(
                "SELECT mode,mtime,uid,gid FROM files WHERE name='x.jpg'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        let metadata = fs::metadata(input.join("x.jpg")).unwrap();
        assert_eq!(uid, metadata.uid());
        assert_eq!(gid, metadata.gid());
        assert_eq!(mode & 0o777, 0o600);
        assert!((mtime - 123.456).abs() < 1e-6);
    }

    /// Regression: malformed options must fail before creating outputs or swallowing mount positionals.
    #[test]
    fn regression_shard_verb_does_not_steal_positionals() {
        let parsed = crate::parse_args_from([
            "ratarmount",
            "shard",
            "input",
            "-o",
            "output",
            "--group-by-key",
        ])
        .unwrap();
        assert_eq!(parsed.shard.unwrap().input_dir, Path::new("input"));
        assert!(parsed.paths.is_empty());
        let before = crate::parse_args_from([
            "ratarmount",
            "shard",
            "--group-by-key",
            "input",
            "-o",
            "output",
        ])
        .unwrap();
        assert_eq!(before.shard.unwrap().input_dir, Path::new("input"));
        let parsed = crate::parse_args_from(["ratarmount", "--no-mount", "shard"]).unwrap();
        assert!(parsed.shard.is_none());
        assert_eq!(parsed.paths, [Path::new("shard")]);
        for tail in [
            vec!["--align-members", "1000"],
            vec!["-j", "0"],
            vec!["--prefix", "../escape"],
            vec!["--size", "0"],
            vec!["--frame-size", "8M", "--frame-per-sample"],
            vec!["mountpoint"],
        ] {
            assert!(crate::parse_args_from(
                ["ratarmount", "shard", "input", "-o", "output"]
                    .into_iter()
                    .chain(tail)
            )
            .is_err());
        }
        assert!(crate::parse_args_from(["ratarmount", "shard", "input"]).is_err());
        assert!(
            crate::parse_args_from(["ratarmount", "shard", "input", "-o", "out", "--nfs"]).is_err()
        );
    }

    /// Regression: empty datasets still need a valid, zero-count completion manifest.
    #[test]
    fn regression_shards_empty_dataset_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        let output = temp.path().join("out");
        let manifest = run(&args(&input, &output, &[])).unwrap();
        assert_eq!(manifest.total_members, 0);
        assert_eq!(manifest.total_bytes, 0);
        assert!(manifest.shards.is_empty());
        assert!(output.join("shards.json").is_file());
        assert_eq!(fs::read_dir(output).unwrap().count(), 1);
        assert_eq!(
            sample_key("dir.with.dots/0001.caption.txt"),
            "dir.with.dots/0001"
        );
        assert_eq!(sample_key("dir/0001"), "dir/0001");
    }

    /// Regression: nested output and existing shard files must never be packed or overwritten.
    #[test]
    fn regression_shards_reject_recursive_output_and_existing_files() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input");
        fs::create_dir(&input).unwrap();
        fs::write(input.join("file"), b"payload").unwrap();
        assert!(run(&args(&input, &input.join("out"), &[])).is_err());
        fs::remove_dir(input.join("out")).unwrap();
        let output = temp.path().join("out");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("shard-000000.tar.zst"), b"original").unwrap();
        assert!(run(&args(&input, &output, &[])).is_err());
        assert_eq!(
            fs::read(output.join("shard-000000.tar.zst")).unwrap(),
            b"original"
        );
        assert!(!output.join("shards.json").exists());
    }

    /// Regression: (R11-S7, #151): artifact SHA-256 opened the file raw; an
    /// artifact that is another name of a database open in this process lost
    /// its lock.
    #[cfg(unix)]
    #[test]
    fn regression_shard_artifact_hash_keeps_aliased_database_lock() {
        use ratarmount_index::managed_read::lock_probe::other_process_sees_lock;
        use sha2::{Digest, Sha256};
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("a.tar.index.sqlite");
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch("CREATE TABLE t(x BLOB); INSERT INTO t VALUES (randomblob(70000));")
            .unwrap();
        drop(c);
        let want = format!("{:x}", Sha256::digest(fs::read(&db).unwrap()));
        let alias = temp.path().join("alias");
        fs::hard_link(&db, &alias).unwrap();
        let holder = rusqlite::Connection::open(&db).unwrap();
        holder.execute_batch("BEGIN").unwrap();
        let _: i64 = holder
            .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert!(other_process_sees_lock(&db));
        assert_eq!(sha256(&alias).unwrap(), want);
        assert!(other_process_sees_lock(&db), "lock kept");
        drop(holder);
    }
}
