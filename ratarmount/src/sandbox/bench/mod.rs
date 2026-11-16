//! Linux-only validation, scheduling and graded native lifecycle.

mod io;
mod manifest;
mod record;
mod run;
mod runtime;
mod schedule;
mod source;
mod summarize;

use clap::{ArgGroup, Args};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
#[command(
    args_conflicts_with_subcommands = true, subcommand_negates_reqs = true,
    group(ArgGroup::new("mode").required(true).multiple(false).args(["validate_only", "dry_run", "out"])),
    after_help = "Example: ratarmount sandbox bench --manifest tasks.json --validate-only\nExample: ratarmount sandbox bench --manifest tasks.json --dry-run --jobs 1\nExample: ratarmount sandbox bench summarize results/batch\n\nRequires Linux. Structural validation does not establish external qualification.\nDry-run emits a JSONL schedule without execution or file creation.\nInherited `--socket` is rejected; bench owns its supervisor.\n\nExit status:\n  0  Structurally valid (draft pins allowed unless --require-pins); schedule admitted if dry-run; native execution: batch complete and every run passed (stub batches are fixtures).\n  1  Operational/reporting failure; failed or blocked runs; interrupted or incomplete batch.\n  2  Invalid arguments/manifest, unresolved strict pins or refused selection.\nSummarize: 0 passed; 1 failed/error/interrupted/incomplete or report failure; 2 invalid/unreadable records."
)]
pub(super) struct BenchArgs {
    #[command(subcommand)]
    command: Option<BenchCommand>,
    /// JSON manifest using schema rrs-perl-tasks/1.
    #[arg(long, required = true, value_name = "PATH")]
    manifest: Option<PathBuf>,
    /// Validate without opening artifacts or running commands.
    #[arg(long)]
    validate_only: bool,
    /// Validate first, then emit a schedule on stdout without preparing sources.
    #[arg(long)]
    dry_run: bool,
    /// Refuse unresolved identities, counts and qualification.
    #[arg(long)]
    require_pins: bool,
    /// Execute native/warm/archive entries into a fresh private output directory.
    #[arg(long, value_name = "DIR", requires = "runtime")]
    out: Option<PathBuf>,
    /// Existing scratch parent; explicit use requires --out. Need not be under --out.
    #[arg(long, default_value = "/var/tmp", value_name = "DIR", requires = "out")]
    work_root: PathBuf,
    /// Explicit local Docker-compatible executable; never pulls an image.
    #[arg(long, value_name = "PATH", requires = "out")]
    runtime: Option<PathBuf>,
    /// Runtime classification: docker or stub (podman is refused, not yet qualified).
    // Choosing requires = "out" keeps execution flags out of validate/dry-run.
    #[arg(long, value_enum, value_name = "KIND", requires = "out")]
    runtime_kind: Option<RuntimeKind>,
    /// Record and override an excessive or unavailable host-load reading.
    #[arg(long, requires = "out")]
    allow_high_load: bool,
    #[command(flatten)]
    selection: Selection,
}

#[derive(Debug, clap::Subcommand)]
enum BenchCommand {
    /// Summarize one completed output directory without a manifest or runtime.
    Summarize { dir: PathBuf },
}
impl BenchArgs {
    fn manifest(&self) -> &Path {
        self.manifest
            .as_deref()
            .expect("clap requires --manifest without a subcommand")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum RuntimeKind {
    Docker,
    Podman,
    Stub,
}

#[derive(Debug, Default, Args)]
#[group(conflicts_with = "validate_only")]
struct Selection {
    /// Task IDs (default: all); comma-separated or repeated.
    #[arg(long, value_delimiter = ',')]
    task: Vec<String>,
    /// Backends (default: those declared by each task).
    #[arg(long, value_delimiter = ',', value_enum)]
    backend: Vec<schedule::Backend>,
    /// Base forms (default: git,tar.zst-single-frame).
    #[arg(long, value_delimiter = ',', value_enum)]
    base_form: Vec<schedule::BaseForm>,
    /// Jobs per attempt (default: 1).
    #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(u32).range(1..))]
    jobs: Vec<u32>,
    /// Cache treatments (default: cold,warm); no cache operations are performed.
    #[arg(long, value_delimiter = ',', value_enum)]
    cache: Vec<schedule::Cache>,
    /// Measured repeats per backend, 1..=100 (default: 5).
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100))]
    repeats: Option<u32>,
    /// Recorded deterministic ordering seed (default: 1).
    #[arg(long)]
    seed: Option<u64>,
    /// Concurrent attempts; only 1 is supported (default: 1).
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1))]
    attempts: Option<u32>,
    /// Admit jobs above the task's CPU limit and record the override.
    #[arg(long)]
    allow_oversubscription: bool,
}

pub(super) fn run(args: &BenchArgs, socket: Option<&Path>) -> Result<i32, String> {
    if socket.is_some() {
        eprintln!("sandbox bench: inherited --socket is rejected; bench owns its supervisor");
        return Ok(2);
    }
    if let Some(BenchCommand::Summarize { dir }) = &args.command {
        return summarize::run(dir);
    }
    if usize::from(args.validate_only) + usize::from(args.dry_run) + usize::from(args.out.is_some())
        != 1
    {
        eprintln!("sandbox bench: exactly one of --validate-only, --dry-run or --out is required");
        return Ok(2);
    }
    let bytes = match manifest::open_manifest(args.manifest()) {
        Ok(bytes) => bytes,
        Err((code, error)) => {
            eprintln!("sandbox bench: {error}");
            return Ok(code);
        }
    };
    for (strict, prefix) in [(false, "invalid manifest"), (true, "unresolved pins")] {
        if strict && !args.require_pins && args.out.is_none() {
            break;
        }
        if let Err(error) = manifest::validate(&bytes, args.manifest(), strict) {
            eprintln!("sandbox bench: {prefix}: {error}");
            return Ok(2);
        }
    }
    if args.dry_run || args.out.is_some() {
        let entries = match schedule::build(&bytes, &args.selection) {
            Ok(entries) => entries,
            Err(error) => {
                eprintln!("sandbox bench: selection: {error}");
                return Ok(2);
            }
        };
        if args.out.is_some() {
            return run::execute(args, &bytes, &entries);
        }
        let mut stdout = std::io::stdout().lock();
        for entry in entries {
            serde_json::to_writer(&mut stdout, &entry)
                .map_err(|error| format!("bench schedule report: {error}"))?;
            stdout
                .write_all(b"\n")
                .map_err(|error| format!("bench schedule report: {error}"))?;
        }
        return Ok(0);
    }
    std::io::stdout()
        .lock()
        .write_all(b"Structurally valid; external qualification not verified.\n")
        .map_err(|error| format!("bench validation report: {error}"))?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::{manifest::validate, *};
    use serde_json::json;
    use serde_json::Value;

    pub(super) const HASH: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    pub(super) const FILE: &str = "/catalog/tasks.json";

    pub(super) fn fixture() -> Value {
        serde_json::from_str(&r#"{
          "schema":"rrs-perl-tasks/1", "catalog_revision":"test-1",
          "platforms":[{"id":"linux-amd64", "os":"linux", "architecture":"amd64",
            "image":"perl@sha256:@HASH@", "toolchain_sha256":"sha256:@HASH@",
            "dependency_lock":{"path":"deps.lock", "sha256":"sha256:@HASH@"}}],
          "tasks":[{"id":"mojo", "role":"Large pure-Perl", "distribution":"Mojolicious", "version":"9.42",
            "cpan":{"path":"authors/id/S/SR/SRI/Mojolicious-9.42.tar.gz", "sha256":"sha256:@HASH@"},
            "git":{"repository":"https://github.com/mojolicious/mojo.git", "commit":"@GIT@", "tree":"@GIT@"},
            "artifact":{"path":"mojo.tar.zst", "sha256":"sha256:@HASH@", "tar_stream_sha256":"sha256:@HASH@"},
            "test_inventory":{"state":"known", "count":10, "sha256":"sha256:@HASH@"},
            "backends":["native","fuse"],
            "platforms":[{"platform_id":"linux-amd64", "candidate_jobs":[1,2,8], "supported_jobs":[1],
              "qualification":{"qualified":true, "reasons":[], "evidence":[
                {"jobs":1,"backend":"native","passed":true,"source_sha256":"sha256:@HASH@","image":"perl@sha256:@HASH@","dependency_lock_sha256":"sha256:@HASH@","test_inventory_sha256":"sha256:@HASH@"},
                {"jobs":1,"backend":"fuse","passed":true,"source_sha256":"sha256:@HASH@","image":"perl@sha256:@HASH@","dependency_lock_sha256":"sha256:@HASH@","test_inventory_sha256":"sha256:@HASH@"}]}}],
            "commands":{"configure":{"argv":["perl","Makefile.PL"],"timeout_seconds":60},
              "build":{"argv":["make","-j{jobs}"],"timeout_seconds":60},
              "test":{"argv":["prove","-b","-r","-j{jobs}","t"],"timeout_seconds":60}},
            "environment":{"TZ":"UTC","PERL_HASH_SEED":"0"},
            "resources":{"max_load":4.0,"memory_bytes":1073741824,"disk_bytes":2147483648,"cpus":2,"pids":128},
            "placement":{"source":"source","output":"output","scratch":"scratch"},
            "dependency_locations":{"base":["/repo/lib"],"build":["/repo/blib/lib","/repo/blib/arch"]}}]
        }"#.replace("@HASH@", HASH).replace("@GIT@", &HASH[..40])).unwrap()
    }

    pub(super) fn valid(v: &Value, strict: bool) -> Result<(), String> {
        validate(&serde_json::to_vec(v).unwrap(), Path::new(FILE), strict)
    }

    pub(super) fn refuses(pointer: &str, value: Value, diagnostic: &str) {
        let mut v = fixture();
        *v.pointer_mut(pointer).unwrap() = value;
        refusal(valid(&v, false), &format!("{diagnostic}:"));
    }

    pub(super) fn refusal(result: Result<(), String>, prefix: &str) {
        let error = result.unwrap_err();
        assert!(error.starts_with(prefix), "{error}; expected {prefix}");
    }
    // Regression: unknown fields escaped validation, unsafe diagnostics or direct dispatch panicked.
    #[test]
    fn regression_bench_manifest_schema_and_unknown_fields() {
        let v = fixture();
        valid(&v, true).unwrap();
        let mut absolute = v.clone();
        absolute["tasks"][0]["artifact"]["path"] = json!("/archives/mojo.tar.zst");
        absolute["platforms"][0]["dependency_lock"]["path"] = json!("/locks/deps.lock");
        valid(&absolute, true).unwrap();
        fn visit(v: &Value, pointer: &str) {
            match v {
                Value::Object(map) => {
                    if !pointer.ends_with("/environment") {
                        let mut bad = fixture();
                        bad.pointer_mut(pointer)
                            .unwrap()
                            .as_object_mut()
                            .unwrap()
                            .insert("surprise".into(), json!(true));
                        refusal(valid(&bad, false), "unknown field `surprise`");
                    }
                    for (key, value) in map {
                        visit(value, &format!("{pointer}/{key}"));
                    }
                }
                Value::Array(values) => {
                    for (i, value) in values.iter().enumerate() {
                        visit(value, &format!("{pointer}/{i}"));
                    }
                }
                _ => {}
            }
        }
        visit(&v, "");
        let mut bad = v.clone();
        bad["\x1b\n"] = json!(true);
        let error = valid(&bad, false).unwrap_err();
        refusal(Err(error.clone()), "unknown field");
        assert!(!error.contains(['\x1b', '\n']) && !error.contains("line: 0"));
        let args = BenchArgs {
            command: None,
            manifest: Some(FILE.into()),
            validate_only: false,
            require_pins: false,
            dry_run: false,
            out: None,
            work_root: "/var/tmp".into(),
            runtime: None,
            runtime_kind: None,
            allow_high_load: false,
            selection: Selection::default(),
        };
        assert_eq!(run(&args, None).unwrap(), 2);
        let args = super::super::SandboxArgs {
            socket: Some("unused.sock".into()),
            command: super::super::Command::Bench(args),
        };
        assert_eq!(
            super::super::run(&args).unwrap_err(),
            "bench requires run_cli"
        );
        for (key, field) in [("tasks", "task.id"), ("platforms", "platform.id")] {
            let mut bad = v.clone();
            let rows = bad[key].as_array_mut().unwrap();
            rows.push(rows[0].clone());
            refusal(valid(&bad, false), &format!("{field}:"));
        }
        let mut bad = v.clone();
        bad["tasks"][0]["test_inventory"]
            .as_object_mut()
            .unwrap()
            .remove("count");
        refusal(valid(&bad, false), "missing field `count`");
        refusal(
            validate(b"1e400", Path::new(FILE), false),
            "number out of range",
        );
    }
    // Regression: JSON maps overwrote duplicate keys, including environment names.
    #[test]
    fn regression_bench_manifest_duplicate_keys_refused() {
        fn visit(value: &Value) {
            match value {
                Value::Object(map) => {
                    let (key, child) = map.iter().next().unwrap();
                    let duplicate = format!("{{{0}:{1},{0}:{1}}}", json!(key), child);
                    let error = validate(duplicate.as_bytes(), Path::new(FILE), false).unwrap_err();
                    refusal(Err(error), "duplicate key");
                    for child in map.values() {
                        visit(child);
                    }
                }
                Value::Array(values) => {
                    for child in values {
                        visit(child);
                    }
                }
                _ => {}
            }
        }
        visit(&fixture());
        let error =
            validate(br#"{"\u001b\n":0,"\u001b\n":1}"#, Path::new(FILE), false).unwrap_err();
        refusal(Err(error.clone()), "duplicate key");
        assert!(!error.contains(['\x1b', '\n']));
        let bytes = serde_json::to_string(&fixture())
            .unwrap()
            .replace("\"TZ\":\"UTC\"", "\"TZ\":\"UTC\",\"TZ\":\"UTC\"");
        refusal(
            validate(bytes.as_bytes(), Path::new(FILE), false),
            "duplicate key",
        );
        for (bytes, prefix) in [
            ("[}", "expected value"),
            ("{1:0}", "key must be a string"),
            (r#"{"a":}"#, "expected value"),
            ("", "EOF"),
        ] {
            refusal(validate(bytes.as_bytes(), Path::new(FILE), false), prefix);
        }
    }
}
