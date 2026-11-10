//! Linux-only structural validation. Execution belongs to later slices.

mod manifest;

use clap::Args;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
#[command(
    after_help = "Example: ratarmount sandbox bench --manifest tasks.json --validate-only\n\nRequires Linux. Structural validation does not establish external qualification.\nInherited `--socket` is rejected; bench owns its supervisor.\n\nExit status:\n  0  Structurally valid (draft pins allowed unless --require-pins).\n  1  Operational or reporting failure.\n  2  Invalid arguments/manifest or unresolved strict pins."
)]
pub(super) struct BenchArgs {
    /// JSON manifest using schema rrs-perl-tasks/1.
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    /// Validate without opening artifacts or running commands.
    #[arg(long, required = true)]
    validate_only: bool,
    /// Refuse unresolved identities, counts and qualification.
    #[arg(long)]
    require_pins: bool,
}

pub(super) fn run(args: &BenchArgs, socket: Option<&Path>) -> Result<i32, String> {
    if socket.is_some() {
        eprintln!("sandbox bench: inherited --socket is rejected; bench owns its supervisor");
        return Ok(2);
    }
    if !args.validate_only {
        eprintln!("sandbox bench: --validate-only is required");
        return Ok(2);
    }
    let bytes = match manifest::open_manifest(&args.manifest) {
        Ok(bytes) => bytes,
        Err((code, error)) => {
            eprintln!("sandbox bench: {error}");
            return Ok(code);
        }
    };
    for (strict, prefix) in [(false, "invalid manifest"), (true, "unresolved pins")] {
        if strict && !args.require_pins {
            break;
        }
        if let Err(error) = manifest::validate(&bytes, &args.manifest, strict) {
            eprintln!("sandbox bench: {prefix}: {error}");
            return Ok(2);
        }
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
            manifest: FILE.into(),
            validate_only: false,
            require_pins: false,
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
