//! Strict JSON shape and local consistency checks; no external qualification.

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_MANIFEST: u64 = 1024 * 1024;
pub(super) fn open_manifest(path: &Path) -> Result<Vec<u8>, (i32, String)> {
    use rustix::fs::{openat, Mode, OFlags, CWD};
    // O_NONBLOCK prevents a FIFO from blocking before the descriptor type check.
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-GAP0-B2-M01","item":"ratarmount::sandbox::bench::manifest::open_manifest","disposition":"out-of-family","category":"benchmark-manifest","reason":"Read the explicitly selected benchmark manifest with O_NOFOLLOW and O_NONBLOCK, require a regular descriptor, and bound input to 1 MiB plus one overflow byte.","creation":{"policy":"none","basis":"Read-only existing manifest; no creation, truncation or artifact acquisition."}}"###
    )]
    let file = openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(|e| open_error(path, e.into()))?;
    let file = std::fs::File::from(file);
    let metadata = file.metadata().map(|m| (m.is_file(), m.len()));
    read_manifest(file, metadata)
}
fn open_error(path: &Path, e: std::io::Error) -> (i32, String) {
    let code = if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENXIO))
        || e.kind() == std::io::ErrorKind::InvalidInput
    {
        2
    } else {
        1
    };
    (code, format!("manifest-open {path:?}: {e}"))
}
fn read_manifest(
    file: impl Read,
    metadata: std::io::Result<(bool, u64)>,
) -> Result<Vec<u8>, (i32, String)> {
    let (regular, size) = metadata.map_err(|e| (1, format!("manifest-stat: {e}")))?;
    if !regular || size > MAX_MANIFEST {
        return Err((2, "manifest must be a regular file of at most 1 MiB".into()));
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| (1, format!("manifest-read: {e}")))?;
    if bytes.len() as u64 > MAX_MANIFEST {
        return Err((2, "manifest exceeds 1 MiB".into()));
    }
    Ok(bytes)
}
// serde_json::Value normally overwrites duplicate map keys. Walk every object
// before typed deserialization so dynamic environment maps obey the same rule.
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                // JSON rejects non-finite numbers before calling this visitor.
                Ok(UniqueValue(v.into()))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueValue(value)) = a.next_element()? {
                    values.push(value);
                }
                Ok(UniqueValue(values.into()))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate key {key:?}")));
                    }
                    let UniqueValue(value) = a.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueValue(values.into()))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    catalog_revision: String,
    platforms: Vec<Platform>,
    tasks: Vec<Task>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Platform {
    id: String,
    os: String,
    architecture: String,
    image: String,
    toolchain_sha256: String,
    dependency_lock: DependencyLock,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyLock {
    path: String,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Task {
    id: String,
    role: String,
    distribution: String,
    version: String,
    cpan: Cpan,
    git: Git,
    artifact: Artifact,
    test_inventory: Inventory,
    platforms: Vec<TaskPlatform>,
    backends: Vec<String>,
    commands: Commands,
    environment: BTreeMap<String, String>,
    resources: Resources,
    placement: Placement,
    dependency_locations: DependencyLocations,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cpan {
    path: String,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Git {
    repository: String,
    commit: String,
    tree: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: String,
    sha256: String,
    tar_stream_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    state: String,
    #[serde(deserialize_with = "required_count")]
    count: Option<u64>,
    sha256: String,
}
fn required_count<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    Option::deserialize(d)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskPlatform {
    platform_id: String,
    candidate_jobs: Vec<u32>,
    supported_jobs: Vec<u32>,
    qualification: Qualification,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Qualification {
    qualified: bool,
    reasons: Vec<String>,
    evidence: Vec<Evidence>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    jobs: u32,
    backend: String,
    passed: bool,
    source_sha256: String,
    image: String,
    dependency_lock_sha256: String,
    test_inventory_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Commands {
    configure: Command,
    build: Command,
    test: Command,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    argv: Vec<String>,
    timeout_seconds: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resources {
    max_load: f64,
    memory_bytes: u64,
    disk_bytes: u64,
    cpus: u32,
    pids: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Placement {
    source: String,
    output: String,
    scratch: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyLocations {
    base: Vec<String>,
    build: Vec<String>,
}
fn check(ok: bool, field: &str, message: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(format!("{field}: {message}"))
    }
}
fn text(value: &str, field: &str) -> Result<(), String> {
    check(
        !value.trim().is_empty() && !value.contains('\0'),
        field,
        "empty or NUL",
    )
}
fn identifier(value: &str, field: &str) -> Result<(), String> {
    check(
        value.starts_with(|c: char| c.is_ascii_alphanumeric())
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
            && value != "unpinned",
        field,
        "expected an identifier",
    )
}
fn pin(value: &str, field: &str, strict: bool) -> Result<bool, String> {
    text(value, field)?;
    if value == "unpinned" {
        check(!strict, field, "unpinned")?;
        Ok(false)
    } else {
        Ok(true)
    }
}
fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value.bytes().any(|c| c != b'0')
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn digest(value: &str, field: &str, strict: bool) -> Result<(), String> {
    if pin(value, field, strict)? {
        check(
            value.strip_prefix("sha256:").is_some_and(|v| hex(v, 64)),
            field,
            "expected sha256: and 64 lowercase hex digits",
        )?;
    }
    Ok(())
}
fn image(value: &str, field: &str, strict: bool) -> Result<(), String> {
    if pin(value, field, strict)? {
        let (name, hash) = value
            .split_once('@')
            .ok_or_else(|| format!("{field}: expected image@sha256:digest"))?;
        let parts: Vec<_> = name.split('/').collect();
        check(
            parts.iter().enumerate().all(|(i, part)| {
                let (part, suffix) = part.split_once(':').unwrap_or((part, ""));
                let valid_suffix = if i == 0 && parts.len() > 1 {
                    suffix.parse::<u16>().is_ok_and(|port| port > 0)
                } else {
                    i == parts.len() - 1
                        && suffix.len() <= 128
                        && suffix
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
                        && suffix.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
                };
                (!parts[i].contains(':') || valid_suffix)
                    && part.starts_with(|c: char| c.is_ascii_alphanumeric())
                    && part.bytes().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c)
                    })
                    && part.ends_with(|c: char| c.is_ascii_alphanumeric())
            }),
            field,
            "malformed image name",
        )?;
        digest(hash, field, true)?;
    }
    Ok(())
}
// Lexical paths only: never canonicalize or acquire these inputs.
fn normal_path<'a>(value: &'a str, field: &str) -> Result<&'a Path, String> {
    check(
        !value.chars().any(char::is_whitespace)
            && !matches!(value, "unknown" | "fake" | "TODO" | "TBD")
            && !value.contains(['{', '}', '\\'])
            && value
                .strip_prefix('/')
                .unwrap_or(value)
                .split('/')
                .all(|c| !matches!(c, "" | "." | "..")),
        field,
        "expected lexically normal path",
    )?;
    Ok(Path::new(value))
}
fn resolve(
    value: &str,
    field: &str,
    manifest: &Path,
    strict: bool,
) -> Result<Option<PathBuf>, String> {
    if !pin(value, field, strict)? {
        return Ok(None);
    }
    let parent = manifest.parent().unwrap_or(Path::new("."));
    Ok(Some(parent.join(normal_path(value, field)?)))
}
fn substitutions(value: &str, field: &str) -> Result<(), String> {
    text(value, field)?;
    check(
        !value.replace("{jobs}", "").contains(['{', '}']),
        field,
        "only {jobs} substitution is supported",
    )
}
fn jobs(values: &[u32], field: &str, nonempty: bool) -> Result<(), String> {
    let unique: BTreeSet<_> = values.iter().collect();
    check(
        (!nonempty || !values.is_empty()) && !values.contains(&0) && unique.len() == values.len(),
        field,
        "expected unique positive jobs",
    )
}
pub(super) fn validate(bytes: &[u8], path: &Path, strict: bool) -> Result<(), String> {
    let UniqueValue(value) =
        serde_json::from_slice(bytes).map_err(|e| e.to_string().escape_debug().to_string())?;
    let manifest: Manifest =
        serde_json::from_value(value).map_err(|e| e.to_string().escape_debug().to_string())?;
    check(
        manifest.schema == "rrs-perl-tasks/1",
        "schema",
        "unsupported schema",
    )?;
    identifier(&manifest.catalog_revision, "catalog_revision")?;
    check(!manifest.platforms.is_empty(), "platforms", "empty catalog")?;
    let mut platforms = BTreeMap::new();
    for p in &manifest.platforms {
        identifier(&p.id, "platform.id")?;
        check(
            platforms.insert(&p.id, p).is_none(),
            "platform.id",
            "duplicate ID",
        )?;
        check(p.os == "linux", "platform.os", "requires linux")?;
        check(
            matches!(p.architecture.as_str(), "amd64" | "arm64"),
            "platform.architecture",
            "unsupported",
        )?;
        image(&p.image, "platform.image", strict)?;
        digest(&p.toolchain_sha256, "platform.toolchain_sha256", strict)?;
        let lock = &p.dependency_lock;
        resolve(&lock.path, "dependency_lock.path", path, strict)?;
        digest(&lock.sha256, "dependency_lock.sha256", strict)?;
    }
    check(!manifest.tasks.is_empty(), "tasks", "empty task catalog")?;
    let mut ids = BTreeSet::new();
    for t in &manifest.tasks {
        identifier(&t.id, "task.id")?;
        check(ids.insert(&t.id), "task.id", "duplicate ID")?;
        t.validate(path, strict, &platforms)?;
    }
    Ok(())
}
impl Task {
    fn validate(
        &self,
        path: &Path,
        strict: bool,
        platforms: &BTreeMap<&String, &Platform>,
    ) -> Result<(), String> {
        check(
            matches!(
                self.role.as_str(),
                "Large pure-Perl" | "XS" | "Moose consumer"
            ),
            "role",
            "unsupported role",
        )?;
        identifier(&self.distribution, "distribution")?;
        if pin(&self.version, "version", strict)? {
            check(
                self.version.bytes().any(|c| c.is_ascii_digit())
                    && self
                        .version
                        .bytes()
                        .all(|c| c.is_ascii_digit() || b"v._".contains(&c)),
                "version",
                "malformed release version",
            )?;
        }
        if pin(&self.cpan.path, "cpan.path", strict)? {
            pin(&self.version, "version", true)?;
            let parts: Vec<_> = self.cpan.path.split('/').collect();
            check(
                parts.len() == 6
                    && parts[..2] == ["authors", "id"]
                    && parts[2].len() == 1
                    && parts[3].len() == 2
                    && parts[4].starts_with(parts[3])
                    && parts[3].starts_with(parts[2])
                    && parts[2..5].iter().all(|p| {
                        p.bytes()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                    })
                    && [".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip"]
                        .iter()
                        .any(|ext| {
                            parts[5] == format!("{}-{}{ext}", self.distribution, self.version)
                        }),
                "cpan.path",
                "expected release CPAN authors/id path",
            )?;
        }
        digest(&self.cpan.sha256, "cpan.sha256", strict)?;
        let git = &self.git;
        if pin(&git.repository, "git.repository", strict)? {
            let repo = url::Url::parse(&git.repository);
            check(
                repo.is_ok_and(|u| {
                    u.scheme() == "https"
                        && u.host_str().is_some_and(|h| h.contains('.'))
                        && u.username().is_empty()
                        && u.password().is_none()
                        && u.query().is_none()
                        && u.fragment().is_none()
                        && u.path() != "/"
                }) && !git.repository.chars().any(char::is_whitespace)
                    && !git.repository.contains(['{', '}']),
                "git.repository",
                "expected HTTPS repository URL",
            )?;
        }
        for (field, hash) in [("git.commit", &git.commit), ("git.tree", &git.tree)] {
            if pin(hash, field, strict)? {
                check(
                    hex(hash, 40) || hex(hash, 64),
                    field,
                    "expected full Git object ID",
                )?;
            }
        }
        check(
            git.commit == "unpinned"
                || git.tree == "unpinned"
                || git.commit.len() == git.tree.len(),
            "git.tree",
            "object formats differ",
        )?;
        let artifact = resolve(&self.artifact.path, "artifact.path", path, strict)?;
        check(
            artifact.as_deref() != Some(path),
            "artifact.path",
            "artifact is the manifest",
        )?;
        digest(&self.artifact.sha256, "artifact.sha256", strict)?;
        digest(
            &self.artifact.tar_stream_sha256,
            "artifact.tar_stream_sha256",
            strict,
        )?;
        let inv = &self.test_inventory;
        check(
            matches!(inv.state.as_str(), "known" | "unknown"),
            "test_inventory.state",
            "expected known or unknown",
        )?;
        let known = inv.state == "known";
        check(
            if known {
                inv.count.is_some_and(|n| n > 0)
            } else {
                inv.count.is_none()
            },
            "test_inventory.count",
            "invalid inventory count",
        )?;
        check(
            !strict || known,
            "test_inventory.state",
            "unknown inventory",
        )?;
        digest(&inv.sha256, "test_inventory.sha256", strict || known)?;
        check(
            known || inv.sha256 == "unpinned",
            "test_inventory.sha256",
            "unknown must be unpinned",
        )?;
        check(!self.backends.is_empty(), "backends", "empty backends")?;
        let mut backends = BTreeSet::new();
        for b in &self.backends {
            check(
                matches!(b.as_str(), "native" | "fuse") && backends.insert(b),
                "backends",
                "unsupported or duplicate backend",
            )?;
        }
        for (field, command) in [
            ("commands.configure", &self.commands.configure),
            ("commands.build", &self.commands.build),
            ("commands.test", &self.commands.test),
        ] {
            check(
                !command.argv.is_empty(),
                &format!("{field}.argv"),
                "empty argv",
            )?;
            for arg in &command.argv {
                substitutions(arg, &format!("{field}.argv"))?;
            }
            check(
                command.timeout_seconds > 0,
                &format!("{field}.timeout_seconds"),
                "nonpositive timeout",
            )?;
        }
        for (name, value) in &self.environment {
            check(
                name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                    && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'),
                "environment.name",
                "invalid environment name",
            )?;
            substitutions(value, "environment.value")?;
        }
        check(
            self.resources.max_load > 0.0,
            "resources.max_load",
            "expected positive load",
        )?;
        for (field, value) in [
            ("resources.memory_bytes", self.resources.memory_bytes),
            ("resources.disk_bytes", self.resources.disk_bytes),
            ("resources.cpus", self.resources.cpus as u64),
            ("resources.pids", self.resources.pids as u64),
        ] {
            check(value > 0, field, "expected positive limit")?;
        }
        let mut placement = Vec::new();
        for (field, value) in [
            ("placement.source", &self.placement.source),
            ("placement.output", &self.placement.output),
            ("placement.scratch", &self.placement.scratch),
        ] {
            check(!Path::new(value).is_absolute(), field, "must be relative")?;
            if let Some(p) = resolve(value, field, path, strict)? {
                check(
                    !placement
                        .iter()
                        .any(|other: &PathBuf| other.starts_with(&p) || p.starts_with(other)),
                    field,
                    "overlapping placement",
                )?;
                placement.push(p);
            }
        }
        let deps = &self.dependency_locations;
        let mut locations = BTreeSet::new();
        for (field, values, root) in [
            ("dependency_locations.base", &deps.base, "/repo"),
            ("dependency_locations.build", &deps.build, "/repo/blib"),
        ] {
            check(!values.is_empty(), field, "empty dependency locations")?;
            for v in values {
                if pin(v, field, strict)? {
                    let p = normal_path(v, field)?;
                    check(
                        p.starts_with(root)
                            && (root != "/repo"
                                || (p != Path::new(root) && !p.starts_with("/repo/blib")))
                            && locations.insert(p),
                        field,
                        "outside scope or duplicate",
                    )?;
                }
            }
        }
        check(!self.platforms.is_empty(), "task.platforms", "empty rows")?;
        let mut seen = BTreeSet::new();
        for row in &self.platforms {
            let p = platforms
                .get(&row.platform_id)
                .ok_or("platform_id: unknown platform")?;
            check(
                seen.insert(&row.platform_id),
                "platform_id",
                "duplicate row",
            )?;
            jobs(&row.candidate_jobs, "candidate_jobs", true)?;
            jobs(&row.supported_jobs, "supported_jobs", false)?;
            check(
                row.supported_jobs
                    .iter()
                    .all(|j| row.candidate_jobs.contains(j)),
                "supported_jobs",
                "not a candidate",
            )?;
            self.qualify(row, p, strict)?;
        }
        Ok(())
    }

    fn qualify(&self, row: &TaskPlatform, platform: &Platform, strict: bool) -> Result<(), String> {
        let q = &row.qualification;
        let deps = &self.dependency_locations;
        let artifact = &self.artifact;
        let inventory = &self.test_inventory;
        let lock = &platform.dependency_lock;
        check(
            q.qualified == !row.supported_jobs.is_empty(),
            "qualification.qualified",
            "supported_jobs disagree",
        )?;
        check(
            q.qualified == q.reasons.is_empty(),
            "qualification.reasons",
            "reasons disagree",
        )?;
        for reason in &q.reasons {
            text(reason, "qualification.reasons")?;
        }
        check(
            !strict || q.qualified,
            "qualification.qualified",
            "not qualified",
        )?;
        let mut evidence = BTreeSet::new();
        for e in &q.evidence {
            check(
                row.candidate_jobs.contains(&e.jobs),
                "evidence.jobs",
                "not a candidate",
            )?;
            check(
                self.backends.contains(&e.backend),
                "evidence.backend",
                "not selected",
            )?;
            check(
                evidence.insert((e.jobs, &e.backend)),
                "qualification.evidence",
                "duplicate evidence",
            )?;
            check(e.passed, "evidence.passed", "must pass")?;
            for (field, value, expected) in [
                (
                    "evidence.source_sha256",
                    &e.source_sha256,
                    &artifact.tar_stream_sha256,
                ),
                (
                    "evidence.dependency_lock_sha256",
                    &e.dependency_lock_sha256,
                    &lock.sha256,
                ),
                (
                    "evidence.test_inventory_sha256",
                    &e.test_inventory_sha256,
                    &inventory.sha256,
                ),
                ("evidence.image", &e.image, &platform.image),
            ] {
                // Parent identities already passed their grammar validators.
                check(
                    value != "unpinned" && value == expected,
                    field,
                    "evidence identity mismatch",
                )?;
            }
        }
        for j in &row.supported_jobs {
            check(
                self.backends.iter().all(|b| evidence.contains(&(*j, b))),
                "supported_jobs",
                "missing backend evidence",
            )?;
        }
        if q.qualified {
            // A qualified claim must contain resolved inputs even outside strict mode.
            for (field, value) in [
                ("version", &self.version),
                ("cpan.path", &self.cpan.path),
                ("cpan.sha256", &self.cpan.sha256),
                ("git.repository", &self.git.repository),
                ("git.commit", &self.git.commit),
                ("git.tree", &self.git.tree),
                ("artifact.path", &artifact.path),
                ("artifact.sha256", &artifact.sha256),
                ("platform.toolchain_sha256", &platform.toolchain_sha256),
                ("dependency_lock.path", &lock.path),
                ("placement.source", &self.placement.source),
                ("placement.output", &self.placement.output),
                ("placement.scratch", &self.placement.scratch),
            ] {
                pin(value, field, true)?;
            }
            for (field, values) in [
                ("dependency_locations.base", &deps.base),
                ("dependency_locations.build", &deps.build),
            ] {
                for value in values {
                    pin(value, field, true)?;
                }
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::super::tests::{fixture, refusal, refuses, valid, FILE, HASH};
    use super::*;
    use serde_json::json;

    // Regression: fake identities and abbreviated digests looked pinned.
    #[test]
    fn regression_bench_manifest_sha256_and_image_formats() {
        assert_eq!(
            resolve("mojo.tar.zst", "artifact.path", Path::new(FILE), true).unwrap(),
            Some(PathBuf::from("/catalog/mojo.tar.zst"))
        );
        for value in ["", "0", "g", "A"] {
            assert!(!hex(&value.repeat(64), 64));
        }
        assert!(hex(HASH, 64));
        for value in ["", " ", "x\0"] {
            refusal(text(value, "text"), "text:");
            refusal(pin(value, "pin", false).map(|_| ()), "pin:");
        }
        for value in ["", "-id", "a!", "unpinned"] {
            refusal(identifier(value, "id"), "id:");
        }
        refusal(pin("unpinned", "pin", true).map(|_| ()), "pin:");
        for value in ["", "unknown", "fake", "sha256:abcd", "sha256:UNPINNED"] {
            refuses("/tasks/0/artifact/sha256", json!(value), "artifact.sha256");
            refuses("/platforms/0/image", json!(value), "platform.image");
        }
        for value in [
            "sha256:".to_owned() + &"0".repeat(64),
            format!("sha256:{}", "A".repeat(64)),
        ] {
            refusal(digest(&value, "hash", false), "hash:");
        }
        // Valid hashes isolate every image-name rule from later digest/equality checks.
        let mut names: Vec<String> = serde_json::from_str(
            r#"[
          "", "/perl", "perl/", "a//b", "Perl", "-perl", "perl-", "p!rl",
          "host:0/perl", "host:65536/perl", "host:abc/perl", "host:/perl",
          "host:1/a:tag/b", "perl:", "perl:-tag", "perl:bad!tag"
        ]"#,
        )
        .unwrap();
        names.push(format!("perl:{}", "a".repeat(129)));
        for name in names {
            let value = format!("{name}@sha256:{HASH}");
            refusal(image(&value, "image", false), "image:");
        }
        for (value, prefix) in [
            ("perl:latest", "image: expected image@"),
            ("perl@unpinned", "image: unpinned"),
            ("../perl@sha256:abcd", "image: malformed image name"),
            ("perl@@sha256:abcd", "image: expected sha256:"),
        ] {
            refusal(image(value, "image", false), prefix);
        }
        for name in ["perl:tag", "host:123/perl:tag", "host/perl:_tag"] {
            image(&format!("{name}@sha256:{HASH}"), "image", true).unwrap();
        }
        for value in [
            "unknown", "fake", "TODO", "TBD", "a{b}", "a}b", "a\\b", "a b", "a\tb", "/", "", "a/.",
            "a/..", "a//b", "a/",
        ] {
            refusal(normal_path(value, "path").map(|_| ()), "path:");
        }
        for field in ["commit", "tree"] {
            refuses(
                &format!("/tasks/0/git/{field}"),
                json!("abc1234"),
                &format!("git.{field}"),
            );
        }
    }
    // Regression: supported jobs lacked matching platform/backend passing evidence.
    #[test]
    fn regression_bench_manifest_supported_jobs() {
        let jobs = "/tasks/0/platforms/0/supported_jobs";
        for value in [json!([0]), json!([1, 1]), json!([3]), json!([1, 2])] {
            refuses(jobs, value, "supported_jobs");
        }
        refuses(
            "/tasks/0/platforms/0/qualification/evidence",
            json!([]),
            "supported_jobs",
        );
        let mut v = fixture();
        let e = &mut v["tasks"][0]["platforms"][0]["qualification"]["evidence"];
        e[1] = e[0].clone();
        refusal(valid(&v, false), "qualification.evidence:");
        let row = v["tasks"][0]["platforms"][0].clone();
        v = fixture();
        v["tasks"][0]["platforms"].as_array_mut().unwrap().push(row);
        refusal(valid(&v, false), "platform_id:");
    }
    // Regression: later slices could receive empty commands, unsafe substitutions or zero deadlines.
    #[test]
    fn regression_bench_manifest_commands_and_timeouts() {
        for command in ["configure", "build", "test"] {
            let path = format!("/tasks/0/commands/{command}");
            let field = format!("commands.{command}");
            let argvs: Vec<Value> = serde_json::from_str(
                r#"[[],[""],["x\u0000"],["{other}"],["${HOME}"],["x{"],["x}"]]"#,
            )
            .unwrap();
            for argv in argvs {
                refuses(&format!("{path}/argv"), argv, &format!("{field}.argv"));
            }
            refuses(
                &format!("{path}/timeout_seconds"),
                json!(0),
                &format!("{field}.timeout_seconds"),
            );
        }
        let env = "/tasks/0/environment";
        for name in ["9BAD", "BAD=NAME", ""] {
            refuses(env, json!({(name):"x"}), "environment.name");
        }
        refuses(&format!("{env}/TZ"), json!("{home}"), "environment.value");
    }
    // Regression: placeholder backends implied support for deferred implementations.
    #[test]
    fn regression_bench_manifest_placeholder_backends_refused() {
        let backends: Vec<String> = serde_json::from_str(
            r#"["negative-cache","kernel-top","docker-overlay2","overlayfs","podman",""]"#,
        )
        .unwrap();
        for backend in backends {
            refuses("/tasks/0/backends", json!([backend]), "backends");
        }
        refuses("/tasks/0/backends", json!(["native", "native"]), "backends");
    }
    // Regression: derived fields were never read by production validation.
    #[test]
    fn regression_bench_manifest_every_field_validated() {
        valid(&fixture(), true).unwrap();
        // Refusal/field-to-case checklist (test names omit regression_bench_manifest_):
        // Every schema leaf has a pointer row below; collections also have empty cases.
        // validate: schema/revision/empty catalogs + platform OS/arch/image/toolchain/lock => named rows;
        // ID grammar/duplicates => /id rows + schema_and_unknown_fields duplicates (task and platform).
        // Task::validate: role/distribution/version/CPAN/Git/artifact/inventory => named pointer rows;
        // CPAN author lengths/prefixes/case/dist/version => /cpan/path; Git parse/HTTPS/host/user/password/query/fragment/
        // root/space/both braces => /git/repository; Git hex/length => /git/{commit,tree} + relations table.
        // Artifact == manifest => tasks.json and absolute rows; inventory state/known zero|null|unpinned
        // => /test_inventory rows; unknown count/hash/strict => relations table.
        // Backends empty/unsupported/duplicate => /backends + placeholder_backends_refused.
        // Commands argv/text/substitution/deadline (all 3) + env name/value => commands_and_timeouts/rows.
        // Resources load/limits => /resources; placement relative/resolve/overlap => /placement rows.
        // Dependencies empty/pin/normal/scope/duplicate => /dependency_locations + paths (incl /repo itself).
        // Task rows empty/lookup/duplicate => /platforms + supported_jobs duplicate platform.
        // Jobs nonempty/positive/unique => candidate_jobs rows + supported_jobs; subset => relations:
        // unqualified [3] (otherwise later missing-evidence refusal masks deletion of subset check).
        // qualify: qualified vs jobs => /qualified; qualified reasons => /reasons; unqualified reasons
        // empty/NUL and strict qualified => fully pinned relations rows (reasons=[]/[NUL]/[r]).
        // Evidence candidate/backend/passed => /evidence; duplicate => supported_jobs duplicate evidence;
        // identity equality + unpinned (all 4) => relations; per-backend coverage => evidence=[]/jobs=[1,2].
        // Qualified resolved inputs => relations unpinned fields (version also unpins CPAN to reach check).
        // Helpers check/text/identifier/pin/hex/digest/image/normal_path => sha256_and_image_formats direct
        // rows (valid-hash image names; path denylist/both braces/backslash/whitespace/components).
        // substitutions/jobs/resolve and their ? propagation => commands/jobs/placement/artifact/lock rows.
        // UniqueValue map-key/value/sequence/deserialize_any errors + duplicates => duplicate_keys_refused;
        // typed deserialize/required_count/nonfinite JSON => schema_and_unknown_fields unknown/count/1e400.
        // open_manifest/open_error ELOOP/ENXIO/InvalidInput/other => errno table + NUL below;
        // CLI invalid_arguments_exit_two also tests link/socket/missing descriptors. read_manifest metadata/read/type/stat-size/post-stat growth =>
        // injected error/nonregular/oversized/growing reader cases below (plus successful read).
        let cases: Vec<(String, Value, String)> = serde_json::from_str(r#"[
          ["/schema","bad","schema"], ["/catalog_revision","","catalog_revision"],
          ["/platforms",[],"platforms"], ["/tasks",[],"tasks"],
          ["/platforms/0/id","","platform.id"], ["/platforms/0/os","darwin","platform.os"],
          ["/platforms/0/architecture","mips","platform.architecture"],
          ["/platforms/0/image","fake","platform.image"], ["/platforms/0/toolchain_sha256","fake","platform.toolchain_sha256"],
          ["/platforms/0/dependency_lock/path","","dependency_lock.path"], ["/platforms/0/dependency_lock/sha256","fake","dependency_lock.sha256"],
          ["/tasks/0/id","","task.id"], ["/tasks/0/role","unknown","role"],
          ["/tasks/0/distribution","","distribution"], ["/tasks/0/version","candidate","version"],
          ["/tasks/0/cpan/path","fake","cpan.path"], ["/tasks/0/cpan/sha256","fake","cpan.sha256"],
          ["/tasks/0/git/repository","fake","git.repository"], ["/tasks/0/git/commit","123","git.commit"], ["/tasks/0/git/tree","123","git.tree"],
          ["/tasks/0/artifact/path","../escape","artifact.path"], ["/tasks/0/artifact/sha256","fake","artifact.sha256"], ["/tasks/0/artifact/tar_stream_sha256","fake","artifact.tar_stream_sha256"],
          ["/tasks/0/test_inventory/state","maybe","test_inventory.state"], ["/tasks/0/test_inventory/count",null,"test_inventory.count"], ["/tasks/0/test_inventory/sha256","fake","test_inventory.sha256"],
          ["/tasks/0/platforms",[],"task.platforms"], ["/tasks/0/platforms/0/platform_id","absent","platform_id"],
          ["/tasks/0/platforms/0/candidate_jobs",[],"candidate_jobs"], ["/tasks/0/platforms/0/candidate_jobs",[0],"candidate_jobs"], ["/tasks/0/platforms/0/candidate_jobs",[1,1],"candidate_jobs"], ["/tasks/0/platforms/0/supported_jobs",[3],"supported_jobs"],
          ["/tasks/0/platforms/0/qualification/qualified",false,"qualification.qualified"],
          ["/tasks/0/platforms/0/qualification/reasons",["unexpected"],"qualification.reasons"],
          ["/tasks/0/platforms/0/qualification/evidence",[],"supported_jobs"],
          ["/tasks/0/platforms/0/qualification/evidence/0/jobs",3,"evidence.jobs"],
          ["/tasks/0/platforms/0/qualification/evidence/0/backend","unsupported","evidence.backend"],
          ["/tasks/0/platforms/0/qualification/evidence/0/passed",false,"evidence.passed"],
          ["/tasks/0/platforms/0/qualification/evidence/0/source_sha256","fake","evidence.source_sha256"],
          ["/tasks/0/platforms/0/qualification/evidence/0/image","fake","evidence.image"],
          ["/tasks/0/platforms/0/qualification/evidence/0/dependency_lock_sha256","fake","evidence.dependency_lock_sha256"],
          ["/tasks/0/platforms/0/qualification/evidence/0/test_inventory_sha256","fake","evidence.test_inventory_sha256"],
          ["/tasks/0/backends",[],"backends"],
          ["/tasks/0/commands/configure/argv",[],"commands.configure.argv"], ["/tasks/0/commands/configure/timeout_seconds",0,"commands.configure.timeout_seconds"],
          ["/tasks/0/commands/build/argv",[],"commands.build.argv"], ["/tasks/0/commands/build/timeout_seconds",0,"commands.build.timeout_seconds"],
          ["/tasks/0/commands/test/argv",[],"commands.test.argv"], ["/tasks/0/commands/test/timeout_seconds",0,"commands.test.timeout_seconds"],
          ["/tasks/0/environment",{"BAD=NAME":"x"},"environment.name"], ["/tasks/0/environment/TZ","\u0000","environment.value"],
          ["/tasks/0/resources/max_load",0,"resources.max_load"], ["/tasks/0/resources/memory_bytes",0,"resources.memory_bytes"],
          ["/tasks/0/resources/disk_bytes",0,"resources.disk_bytes"], ["/tasks/0/resources/cpus",0,"resources.cpus"], ["/tasks/0/resources/pids",0,"resources.pids"],
          ["/tasks/0/placement/source","","placement.source"], ["/tasks/0/placement/output","source","placement.output"], ["/tasks/0/placement/scratch","output/child","placement.scratch"],
          ["/tasks/0/dependency_locations/base",["/elsewhere"],"dependency_locations.base"], ["/tasks/0/dependency_locations/build",["/repo/lib"],"dependency_locations.build"],
          ["/tasks/0/artifact/path","tasks.json","artifact.path"],
          ["/tasks/0/artifact/path","/catalog/tasks.json","artifact.path"],
          ["/tasks/0/cpan/path","authors/id/S/SR/SRI/Other-9.42.tar.gz","cpan.path"],
          ["/tasks/0/cpan/path","authors/id/S/SR/SRI/Mojolicious-9.43.tar.gz","cpan.path"],
          ["/tasks/0/git/repository","https://user:pass@github.com/mojo.git","git.repository"],
          ["/tasks/0/git/repository","https://user@github.com/mojo.git","git.repository"],
          ["/tasks/0/git/repository","https://github.com/mojo.git?q=1","git.repository"],
          ["/tasks/0/git/repository","https://github.com/mojo.git#main","git.repository"],
          ["/tasks/0/placement/source","/host","placement.source"],
          ["/tasks/0/placement/output","/host","placement.output"],
          ["/tasks/0/placement/scratch","/host","placement.scratch"],
          ["/tasks/0/artifact/path","a/./b","artifact.path"],
          ["/tasks/0/artifact/path","a//b","artifact.path"],
          ["/tasks/0/artifact/path","a/","artifact.path"],
          ["/platforms/0/dependency_lock/path","a/./b","dependency_lock.path"],
          ["/platforms/0/dependency_lock/path","a//b","dependency_lock.path"],
          ["/platforms/0/dependency_lock/path","a/","dependency_lock.path"],
          ["/tasks/0/version","v._","version"],
          ["/tasks/0/version","9x","version"],
          ["/tasks/0/cpan/path","authors/id/S/SR/SRI/Mojolicious-9.42.1.tar.gz","cpan.path"],
          ["/tasks/0/cpan/path","other/id/S/SR/SRI/Mojolicious-9.42.tar.gz","cpan.path"],
          ["/tasks/0/cpan/path","authors/id/SR/SR/SRI/Mojolicious-9.42.tar.gz","cpan.path"],
          ["/tasks/0/cpan/path","authors/id/S/SRR/SRRI/Mojolicious-9.42.tar.gz","cpan.path"],
          ["/tasks/0/cpan/path","authors/id/S/SR/SZI/Mojolicious-9.42.tar.gz","cpan.path"],
          ["/tasks/0/cpan/path","authors/id/Z/SR/SRI/Mojolicious-9.42.tar.gz","cpan.path"],
          ["/tasks/0/cpan/path","authors/id/s/sr/sri/Mojolicious-9.42.tar.gz","cpan.path"],
          ["/tasks/0/git/repository","http://github.com/mojo.git","git.repository"],
          ["/tasks/0/git/repository","https://localhost/mojo.git","git.repository"],
          ["/tasks/0/git/repository","https://github.com/","git.repository"],
          ["/tasks/0/git/repository","https://:pass@github.com/mojo.git","git.repository"],
          ["/tasks/0/git/repository","https://github.com/a b","git.repository"],
          ["/tasks/0/git/repository","https://github.com/a{b}","git.repository"],
          ["/tasks/0/git/repository","https://github.com/a}b","git.repository"],
          ["/tasks/0/dependency_locations/base",[],"dependency_locations.base"],
          ["/tasks/0/dependency_locations/build",[],"dependency_locations.build"],
          ["/tasks/0/dependency_locations/build",["/repo/blib/lib","/repo/blib/lib"],"dependency_locations.build"],
          ["/tasks/0/test_inventory/count",0,"test_inventory.count"],
          ["/tasks/0/test_inventory/sha256","unpinned","test_inventory.sha256"]
        ]"#).unwrap();
        for (pointer, value, diagnostic) in cases {
            refuses(&pointer, value, &diagnostic);
        }
        // Regression: well-formed relations isolate each comparison and strict-qualification refusal.
        let relations: Vec<(BTreeMap<String, Value>, bool, String)> = serde_json::from_str(&r#"[
          [{"/tasks/0/platforms/0/qualification/evidence/0/source_sha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},false,"evidence.source_sha256"],
          [{"/tasks/0/platforms/0/qualification/evidence/0/source_sha256":"unpinned"},false,"evidence.source_sha256"],
          [{"/tasks/0/platforms/0/qualification/evidence/0/dependency_lock_sha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},false,"evidence.dependency_lock_sha256"],
          [{"/tasks/0/platforms/0/qualification/evidence/0/dependency_lock_sha256":"unpinned"},false,"evidence.dependency_lock_sha256"],
          [{"/tasks/0/platforms/0/qualification/evidence/0/test_inventory_sha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},false,"evidence.test_inventory_sha256"],
          [{"/tasks/0/platforms/0/qualification/evidence/0/test_inventory_sha256":"unpinned"},false,"evidence.test_inventory_sha256"],
          [{"/tasks/0/platforms/0/qualification/evidence/0/image":"perl@sha256:1111111111111111111111111111111111111111111111111111111111111111"},false,"evidence.image"],
          [{"/tasks/0/platforms/0/qualification/evidence/0/image":"unpinned"},false,"evidence.image"],
          [{"/tasks/0/version":"unpinned","/tasks/0/cpan/path":"unpinned"},false,"version"],
          [{"/tasks/0/version":"unpinned","/tasks/0/cpan/path":"authors/id/S/SR/SRI/Mojolicious-unpinned.tar.gz","/tasks/0/platforms/0/supported_jobs":[],"/tasks/0/platforms/0/qualification":{"qualified":false,"reasons":["r"],"evidence":[]}},false,"version"],
          [{"/tasks/0/cpan/path":"unpinned"},false,"cpan.path"],
          [{"/tasks/0/cpan/sha256":"unpinned"},false,"cpan.sha256"],
          [{"/tasks/0/git/repository":"unpinned"},false,"git.repository"],
          [{"/tasks/0/git/commit":"unpinned"},false,"git.commit"],
          [{"/tasks/0/git/tree":"unpinned"},false,"git.tree"],
          [{"/tasks/0/artifact/path":"unpinned"},false,"artifact.path"],
          [{"/tasks/0/artifact/sha256":"unpinned"},false,"artifact.sha256"],
          [{"/platforms/0/toolchain_sha256":"unpinned"},false,"platform.toolchain_sha256"],
          [{"/platforms/0/dependency_lock/path":"unpinned"},false,"dependency_lock.path"],
          [{"/tasks/0/placement/source":"unpinned"},false,"placement.source"],
          [{"/tasks/0/placement/output":"unpinned"},false,"placement.output"],
          [{"/tasks/0/placement/scratch":"unpinned"},false,"placement.scratch"],
          [{"/tasks/0/dependency_locations/base/0":"unpinned"},false,"dependency_locations.base"],
          [{"/tasks/0/dependency_locations/build/0":"unpinned"},false,"dependency_locations.build"],
          [{"/tasks/0/dependency_locations/build/1":"unpinned"},false,"dependency_locations.build"],
          [{"/tasks/0/test_inventory/state":"unknown","/tasks/0/test_inventory/count":5,"/tasks/0/test_inventory/sha256":"unpinned"},false,"test_inventory.count"],
          [{"/tasks/0/test_inventory/state":"unknown","/tasks/0/test_inventory/count":null,"/tasks/0/test_inventory/sha256":"sha256:@HASH@"},false,"test_inventory.sha256"],
          [{"/tasks/0/test_inventory/state":"unknown","/tasks/0/test_inventory/count":null,"/tasks/0/test_inventory/sha256":"unpinned"},true,"test_inventory.state"],
          [{"/tasks/0/git/commit":"@HASH@"},false,"git.tree"],
          [{"/tasks/0/git/tree":"@HASH@"},false,"git.tree"],
          [{"/tasks/0/platforms/0/supported_jobs":[],"/tasks/0/platforms/0/qualification":{"qualified":false,"reasons":["r"],"evidence":[]}},true,"qualification.qualified"],
          [{"/tasks/0/platforms/0/supported_jobs":[],"/tasks/0/platforms/0/qualification":{"qualified":false,"reasons":[],"evidence":[]}},false,"qualification.reasons"],
          [{"/tasks/0/platforms/0/supported_jobs":[],"/tasks/0/platforms/0/qualification":{"qualified":false,"reasons":["\u0000"],"evidence":[]}},false,"qualification.reasons"],
          [{"/tasks/0/placement/source":"source/child","/tasks/0/placement/output":"source"},false,"placement.output"],
          [{"/tasks/0/platforms/0/supported_jobs":[3],"/tasks/0/platforms/0/qualification/qualified":false},false,"supported_jobs"],
          [{"/tasks/0/test_inventory":{"state":"unknown","count":null,"sha256":"unpinned"},"/tasks/0/platforms/0/supported_jobs":[],"/tasks/0/platforms/0/qualification/qualified":false,"/tasks/0/platforms/0/qualification/reasons":["r"],"/tasks/0/platforms/0/qualification/evidence/0/test_inventory_sha256":"unpinned","/tasks/0/platforms/0/qualification/evidence/1/test_inventory_sha256":"unpinned"},false,"evidence.test_inventory_sha256"]
        ]"#.replace("@HASH@", HASH)).unwrap();
        for (patch, strict, field) in relations {
            let mut v = fixture();
            for (pointer, value) in patch {
                *v.pointer_mut(&pointer).unwrap() = value;
            }
            refusal(valid(&v, strict), &format!("{field}:"));
        }
        // Regression: dependency locations must use container scope even for manifests under /repo.
        let bytes = serde_json::to_vec(&fixture()).unwrap();
        for manifest in [FILE, "/repo/cat/tasks.json", "/repo/blib/x/tasks.json"] {
            validate(&bytes, Path::new(manifest), false).unwrap();
            let paths: Vec<(String, Vec<String>)> = serde_json::from_str(r#"[
              ["base",["/repo","lib","repo/lib","/repo/blib","/repo2/lib","/repo/./lib","/repo/../lib","/repo//lib","/repo/lib/","//repo/lib"]],
              ["build",["lib","repo/blib/lib","/repo/lib","/repo/blib2/lib","/repo/blib/./lib","/repo/blib/../lib","/repo/blib//lib","/repo/blib/lib/","//repo/blib/lib"]]
            ]"#).unwrap();
            for (field, values) in paths {
                for value in values {
                    let mut v = fixture();
                    v["tasks"][0]["dependency_locations"][&field] = json!([value]);
                    refusal(
                        validate(&serde_json::to_vec(&v).unwrap(), Path::new(manifest), false),
                        &format!("dependency_locations.{field}:"),
                    );
                }
            }
        }
        // Regression: descriptor failures and growth after stat must fail deterministically.
        let injected = || std::io::Error::other("injected");
        let io_refusal = |result: Result<Vec<u8>, (i32, String)>, code, prefix| {
            let (actual, error) = result.unwrap_err();
            assert_eq!(actual, code);
            assert!(error.starts_with(prefix), "{error}");
        };
        struct FailingRead;
        impl Read for FailingRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("injected"))
            }
        }
        io_refusal(
            read_manifest(&b""[..], Err(injected())),
            1,
            "manifest-stat:",
        );
        io_refusal(
            read_manifest(FailingRead, Ok((true, 0))),
            1,
            "manifest-read:",
        );
        for metadata in [(false, 0), (true, MAX_MANIFEST + 1)] {
            io_refusal(read_manifest(&b""[..], Ok(metadata)), 2, "manifest must be");
        }
        let bytes = vec![b' '; MAX_MANIFEST as usize + 2];
        let mut input = &bytes[..];
        io_refusal(
            read_manifest(&mut input, Ok((true, 0))),
            2,
            "manifest exceeds",
        );
        assert_eq!(input.len(), 1);
        assert_eq!(read_manifest(&b"ok"[..], Ok((true, 2))).unwrap(), b"ok");
        assert_eq!(open_manifest(Path::new("bad\0path")).unwrap_err().0, 2);
        let error = |errno| open_error(Path::new(FILE), std::io::Error::from_raw_os_error(errno)).0;
        for errno in [libc::ELOOP, libc::ENXIO, libc::EINVAL] {
            assert_eq!(error(errno), 2);
        }
        assert_eq!(error(libc::ENOENT), 1);
    }
}
