//! Bounded validation and summaries of one producer batch; no runtime or manifest.
use super::{manifest::UniqueValue, record::SCHEMA};
use rustix::fd::OwnedFd;
use rustix::fs::{openat, Mode, OFlags, CWD};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

struct Limits {
    batch: u64,
    end: u64,
    line: u64,
    lines: usize,
}
impl Limits {
    const DEFAULT: Self = Self {
        batch: 16 * 1024 * 1024,
        end: 1024 * 1024,
        line: 32 * 1024 * 1024,
        lines: 100_000,
    };
}
fn open_record_dir(dir: &Path) -> io::Result<OwnedFd> {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-GAP0-B4B5-M01","item":"ratarmount::sandbox::bench::summarize::open_record_dir","disposition":"out-of-family","category":"benchmark-record-input","reason":"Open the user-selected existing record directory with O_DIRECTORY and O_NOFOLLOW after removing trailing separators.","creation":{"policy":"none","basis":"Read-only existing record directory; no creation or truncation."}}"###
    )]
    let fd = openat(
        CWD,
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(fd)
}
fn open_record_input(parent: &OwnedFd, name: &str) -> io::Result<File> {
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-GAP0-B4B5-M02","item":"ratarmount::sandbox::bench::summarize::open_record_input","disposition":"out-of-family","category":"benchmark-record-input","reason":"Read only the four fixed record names relative to the held directory, without following symlinks or blocking on FIFOs; require regular files and bound reads.","creation":{"policy":"none","basis":"Read-only existing records; no creation or truncation."}}"###
    )]
    let fd = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let file = File::from(fd);
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("record input must be regular"));
    }
    Ok(file)
}
fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str, String> {
    v[field]
        .as_str()
        .ok_or_else(|| format!("invalid string {field:?}"))
}
fn integer(v: &Value, field: &str) -> Result<u64, String> {
    v[field]
        .as_u64()
        .ok_or_else(|| format!("invalid non-negative integer {field:?}"))
}
fn array<'a>(v: &'a Value, field: &str) -> Result<&'a [Value], String> {
    v[field]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("invalid array {field:?}"))
}
fn check(ok: bool, reason: impl Into<String>) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn context(name: &str, line: usize, e: impl std::fmt::Display) -> String {
    format!("{name}:{line}: {e}")
}
fn parse(bytes: &[u8], kind: &str, id: Option<&str>) -> Result<Value, String> {
    let value = serde_json::from_slice::<UniqueValue>(bytes)
        .map_err(|e| format!("{e:?}"))?
        .0;
    check(
        value.is_object() && value["schema"] == SCHEMA,
        "wrong schema",
    )?;
    check(value["record"] == kind, "wrong record discriminator")?;
    let batch = text(&value, "batch_id")?;
    if let Some(id) = id {
        check(batch == id, format!("mixed identity batch_id {batch:?}"))?;
    }
    Ok(value)
}
fn single(
    file: File,
    name: &str,
    limit: u64,
    kind: &str,
    id: Option<&str>,
) -> Result<Value, String> {
    let read = || -> Result<Value, String> {
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        check(bytes.len() as u64 <= limit, "oversized input")?;
        check(
            bytes.ends_with(b"\n") && !bytes[..bytes.len() - 1].contains(&b'\n'),
            "truncated or multiple lines",
        )?;
        parse(&bytes, kind, id)
    };
    read().map_err(|e| context(name, 1, e))
}
// Returns true for an uncommitted final run append; it is never parsed or counted.
fn lines(
    parent: &OwnedFd,
    name: &str,
    limits: &Limits,
    partial: bool,
    mut visit: impl FnMut(usize, &[u8]) -> Result<(), String>,
) -> Result<bool, String> {
    let file = open_record_input(parent, name).map_err(|e| context(name, 1, e))?;
    let mut reader = BufReader::new(file);
    let mut bytes = Vec::new();
    for index in 0.. {
        bytes.clear();
        reader
            .by_ref()
            .take(limits.line + 1)
            .read_until(b'\n', &mut bytes)
            .map_err(|e| context(name, index + 1, e))?;
        if bytes.is_empty() {
            return Ok(false);
        }
        let read = || -> Result<(), String> {
            check(index < limits.lines, "oversized line count")?;
            check(bytes.len() as u64 <= limits.line, "oversized line")?;
            check(bytes.ends_with(b"\n") || partial, "truncated final line")
        };
        read().map_err(|e| context(name, index + 1, e))?;
        if !bytes.ends_with(b"\n") {
            return Ok(true);
        }
        visit(index, &bytes).map_err(|e| context(name, index + 1, e))?;
    }
    unreachable!()
}
const OUTCOMES: [&str; 5] = ["passed", "failed", "blocked", "interrupted", "error"];
const KINDS: [&str; 4] = ["reference", "warmup", "measured", "empty-top-fuse-probe"];
fn counts() -> BTreeMap<String, u64> {
    OUTCOMES.into_iter().map(|s| (s.into(), 0)).collect()
}
struct Planned {
    canonical: String,
    key: String,
    kind: String,
    backend: String,
    repeat: Option<u64>,
}
fn planned(entry: &Value, header: &Value) -> Result<Planned, String> {
    let native = &header["settings"]["native"];
    for field in ["seed", "repeats", "attempts"] {
        integer(entry, field)?;
        check(entry[field] == native[field], "incompatible settings")?;
    }
    check(
        entry["catalog_revision"] == header["catalog_revision"],
        "incompatible settings catalog_revision",
    )?;
    let cell = &entry["cell"];
    for field in ["base_form", "cache", "jobs"] {
        check(
            array(native, field)?.contains(&cell[field]),
            "incompatible settings cell",
        )?;
    }
    integer(cell, "jobs")?;
    for (field, rows) in [("task", "tasks"), ("platform", "platforms")] {
        let id = text(cell, field)?;
        check(
            array(header, rows)?.iter().any(|v| v["id"] == id),
            format!("mixed identity {field} {id:?}"),
        )?;
    }
    let kind = text(entry, "kind")?;
    check(KINDS.contains(&kind), format!("unknown kind {kind:?}"))?;
    let backend = text(entry, "backend")?;
    check(
        ["native", "fuse"].contains(&backend),
        format!("unknown backend {backend:?}"),
    )?;
    let repeat = if kind == "measured" {
        Some(integer(entry, "repeat")?)
    } else {
        None
    };
    check(
        entry["schema"] == "rrs-perl-bench-schedule/1",
        "wrong entry schema",
    )?;
    integer(entry, "cpus")?;
    for field in [
        "paired",
        "allow_oversubscription",
        "oversubscribed",
        "qualified",
    ] {
        check(
            entry[field].is_boolean(),
            format!("invalid boolean {field:?}"),
        )?;
    }
    let mut key = json!({"cell":{"task":cell["task"],"platform":cell["platform"],"base_form":cell["base_form"],"jobs":cell["jobs"],"cache":cell["cache"]}});
    for field in [
        "catalog_revision",
        "schema",
        "paired",
        "seed",
        "repeats",
        "attempts",
        "cpus",
        "allow_oversubscription",
        "oversubscribed",
        "qualified",
    ] {
        key[field] = entry[field].clone();
    }
    Ok(Planned {
        canonical: entry.to_string(),
        key: key.to_string(),
        kind: kind.into(),
        backend: backend.into(),
        repeat,
    })
}
#[derive(Default)]
struct Samples {
    times: Vec<u64>,
    repeats: BTreeMap<u64, u64>,
}
fn rank(n: usize, p: usize) -> usize {
    (p * n).div_ceil(100) - 1
}
fn summarize_dir(dir: &Path, limits: &Limits) -> Result<Value, String> {
    let dir: PathBuf = dir.components().collect();
    let parent = open_record_dir(&dir).map_err(|e| context("DIR", 1, format!("{dir:?}: {e}")))?;
    let file = open_record_input(&parent, "batch.json").map_err(|e| context("batch.json", 1, e))?;
    let header = single(file, "batch.json", limits.batch, "batch", None)?;
    let id = text(&header, "batch_id")?;
    let end = match open_record_input(&parent, "batch-end.json") {
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(context("batch-end.json", 1, e)),
        Ok(file) => Some(single(
            file,
            "batch-end.json",
            limits.end,
            "batch-end",
            Some(id),
        )?),
    };
    let validate_header = || -> Result<(), String> {
        for field in ["fixture", "publishable"] {
            check(
                header[field].is_boolean(),
                format!("invalid boolean {field:?}"),
            )?;
        }
        for field in ["runtime", "load"] {
            check(
                header[field].is_object(),
                format!("invalid object {field:?}"),
            )?;
        }
        text(&header, "catalog_revision")?;
        for field in ["seed", "repeats", "attempts"] {
            integer(&header["settings"]["native"], field)?;
        }
        Ok(())
    };
    validate_header().map_err(|e| context("batch.json", 1, e))?;
    let mut schedule = Vec::new();
    let mut repeats = BTreeSet::new();
    lines(&parent, "schedule.jsonl", limits, false, |index, bytes| {
        let row = parse(bytes, "schedule", Some(id))?;
        check(
            integer(&row, "sequence")? == index as u64,
            "duplicate or sequence gap",
        )?;
        check(
            row["run_id"] == format!("{id}-{index}"),
            format!("duplicate or wrong run_id {:?}", row["run_id"]),
        )?;
        let entry = planned(&row["entry"], &header)?;
        if let Some(repeat) = entry.repeat {
            check(
                repeats.insert((entry.key.clone(), entry.backend.clone(), repeat)),
                "duplicate repeat",
            )?;
        }
        schedule.push(entry);
        Ok(())
    })?;
    check(
        !schedule.is_empty(),
        context("schedule.jsonl", 1, "empty schedule"),
    )?;
    let mut totals = counts();
    let mut by_kind: BTreeMap<_, _> = KINDS.into_iter().map(|kind| (kind, counts())).collect();
    let mut groups: BTreeMap<(String, String), Samples> = BTreeMap::new();
    let mut terminals = 0;
    let partial = lines(
        &parent,
        "runs.jsonl",
        limits,
        end.is_none(),
        |index, bytes| {
            let row = parse(bytes, "run", Some(id))?;
            check(
                integer(&row, "index")? == index as u64,
                "duplicate or sequence gap",
            )?;
            let entry = schedule.get(index).ok_or("extra terminal")?;
            check(
                row["run_id"] == format!("{id}-{index}"),
                format!("wrong run_id {:?}", row["run_id"]),
            )?;
            let canonical = row["schedule"].to_string();
            check(
                canonical == entry.canonical,
                "incompatible settings schedule",
            )?;
            for field in ["runtime", "fixture", "publishable", "load"] {
                check(
                    row[field] == header[field],
                    format!("mixed identity {field}"),
                )?;
            }
            let outcome = text(&row, "outcome")?;
            check(
                OUTCOMES.contains(&outcome),
                format!("unknown outcome {outcome:?}"),
            )?;
            let time = integer(&row["lifecycle_ms"], "total")?;
            *totals.get_mut(outcome).unwrap() += 1;
            *by_kind
                .get_mut(entry.kind.as_str())
                .unwrap()
                .get_mut(outcome)
                .unwrap() += 1;
            if entry.kind == "measured" && outcome == "passed" {
                let samples = groups
                    .entry((entry.key.clone(), entry.backend.clone()))
                    .or_default();
                samples.times.push(time);
                if let Some(repeat) = entry.repeat {
                    samples.repeats.insert(repeat, time);
                }
            }
            terminals += 1;
            Ok(())
        },
    )?;
    let mut status = "incomplete";
    let mut wall = 0;
    if let Some(end) = end {
        let validate_end = || -> Result<(&'static str, u64), String> {
            check(terminals == schedule.len(), "missing terminal")?;
            check(end["counts"] == json!(totals), "counts mismatch")?;
            let expected = if totals["interrupted"] > 0 {
                "interrupted"
            } else if !end["error"].is_null() || totals["error"] > 0 {
                "error"
            } else if totals["failed"] + totals["blocked"] > 0 {
                "failed"
            } else {
                "passed"
            };
            check(end["status"] == expected, "status mismatch")?;
            Ok((expected, integer(&end, "wall_ms")?))
        };
        (status, wall) = validate_end().map_err(|e| context("batch-end.json", 1, e))?;
    }
    debug_assert!(!partial || status == "incomplete");
    let mut distributions = Vec::new();
    let mut ratios = Vec::new();
    for ((key, backend), samples) in &mut groups {
        samples.times.sort_unstable();
        let n = samples.times.len();
        distributions.push(json!({"key":serde_json::from_str::<Value>(key).unwrap(),"backend":backend,"samples":n,"attempt_ms":samples.times,"median_ms":samples.times[rank(n,50)],"p95_ms":samples.times[rank(n,95)]}));
    }
    for ((key, backend), samples) in &groups {
        if backend != "fuse" {
            continue;
        }
        if let Some(native) = groups.get(&(key.clone(), "native".into())) {
            let mut values: Vec<f64> = samples
                .repeats
                .iter()
                .filter_map(|(repeat, time)| {
                    let denominator = *native.repeats.get(repeat)?;
                    (denominator != 0).then_some(*time as f64 / denominator as f64)
                })
                .collect();
            values.sort_by(f64::total_cmp);
            let n = values.len();
            if n > 0 {
                ratios.push(json!({"key":serde_json::from_str::<Value>(key).unwrap(),"pairs":n,"median":values[rank(n,50)],"p95":values[rank(n,95)]}));
            }
        }
    }
    let measured: usize = groups.values().map(|s| s.times.len()).sum();
    let throughput = if status == "passed" && wall > 0 {
        Some(measured as f64 * 3_600_000.0 / wall as f64)
    } else {
        None
    };
    Ok(
        json!({"status":status,"batch_id":id,"fixture":header["fixture"],"publishable":header["publishable"],"counts":by_kind,"graded_attempts":totals["passed"]+totals["failed"],"groups":distributions,"ratios":ratios,"verified_attempts_per_hour":throughput,"throughput_note":if status == "passed" && wall == 0 { Some("zero wall time") } else { None }}),
    )
}
pub(super) fn run(dir: &Path) -> Result<i32, String> {
    let report = match summarize_dir(dir, &Limits::DEFAULT) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("sandbox bench summarize: invalid records: {error}");
            return Ok(2);
        }
    };
    let status = report["status"].as_str().unwrap();
    let groups = report["groups"].as_array().unwrap();
    let samples: u64 = groups.iter().map(|g| g["samples"].as_u64().unwrap()).sum();
    let rate = report["verified_attempts_per_hour"]
        .as_f64()
        .map(|v| format!("; {v:.2}/hour"))
        .unwrap_or_default();
    let fixture = if report["fixture"] == true {
        "; stub fixture, not publishable"
    } else {
        ""
    };
    let mut bytes = serde_json::to_vec(&report).map_err(|e| format!("summarize report: {e}"))?;
    bytes.push(b'\n');
    if let Err(error) = io::stdout().lock().write_all(&bytes) {
        eprintln!("sandbox bench summarize: report failure: {error}");
        return Ok(1);
    }
    let message = format!("sandbox bench summarize: {status}: {samples} measured samples in {} groups{rate}{fixture}\n", groups.len());
    if io::stderr().lock().write_all(message.as_bytes()).is_err() {
        return Ok(1);
    }
    Ok(i32::from(status != "passed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::bench::{schedule, Selection};

    struct Fixture {
        dir: tempfile::TempDir,
        header: Value,
        schedule: Vec<Value>,
        runs: Vec<Value>,
        end: Option<Value>,
    }
    impl Fixture {
        fn new() -> Self {
            let mut catalog = super::super::tests::fixture();
            let mut task = catalog["tasks"][0].clone();
            task["id"] = "second".into();
            catalog["tasks"].as_array_mut().unwrap().push(task);
            let entries = schedule::build(
                &serde_json::to_vec(&catalog).unwrap(),
                &Selection {
                    backend: vec![schedule::Backend::Native, schedule::Backend::Fuse],
                    cache: vec![schedule::Cache::Warm],
                    base_form: vec![schedule::BaseForm::TarZstSingleFrame],
                    repeats: Some(3),
                    ..Default::default()
                },
            )
            .unwrap();
            let header = json!({"schema":SCHEMA,"record":"batch","batch_id":"batch","catalog_revision":"test-1",
                "tasks":catalog["tasks"],"platforms":catalog["platforms"],"fixture":true,"publishable":false,
                "runtime":{"kind":"stub","path":"fixture"},"load":{},
                "settings":{"native":{"seed":1,"repeats":3,"attempts":1,"base_form":["tar.zst-single-frame"],"cache":["warm"],"jobs":[1]}}});
            let schedule: Vec<_> = entries.iter().enumerate().map(|(i,e)| json!({"schema":SCHEMA,"record":"schedule","batch_id":"batch","run_id":format!("batch-{i}"),"sequence":i,"entry":e})).collect();
            let runs = schedule.iter().enumerate().map(|(i,s)| json!({"schema":SCHEMA,"record":"run","batch_id":"batch","run_id":s["run_id"],"index":i,"schedule":s["entry"],"outcome":"passed","runtime":header["runtime"],"fixture":true,"publishable":false,"load":{},"lifecycle_ms":{"total":(i+1)*10}})).collect();
            let mut f = Self {
                dir: tempfile::tempdir().unwrap(),
                header,
                schedule,
                runs,
                end: Some(
                    json!({"schema":SCHEMA,"record":"batch-end","batch_id":"batch","wall_ms":1000,"error":null}),
                ),
            };
            f.refresh();
            f
        }
        fn refresh(&mut self) {
            let mut totals = counts();
            for row in &self.runs {
                *totals.get_mut(row["outcome"].as_str().unwrap()).unwrap() += 1;
            }
            if let Some(end) = &mut self.end {
                end["counts"] = json!(totals);
                end["status"] = if totals["interrupted"] > 0 {
                    "interrupted"
                } else if totals["error"] > 0 || !end["error"].is_null() {
                    "error"
                } else if totals["failed"] + totals["blocked"] > 0 {
                    "failed"
                } else {
                    "passed"
                }
                .into();
            }
        }
        fn save(&self) {
            for (name, rows) in [
                ("batch.json", vec![self.header.clone()]),
                ("schedule.jsonl", self.schedule.clone()),
                ("runs.jsonl", self.runs.clone()),
            ] {
                let bytes: String = rows.iter().map(|r| format!("{r}\n")).collect();
                std::fs::write(self.dir.path().join(name), bytes).unwrap();
            }
            let path = self.dir.path().join("batch-end.json");
            if let Some(end) = &self.end {
                std::fs::write(path, format!("{end}\n")).unwrap();
            } else if path.exists() {
                std::fs::remove_file(path).unwrap();
            }
        }
        fn report(&self) -> Value {
            self.save();
            summarize_dir(self.dir.path(), &Limits::DEFAULT).unwrap()
        }
        fn refuses(&self, reason: &str) {
            let result = summarize_dir(self.dir.path(), &Limits::DEFAULT);
            assert!(
                result.is_err(),
                "expected invalid records: {reason}; got {result:?}"
            );
            let error = result.unwrap_err();
            assert!(error.contains(reason), "{error}; expected {reason}");
            assert!(
                !error.contains(['\x1b', '\n']),
                "unescaped diagnostic: {error:?}"
            );
            assert_eq!(run(self.dir.path()).unwrap(), 2);
        }
    }
    // Regression: warm-ups, references, probes and unsuccessful measurements polluted samples.
    #[test]
    fn regression_bench_summary_excludes_nonmeasurement_rows() {
        let mut f = Fixture::new();
        let measured: Vec<_> = f
            .runs
            .iter()
            .enumerate()
            .filter(|(_, r)| r["schedule"]["kind"] == "measured")
            .map(|(i, _)| i)
            .collect();
        f.runs[measured[0]]["outcome"] = "failed".into();
        f.runs[measured[1]]["outcome"] = "blocked".into();
        f.refresh();
        let report = f.report();
        assert_eq!(report["counts"]["measured"]["failed"], 1);
        assert_eq!(report["counts"]["measured"]["blocked"], 1);
        for (kind, n) in [("reference", 2), ("warmup", 4), ("empty-top-fuse-probe", 2)] {
            assert_eq!(report["counts"][kind]["passed"], n);
        }
        assert_eq!(report["graded_attempts"], f.runs.len() - 1);
        let mut expected: Vec<_> = measured[2..]
            .iter()
            .map(|&i| f.runs[i]["lifecycle_ms"]["total"].as_u64().unwrap())
            .collect();
        let mut actual: Vec<_> = report["groups"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|g| {
                g["attempt_ms"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_u64().unwrap())
            })
            .collect();
        expected.sort();
        actual.sort();
        assert_eq!(actual, expected, "only passed measured samples");
        assert_eq!(
            report["groups"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| g["samples"].as_u64().unwrap())
                .sum::<u64>(),
            10
        );
    }
    // Regression: mixed settings, partial appends, unsafe inputs and duplicate keys looked valid.
    #[test]
    fn regression_bench_summary_rejects_mixed_identity_and_truncation() {
        for (file, pointer, value, reason) in [
            (
                "schedule",
                "/0/batch_id",
                json!("foreign\x1b\n"),
                "mixed identity",
            ),
            ("runs", "/0/run_id", json!("wrong"), "run_id"),
            (
                "runs",
                "/0/schedule/cpus",
                json!(999),
                "incompatible settings",
            ),
            (
                "header",
                "/settings/native/seed",
                json!(42),
                "incompatible settings",
            ),
            ("schedule", "/1/sequence", json!(0), "duplicate"),
            ("runs", "/1/index", json!(0), "duplicate"),
            ("runs", "/0/schema", json!("wrong"), "schema"),
            ("runs", "/0/record", json!("schedule"), "record"),
            ("runs", "/0/outcome", json!("unknown"), "outcome"),
            (
                "runs",
                "/0/lifecycle_ms/total",
                json!(-1),
                "non-negative integer",
            ),
            (
                "runs",
                "/0/lifecycle_ms/total",
                json!(1.5),
                "non-negative integer",
            ),
            ("schedule", "/0/entry/kind", json!("unknown"), "kind"),
            (
                "schedule",
                "/3/entry/repeat",
                json!(1.5),
                "non-negative integer",
            ),
            ("runs", "/0/runtime/kind", json!("docker"), "mixed identity"),
            ("end", "/wall_ms", json!(-1), "non-negative integer"),
        ] {
            let mut f = Fixture::new();
            let mut values = match file {
                "schedule" => json!(f.schedule),
                "runs" => json!(f.runs),
                "header" => f.header.clone(),
                _ => f.end.clone().unwrap(),
            };
            *values.pointer_mut(pointer).unwrap() = value;
            match file {
                "schedule" => f.schedule = serde_json::from_value(values).unwrap(),
                "runs" => f.runs = serde_json::from_value(values).unwrap(),
                "header" => f.header = values,
                _ => f.end = Some(values),
            }
            f.save();
            f.refuses(reason);
        }
        // Regression: duplicate measured repeats overwrote pairs or escaped when unsuccessful.
        for outcome in OUTCOMES {
            let mut f = Fixture::new();
            let index = f
                .schedule
                .iter()
                .position(|s| s["entry"]["kind"] == "measured")
                .unwrap();
            let n = f.schedule.len();
            let mut scheduled = f.schedule[index].clone();
            scheduled["sequence"] = json!(n);
            scheduled["run_id"] = json!(format!("batch-{n}"));
            let mut terminal = f.runs[index].clone();
            terminal["index"] = json!(n);
            terminal["run_id"] = scheduled["run_id"].clone();
            terminal["outcome"] = outcome.into();
            f.runs[index]["outcome"] = outcome.into();
            f.schedule.push(scheduled);
            f.runs.push(terminal);
            f.refresh();
            f.save();
            f.refuses("duplicate repeat");
            f.schedule[n]["entry"]["cell"]["extra"] = json!(true);
            f.runs[n]["schedule"] = f.schedule[n]["entry"].clone();
            f.save();
            f.refuses("duplicate repeat");
        }
        for (case, reason) in [
            ("schedule-truncated", "truncated"),
            ("runs-truncated", "truncated"),
            ("extra", "extra terminal"),
            ("empty", "empty schedule"),
            ("duplicate-key", "duplicate key"),
            ("nested-duplicate", "duplicate key"),
            ("multiline-header", "multiple lines"),
        ] {
            let mut f = Fixture::new();
            if case == "extra" {
                let mut row = f.runs[0].clone();
                let n = f.runs.len();
                row["index"] = json!(n);
                row["run_id"] = json!(format!("batch-{n}"));
                f.runs.push(row);
            }
            if case == "empty" {
                f.schedule.clear();
            }
            f.save();
            let name = if case == "schedule-truncated" {
                "schedule.jsonl"
            } else if case == "runs-truncated" {
                "runs.jsonl"
            } else {
                "batch.json"
            };
            let path = f.dir.path().join(name);
            let mut bytes = std::fs::read(&path).unwrap();
            if case.ends_with("truncated") {
                bytes.pop();
            }
            if case == "duplicate-key" {
                bytes.splice(1..1, b"\"schema\":\"rrs-perl-bench/1\",".iter().copied());
            }
            if case == "nested-duplicate" {
                bytes = String::from_utf8(bytes)
                    .unwrap()
                    .replace("\"load\":{}", "\"load\":{\"a\":1,\"a\":2}")
                    .into_bytes();
            }
            if case == "multiline-header" {
                bytes.extend_from_within(..);
            }
            std::fs::write(path, bytes).unwrap();
            f.refuses(reason);
        }
        let mut f = Fixture::new();
        f.end = None;
        f.save();
        let path = f.dir.path().join("runs.jsonl");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(b"{partial");
        std::fs::write(path, bytes).unwrap();
        let report = summarize_dir(f.dir.path(), &Limits::DEFAULT).unwrap();
        assert_eq!(report["status"], "incomplete");
        assert!(report["verified_attempts_per_hour"].is_null());
        for name in ["batch.json", "schedule.jsonl", "runs.jsonl"] {
            let f = Fixture::new();
            f.save();
            std::fs::remove_file(f.dir.path().join(name)).unwrap();
            f.refuses(name);
        }
        for field in ["batch", "end", "line", "lines"] {
            let f = Fixture::new();
            f.save();
            let mut limits = Limits::DEFAULT;
            match field {
                "batch" => limits.batch = 8,
                "end" => limits.end = 8,
                "line" => limits.line = 8,
                _ => limits.lines = 1,
            }
            let result = summarize_dir(f.dir.path(), &limits);
            assert!(result.is_err(), "limit {field}");
            assert!(result.unwrap_err().contains("oversized"), "limit {field}");
        }
        let f = Fixture::new();
        f.save();
        let links = tempfile::tempdir().unwrap();
        let link = links.path().join("link");
        std::os::unix::fs::symlink(f.dir.path(), &link).unwrap();
        for path in [link.clone(), PathBuf::from(format!("{}/", link.display()))] {
            assert!(
                summarize_dir(&path, &Limits::DEFAULT).is_err(),
                "symlink DIR {path:?}"
            );
        }
        std::fs::remove_file(link).unwrap();
        for name in [
            "batch.json",
            "schedule.jsonl",
            "runs.jsonl",
            "batch-end.json",
        ] {
            let f = Fixture::new();
            f.save();
            let path = f.dir.path().join(name);
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink("/dev/null", path).unwrap();
            f.refuses(name);
        }
    }
    // Regression: absent terminals and contradictory end status yielded throughput or success.
    #[test]
    fn regression_bench_summary_failed_or_missing_runs_nonzero() {
        let mut f = Fixture::new();
        f.end = None;
        let report = f.report();
        assert_eq!(report["status"], "incomplete");
        assert!(report["verified_attempts_per_hour"].is_null());
        assert_eq!(run(f.dir.path()).unwrap(), 1);
        let mut f = Fixture::new();
        f.runs.pop();
        f.refresh();
        f.save();
        f.refuses("missing terminal");
        for outcome in ["failed", "interrupted", "error"] {
            let mut f = Fixture::new();
            f.runs[0]["outcome"] = outcome.into();
            f.refresh();
            let report = f.report();
            assert_eq!(report["status"], outcome);
            assert!(report["verified_attempts_per_hour"].is_null());
            assert_eq!(run(f.dir.path()).unwrap(), 1);
        }
        for case in ["counts", "passed-with-failed", "failed-with-error"] {
            let mut f = Fixture::new();
            match case {
                "counts" => f.end.as_mut().unwrap()["counts"]["passed"] = json!(999),
                "passed-with-failed" => {
                    f.runs[0]["outcome"] = "failed".into();
                    f.refresh();
                    f.end.as_mut().unwrap()["status"] = "passed".into();
                }
                _ => {
                    f.end.as_mut().unwrap()["error"] = "cleanup".into();
                    f.end.as_mut().unwrap()["status"] = "failed".into();
                }
            }
            f.save();
            f.refuses(if case == "counts" {
                "counts mismatch"
            } else {
                "status mismatch"
            });
        }
    }
    // Regression: averaged medians, floor p95, position pairing and per-cell clocks skewed results.
    #[test]
    fn regression_bench_summary_quantiles_pairs_and_batch_denominator() {
        for (n, median, p95) in [(1, 1, 1), (2, 1, 2), (5, 3, 5), (20, 10, 19)] {
            let mut f = Fixture::new();
            let template = f
                .schedule
                .iter()
                .find(|s| s["entry"]["kind"] == "measured")
                .unwrap()
                .clone();
            f.schedule = (0..n)
                .map(|i| {
                    let mut s = template.clone();
                    s["sequence"] = json!(i);
                    s["run_id"] = json!(format!("batch-{i}"));
                    s["entry"]["backend"] = "native".into();
                    s["entry"]["repeat"] = json!(i + 1);
                    s
                })
                .collect();
            let row = f.runs[0].clone();
            f.runs = f
                .schedule
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let mut r = row.clone();
                    r["index"] = json!(i);
                    r["run_id"] = s["run_id"].clone();
                    r["schedule"] = s["entry"].clone();
                    r["lifecycle_ms"]["total"] = json!(n - i);
                    r
                })
                .collect();
            f.refresh();
            let report = f.report();
            let group = &report["groups"][0];
            assert_eq!(group["samples"], n);
            assert_eq!(group["median_ms"], median, "n={n}");
            assert_eq!(group["p95_ms"], p95, "n={n}");
        }
        let mut f = Fixture::new();
        for row in &mut f.runs {
            let entry = &row["schedule"];
            if entry["kind"] != "measured" {
                continue;
            }
            let repeat = entry["repeat"].as_u64().unwrap();
            row["lifecycle_ms"]["total"] = json!(if entry["backend"] == "native" {
                repeat * 10
            } else {
                match repeat {
                    1 => 90,
                    2 => 20,
                    _ => 60,
                }
            });
        }
        // Leave one unmatched repeat per cell; pair order differs from repeat order.
        for i in 0..f.schedule.len() {
            if f.schedule[i]["entry"]["kind"] == "measured"
                && f.schedule[i]["entry"]["backend"] == "fuse"
                && f.schedule[i]["entry"]["repeat"] == 1
            {
                f.schedule[i]["entry"]["repeat"] = json!(99);
                f.runs[i]["schedule"] = f.schedule[i]["entry"].clone();
            }
        }
        f.refresh();
        let report = f.report();
        assert_eq!(report["groups"].as_array().unwrap().len(), 4);
        let ratios = report["ratios"].as_array().unwrap();
        assert_eq!(
            ratios.len(),
            2,
            "backend-derived reasons must not split cells"
        );
        for ratio in ratios {
            assert_eq!(ratio["pairs"], 2);
            assert_eq!(ratio["median"], 1.0);
            assert_eq!(ratio["p95"], 2.0);
        }
        assert_eq!(
            report["verified_attempts_per_hour"], 43200.0,
            "one shared batch denominator"
        );
        f.end.as_mut().unwrap()["wall_ms"] = json!(0);
        let report = f.report();
        assert!(report["verified_attempts_per_hour"].is_null());
        assert_eq!(report["throughput_note"], "zero wall time");
    }
}
