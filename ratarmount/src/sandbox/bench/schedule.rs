//! Pure admission and deterministic scheduling of an already validated manifest.

use super::Selection;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Backend {
    Native,
    Fuse,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(super) enum BaseForm {
    Git,
    #[value(name = "tar.zst-single-frame")]
    #[serde(rename = "tar.zst-single-frame")]
    TarZstSingleFrame,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Cache {
    Cold,
    Warm,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Kind {
    Reference,
    Warmup,
    Measured,
    EmptyTopFuseProbe,
}
#[derive(Debug, Clone, Serialize)]
pub(super) struct Cell {
    pub task: String,
    pub platform: String,
    pub base_form: BaseForm,
    pub jobs: u32,
    pub cache: Cache,
}
impl Cell {
    fn identity(&self) -> String {
        serde_json::to_string(&(
            &self.task,
            &self.platform,
            self.base_form,
            self.jobs,
            self.cache,
        ))
        .expect("scalar cell identity serializes")
    }
}
#[derive(Debug, Clone, Serialize)]
pub(super) struct Entry {
    schema: &'static str,
    catalog_revision: String,
    pub cell: Cell,
    kind: Kind,
    pub backend: Backend,
    repeat: Option<u32>,
    discarded: bool,
    paired: bool,
    seed: u64,
    repeats: u32,
    attempts: u32,
    cpus: u32,
    allow_oversubscription: bool,
    oversubscribed: bool,
    qualified: bool,
    execution_available: bool,
    pub runnable: bool,
    reasons: Vec<String>,
}
impl Entry {
    pub(super) fn is_probe(&self) -> bool {
        self.kind == Kind::EmptyTopFuseProbe
    }
    pub(super) fn is_reference(&self) -> bool {
        self.kind == Kind::Reference
    }
}
// A scheduling projection, decoded only after B2 validates every manifest field.
#[derive(Deserialize)]
struct Manifest {
    catalog_revision: String,
    tasks: Vec<Task>,
}
#[derive(Deserialize)]
struct Task {
    id: String,
    backends: Vec<Backend>,
    platforms: Vec<Row>,
    resources: Resources,
}
#[derive(Deserialize)]
struct Resources {
    cpus: u32,
}
#[derive(Deserialize)]
struct Row {
    platform_id: String,
    candidate_jobs: Vec<u32>,
    supported_jobs: Vec<u32>,
    qualification: Qualification,
}
#[derive(Deserialize)]
struct Qualification {
    qualified: bool,
    reasons: Vec<String>,
}
fn selected<T: Clone + Ord>(values: &[T], defaults: &[T]) -> Vec<T> {
    let mut result = if values.is_empty() { defaults } else { values }.to_vec();
    result.sort();
    result.dedup();
    result
}
fn hash(domain: &str, seed: u64, identity: &str) -> String {
    // Reuse sandbox/requests.rs:360-389: sha2 Digest/Sha256, digest bytes, hex format.
    let bytes = serde_json::to_vec(&(domain, seed, identity)).expect("hash input serializes");
    format!("{:x}", Sha256::digest(&bytes))
}
pub(super) fn build(bytes: &[u8], options: &Selection) -> Result<Vec<Entry>, String> {
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let (seed, repeats, attempts) = (
        options.seed.unwrap_or(1),
        options.repeats.unwrap_or(5),
        options.attempts.unwrap_or(1),
    );
    if attempts != 1 {
        return Err("--attempts accepts only 1; concurrent attempts are unsupported".into());
    }
    if !(1..=100).contains(&repeats) {
        return Err("--repeats must be in 1..=100".into());
    }
    for id in &options.task {
        if !manifest.tasks.iter().any(|task| &task.id == id) {
            return Err(format!("unknown task {id:?}"));
        }
    }
    let mut cells = Vec::new();
    let mut total_entries = 0;
    for task in &manifest.tasks {
        if !options.task.is_empty() && !options.task.contains(&task.id) {
            continue;
        }
        let backends = selected(&options.backend, &task.backends);
        if backends.iter().any(|b| !task.backends.contains(b)) {
            return Err(format!("task {:?}: unsupported backend selection", task.id));
        }
        for row in &task.platforms {
            for jobs in selected(&options.jobs, &[1]) {
                if !row.candidate_jobs.contains(&jobs)
                    || (row.qualification.qualified && !row.supported_jobs.contains(&jobs))
                {
                    return Err(format!(
                        "task {:?}, platform {:?}: unsupported jobs {jobs}",
                        task.id, row.platform_id
                    ));
                }
                let oversubscribed = jobs > task.resources.cpus;
                if oversubscribed && !options.allow_oversubscription {
                    return Err(format!(
                        "task {:?}: jobs {jobs} exceeds cpus {}; use --allow-oversubscription",
                        task.id, task.resources.cpus
                    ));
                }
                for base_form in selected(
                    &options.base_form,
                    &[BaseForm::Git, BaseForm::TarZstSingleFrame],
                ) {
                    for cache in selected(&options.cache, &[Cache::Cold, Cache::Warm]) {
                        // Cap all entries before allocating their list: at most 2*100+4 per cell.
                        total_entries += 1
                            + backends.len()
                                * (repeats as usize + usize::from(cache == Cache::Warm))
                            + usize::from(backends.contains(&Backend::Fuse));
                        if total_entries > 100_000 {
                            return Err("schedule exceeds the 100000 total-entry cap".into());
                        }
                        let cell = Cell {
                            task: task.id.clone(),
                            platform: row.platform_id.clone(),
                            base_form,
                            jobs,
                            cache,
                        };
                        let identity = cell.identity();
                        let mut reasons = row.qualification.reasons.clone();
                        reasons.push("execution unavailable: selection or qualification unsupported by native lifecycle".into());
                        let entry = Entry {
                            schema: "rrs-perl-bench-schedule/1",
                            catalog_revision: manifest.catalog_revision.clone(),
                            cell,
                            kind: Kind::Reference,
                            backend: Backend::Native,
                            repeat: None,
                            discarded: false,
                            paired: backends.len() == 2,
                            seed,
                            repeats,
                            attempts,
                            cpus: task.resources.cpus,
                            allow_oversubscription: options.allow_oversubscription,
                            oversubscribed,
                            qualified: row.qualification.qualified,
                            execution_available: false,
                            runnable: false,
                            reasons,
                        };
                        cells.push((
                            hash("rrs-perl-bench/cell-order/1", seed, &identity),
                            identity,
                            entry,
                            backends.clone(),
                        ));
                    }
                }
            }
        }
    }
    // Identity breaks even a digest collision; manifest/selection order is irrelevant.
    cells.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    let mut entries = Vec::new();
    for (_, identity, mut entry, mut backends) in cells {
        // A separate domain chooses AB versus BA without coupling to cell sorting.
        if entry.paired
            && hash("rrs-perl-bench/backend-orientation/1", seed, &identity).as_bytes()[0] <= b'7'
        {
            backends.reverse();
        }
        entries.push(entry.clone()); // Native reference precedes every dependent entry.
        if entry.cell.cache == Cache::Warm {
            entry.kind = Kind::Warmup;
            entry.discarded = true;
            for backend in &backends {
                entry.backend = *backend;
                entries.push(entry.clone());
            }
        }
        entry.kind = Kind::Measured;
        entry.discarded = false;
        for repeat in 1..=repeats {
            entry.repeat = Some(repeat);
            for backend in &backends {
                entry.backend = *backend;
                entries.push(entry.clone());
            }
            // Each repeat is a complete pair, including an odd final repeat.
            if entry.paired {
                backends.reverse();
            }
        }
        if backends.contains(&Backend::Fuse) {
            entry.kind = Kind::EmptyTopFuseProbe;
            entry.backend = Backend::Fuse;
            entry.repeat = None;
            entries.push(entry);
        }
    }
    for entry in &mut entries {
        entry.execution_available = entry.qualified
            && matches!(entry.backend, Backend::Native | Backend::Fuse)
            && entry.cell.base_form == BaseForm::TarZstSingleFrame
            && entry.cell.cache == Cache::Warm;
        entry.runnable = entry.execution_available;
        if entry.execution_available {
            entry.reasons.pop();
            entry
                .reasons
                .push(if entry.kind == Kind::EmptyTopFuseProbe { "execution available: lifecycle-only probe, not suite-graded; stub runtime output is fixture-only" } else { "execution available: graded against the native reference; stub runtime output is fixture-only" }.into());
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::bench::tests::{fixture, valid};

    fn schedule(options: &Selection) -> Vec<Entry> {
        valid(&fixture(), true).unwrap();
        build(&serde_json::to_vec(&fixture()).unwrap(), options).unwrap()
    }
    fn measured(entries: &[Entry]) -> Vec<Backend> {
        entries
            .iter()
            .filter(|e| e.kind == Kind::Measured)
            .map(|e| e.backend)
            .collect()
    }
    // Regression: iteration order or an ignored seed changed deterministic cell/backend order.
    #[test]
    fn regression_bench_schedule_seed_reproducible() {
        let mut options = Selection::default();
        let first = schedule(&options);
        assert!(first.iter().all(|e| e.qualified
            && e.execution_available == e.runnable
            && e.runnable
                == (matches!(e.backend, Backend::Native | Backend::Fuse)
                    && e.cell.base_form == BaseForm::TarZstSingleFrame
                    && e.cell.cache == Cache::Warm)));
        assert!(first
            .iter()
            .any(|e| e.backend == Backend::Fuse && e.kind == Kind::Measured && e.runnable));
        assert!(first.iter().any(|e| e.kind == Kind::EmptyTopFuseProbe && e.runnable && e.reasons.iter().any(|r| r == "execution available: lifecycle-only probe, not suite-graded; stub runtime output is fixture-only")));
        let bytes = serde_json::to_vec(&first).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&schedule(&options)).unwrap());
        let identities: Vec<_> = first
            .iter()
            .filter(|e| e.kind == Kind::Reference)
            .map(|e| e.cell.identity())
            .collect();
        assert_eq!(identities.len(), 4);
        assert_eq!(
            hash("rrs-perl-bench/cell-order/1", 1, &identities[0]),
            "876edaff1ccd5702cf684410dcbd0a070f45834f40977fceef7f044416193aab"
        );
        options.seed = Some(2);
        let second = schedule(&options);
        let identity = second
            .iter()
            .filter(|e| e.kind == Kind::Measured)
            .nth(10)
            .unwrap()
            .cell
            .identity();
        assert!(hash("rrs-perl-bench/backend-orientation/1", 2, &identity).starts_with('c'));
        assert_eq!(measured(&second)[10], Backend::Native);
        assert_ne!(
            identities,
            second
                .iter()
                .filter(|e| e.kind == Kind::Reference)
                .map(|e| e.cell.identity())
                .collect::<Vec<_>>()
        );
        assert_ne!(measured(&first), measured(&second));
        assert_eq!(measured(&first)[0], Backend::Native);
        assert_eq!(measured(&second)[0], Backend::Fuse);
        assert!(first.iter().all(|e| e.seed == 1));
        assert!(second.iter().all(|e| e.seed == 2));
        options.base_form = vec![BaseForm::TarZstSingleFrame, BaseForm::Git, BaseForm::Git];
        options.cache = vec![Cache::Warm, Cache::Cold];
        options.backend = vec![Backend::Fuse, Backend::Native];
        options.seed = Some(1);
        assert_eq!(bytes, serde_json::to_vec(&schedule(&options)).unwrap());
    }
    // Regression: odd repeats lost a backend, or pairs failed to alternate AB/BA.
    #[test]
    fn regression_bench_schedule_abba_and_odd_repeat_balance() {
        for seed in 1..=4 {
            for repeats in [1, 2, 3, 5] {
                let mut options = Selection {
                    seed: Some(seed),
                    repeats: Some(repeats),
                    base_form: vec![BaseForm::Git],
                    cache: vec![Cache::Cold],
                    ..Selection::default()
                };
                let entries = schedule(&options);
                let order = measured(&entries);
                assert_eq!(order.len(), 2 * repeats as usize);
                assert_eq!(
                    order.iter().filter(|b| **b == Backend::Native).count(),
                    repeats as usize
                );
                for (i, pair) in order.as_chunks::<2>().0.iter().enumerate() {
                    assert_ne!(pair[0], pair[1]);
                    assert_eq!(pair[0], order[i % 2]);
                }
                assert!(entries.iter().all(|e| e.paired));
                for backend in [Backend::Native, Backend::Fuse] {
                    options.backend = vec![backend];
                    let single = schedule(&options);
                    assert_eq!(measured(&single), vec![backend; repeats as usize]);
                    assert!(single.iter().all(|e| !e.paired));
                }
            }
        }
    }
    // Regression: measurements ran before references/warm-ups, or probes became suite samples.
    #[test]
    fn regression_bench_schedule_reference_and_warmup_order() {
        let entries = schedule(&Selection::default());
        for reference in entries.iter().filter(|e| e.kind == Kind::Reference) {
            let cell: Vec<_> = entries
                .iter()
                .filter(|e| e.cell.identity() == reference.cell.identity())
                .collect();
            assert_eq!(cell[0].kind, Kind::Reference);
            assert_eq!(cell[0].backend, Backend::Native);
            let warmups = if reference.cell.cache == Cache::Warm {
                2
            } else {
                0
            };
            assert_eq!(cell.len(), 12 + warmups);
            for entry in &cell[1..1 + warmups] {
                assert_eq!(entry.kind, Kind::Warmup);
                assert!(entry.discarded && entry.repeat.is_none());
            }
            for (i, entry) in cell[1 + warmups..cell.len() - 1].iter().enumerate() {
                assert_eq!(entry.kind, Kind::Measured);
                assert!(!entry.discarded);
                assert_eq!(entry.repeat, Some((i / 2 + 1) as u32));
            }
            assert_eq!(cell.last().unwrap().kind, Kind::EmptyTopFuseProbe);
            assert_eq!(cell.last().unwrap().backend, Backend::Fuse);
            assert!(cell.last().unwrap().repeat.is_none());
        }
        let native = schedule(&Selection {
            backend: vec![Backend::Native],
            ..Selection::default()
        });
        assert!(!native.iter().any(|e| e.kind == Kind::EmptyTopFuseProbe));
    }
    // Regression: excess jobs bypassed admission, or the override erased qualification refusal.
    #[test]
    fn regression_bench_oversubscription_refused_and_override_recorded() {
        let mut v = fixture();
        let mut options = Selection {
            jobs: vec![2],
            ..Selection::default()
        };
        let error = build(&serde_json::to_vec(&v).unwrap(), &options).unwrap_err();
        assert!(error.contains("unsupported jobs 2"), "{error}");
        options.allow_oversubscription = true;
        assert!(build(&serde_json::to_vec(&v).unwrap(), &options)
            .unwrap_err()
            .contains("unsupported jobs 2"));
        options.allow_oversubscription = false;
        v["tasks"][0]["platforms"][0]["qualification"] =
            serde_json::json!({"qualified":false,"reasons":["not qualified"],"evidence":[]});
        v["tasks"][0]["platforms"][0]["supported_jobs"] = serde_json::json!([]);
        valid(&v, false).unwrap();
        options.jobs = vec![8];
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(build(&bytes, &options)
            .unwrap_err()
            .contains("task \"mojo\": jobs 8 exceeds cpus 2; use --allow-oversubscription"));
        options.allow_oversubscription = true;
        let entries = build(&bytes, &options).unwrap();
        assert!(entries
            .iter()
            .all(|e| e.oversubscribed && e.allow_oversubscription && e.cpus == 2));
        assert!(entries
            .iter()
            .all(|e| !e.qualified && !e.runnable && !e.execution_available));
        options.jobs = vec![3];
        assert!(build(&bytes, &options)
            .unwrap_err()
            .contains("unsupported jobs 3"));
    }
    // Regression: manifest growth allocated an unbounded schedule before refusing execution.
    #[test]
    fn regression_bench_schedule_entry_cap_refused() {
        let mut value = fixture();
        let template = value["tasks"][0].clone();
        value["tasks"] = serde_json::Value::Array(
            (0..124)
                .map(|i| {
                    let mut task = template.clone();
                    task["id"] = format!("task-{i}").into();
                    task
                })
                .collect(),
        );
        valid(&value, true).unwrap();
        let options = Selection {
            repeats: Some(100),
            ..Selection::default()
        };
        let Err(error) = build(&serde_json::to_vec(&value).unwrap(), &options) else {
            panic!("schedule entry cap was not enforced");
        };
        assert!(error.contains("100000 total-entry cap"));
        // Regression: the neighboring legal schedule (123 * 812) was over-refused.
        value["tasks"].as_array_mut().unwrap().pop();
        valid(&value, true).unwrap();
        assert_eq!(
            build(&serde_json::to_vec(&value).unwrap(), &options)
                .unwrap()
                .len(),
            99_876
        );
    }
    // Regression: concurrent attempts were accepted despite a serial-only schedule contract.
    #[test]
    fn regression_bench_concurrent_attempts_refused() {
        for attempts in [0, 2, u32::MAX] {
            let options = Selection {
                attempts: Some(attempts),
                ..Selection::default()
            };
            assert!(build(&serde_json::to_vec(&fixture()).unwrap(), &options)
                .unwrap_err()
                .contains("--attempts accepts only 1"));
        }
        assert!(schedule(&Selection::default())
            .iter()
            .all(|e| e.attempts == 1));
    }
}
