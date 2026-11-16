//! Independent whole-file hashes. Cache only observations bound to this infohash.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

use super::metainfo::{invalid, Metainfo};
use super::{hub_file, web_seed_url};
use crate::HfRepo;

pub(super) type HubHashes = BTreeMap<(String, String), (u64, String)>;

#[derive(Default)]
pub(super) struct Observations {
    pub checks: Hashes,
    pub hub: HubHashes,
}

type Hashes = BTreeMap<String, [u8; 32]>;
const MAX_HASHES: u64 = 64 * 1024 * 1024;

fn digest(value: &str) -> Option<[u8; 32]> {
    hex::decode(value.strip_prefix("sha256:").unwrap_or(value))
        .ok()?
        .try_into()
        .ok()
}

fn pirate_hashes(value: &Value, meta: &Metainfo, repo: &str, revision: &str) -> io::Result<Hashes> {
    if !value["infohash"]
        .as_str()
        .is_some_and(|h| Some(h) == meta.v1_hash.as_deref() || Some(h) == meta.v2_hash.as_deref())
        || value["repoId"].as_str() != Some(repo)
        || value["revision"].as_str() != Some(revision)
    {
        return Err(invalid(
            "Pirate Face checksum manifest does not match torrent/repo/revision",
        ));
    }
    let files = value["files"]
        .as_array()
        .ok_or_else(|| invalid("invalid Pirate Face checksum files"))?;
    let mut hashes = BTreeMap::new();
    for f in files {
        let path = f["path"]
            .as_str()
            .ok_or_else(|| invalid("checksum file has no path"))?;
        let hash = f["sha256"]
            .as_str()
            .and_then(digest)
            .ok_or_else(|| invalid("invalid checksum SHA-256"))?;
        if hashes.insert(path.into(), hash).is_some() {
            return Err(invalid("duplicate checksum path"));
        }
    }
    Ok(hashes)
}

fn cache_path(meta: &Metainfo, dir: &Path, source: &str) -> std::path::PathBuf {
    // source includes repository kind, repository ID and pinned revision.
    let key = hex::encode(Sha256::digest(format!("{}\0{source}", meta.identity())));
    dir.join(format!("{key}.sha256-v2.json"))
}

fn cached(meta: &Metainfo, dir: &Path, source: &str) -> Hashes {
    let read = || -> Option<Hashes> {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0528-M01","item":"ratarmount_remote::torrent::checksums::cached","disposition":"residual","reason":"torrent checksum cache record","family":"remote-listing-and-torrent-caches","issue":"#196","category":"remote-listing-and-torrent-caches","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let file = std::fs::File::open(cache_path(meta, dir, source)).ok()?;
        let mut bytes = Vec::new();
        file.take(MAX_HASHES + 1).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 > MAX_HASHES {
            return None;
        }
        let value: Value = serde_json::from_slice(&bytes).ok()?;
        if value["infohash"].as_str() != Some(meta.identity())
            || value["source"].as_str() != Some(source)
        {
            return None;
        }
        Some(
            value["files"]
                .as_object()?
                .iter()
                .filter_map(|(p, h)| Some((p.clone(), digest(h.as_str()?)?)))
                .collect(),
        )
    };
    read().unwrap_or_default()
}

pub(super) fn save(meta: &Metainfo, dir: &Path, source: &str, hashes: &Hashes) -> io::Result<()> {
    if hashes.is_empty() {
        return Ok(());
    }
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-E0088-M01","item":"ratarmount_remote::torrent::checksums::save","disposition":"output-owner","category":"torrent-checksum-cache-directory","reason":"Create the checksum cache output directory before writing an atomic hash-summary tempfile.","creation":{"policy":"recursive-directory","basis":"Empty checksum sets return early; nonempty summary output uses the existing directory and tempfile defaults."}}"###
    )]
    std::fs::create_dir_all(dir)?;
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0529-M01","item":"ratarmount_remote::torrent::checksums::save","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
    )]
    let mut temp = tempfile::NamedTempFile::new_in(dir)?;
    let files: BTreeMap<_, _> = hashes.iter().map(|(p, h)| (p, hex::encode(h))).collect();
    serde_json::to_writer(
        &mut temp,
        &json!({"infohash":meta.identity(), "source":source, "files":files}),
    )?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    temp.persist(cache_path(meta, dir, source))
        .map_err(|e| e.error)?;
    Ok(())
}

fn load_with(meta: &Metainfo, dir: &Path, mut fetch: impl FnMut(&str, bool) -> Hashes) -> Hashes {
    let mut sources: BTreeMap<String, (bool, Vec<(String, String)>)> = BTreeMap::new();
    for file in 0..meta.files.len() {
        if meta.files[file].padding {
            continue;
        }
        for seed in 0..meta.web_seeds.len() {
            let Ok(url) = web_seed_url(meta, seed, file) else {
                continue;
            };
            let Some((source, path)) = hub_file(&url) else {
                continue;
            };
            let entry = sources.entry(source).or_default();
            entry.0 |= Url::parse(&url).is_ok_and(|u| u.host_str() == Some("pirateface.co"));
            entry.1.push((meta.files[file].path.clone(), path));
        }
    }
    let mut result = Hashes::new();
    for (source, (pirate, paths)) in sources {
        let mut hashes = cached(meta, dir, &source);
        // A partial observation must not permanently suppress later discoveries.
        let fresh = fetch(&source, pirate);
        if !fresh.is_empty() {
            hashes.extend(fresh);
            if let Err(e) = save(meta, dir, &source, &hashes) {
                log::warn!("torrent checksum cache: {e}");
            }
        }
        for (torrent_path, repo_path) in paths {
            if let Some(hash) = hashes.get(&repo_path) {
                result.entry(torrent_path).or_insert(*hash);
            }
        }
    }
    result
}

pub(super) fn cached_only(meta: &Metainfo, dir: &Path) -> Hashes {
    load_with(meta, dir, |_, _| Hashes::new())
}

pub(super) fn load(meta: &Metainfo, dir: &Path) -> Observations {
    let mut hub = HubHashes::new();
    let checks = load_with(meta, dir, |repo_url, pirate| {
        let mut hashes: Hashes =
            match HfRepo::resolve(repo_url).and_then(|repo| repo.torrent_oids()) {
                Ok(oids) => {
                    hub.extend(
                        oids.iter()
                            .map(|(path, oid)| ((repo_url.into(), path.clone()), oid.clone())),
                    );
                    oids.into_iter()
                        .filter_map(|(path, (_, oid))| Some((path, digest(&oid)?)))
                        .collect()
                }
                Err(e) => {
                    log::warn!("torrent Hub checksum lookup: {e}");
                    Hashes::new()
                }
            };
        if pirate {
            let fetch = || -> Option<Hashes> {
                let location = crate::parse_hf_url(repo_url).ok()?;
                let mut api = Url::parse("https://pirateface.co/api/torrents").unwrap();
                api.query_pairs_mut().append_pair("repo", &location.repo);
                let bytes = crate::fetch_http_bytes_capped(api.as_str(), MAX_HASHES).ok()?;
                let value = serde_json::from_slice(&bytes).ok()?;
                pirate_hashes(&value, meta, &location.repo, &location.revision).ok()
            };
            if let Some(manifest) = fetch() {
                for (p, h) in manifest {
                    hashes.entry(p).or_insert(h);
                }
            }
        }
        hashes
    });
    Observations { checks, hub }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a moving Pirate Face listing supplied hashes for a different torrent/revision.
    #[test]
    fn regression_pirate_face_manifest_identity_and_hashes() {
        let bytes = super::super::tests::single_file_fixture();
        let meta = Metainfo::parse(bytes).unwrap();
        let value = json!({"repoId":"org/repo", "revision":"rev", "infohash":meta.v1_hash,
            "files":[{"path":"file", "sha256":"ab".repeat(32)}]});
        assert_eq!(
            pirate_hashes(&value, &meta, "org/repo", "rev").unwrap()["file"],
            [0xab; 32]
        );
        assert!(pirate_hashes(&value, &meta, "org/repo", "other").is_err());
        let mut wrong = value;
        wrong["infohash"] = json!("0".repeat(40));
        assert!(pirate_hashes(&wrong, &meta, "org/repo", "rev").is_err());
    }
    /// Regression: one magnet's ws repository poisoned the per-infohash checksum cache of another.
    #[test]
    fn regression_checksum_cache_bound_to_repository_and_revision() {
        let dir = tempfile::tempdir().unwrap();
        let mut meta = Metainfo::parse(super::super::tests::single_file_fixture()).unwrap();
        let source = format!("hf://org/first@{}", "a".repeat(40));
        save(
            &meta,
            dir.path(),
            &source,
            &BTreeMap::from([("file".into(), [1; 32])]),
        )
        .unwrap();
        assert_eq!(cached(&meta, dir.path(), &source)["file"], [1; 32]);
        for other in [
            format!("hf://org/second@{}", "a".repeat(40)),
            format!("hf://org/first@{}", "b".repeat(40)),
        ] {
            assert!(cached(&meta, dir.path(), &other).is_empty());
        }
        meta.web_seeds = vec![format!(
            "https://huggingface.co/org/first/resolve/{}/file",
            "a".repeat(40)
        )];
        // Partial caches are refilled for paths required by this source.
        save(
            &meta,
            dir.path(),
            &source,
            &BTreeMap::from([("other".into(), [2; 32])]),
        )
        .unwrap();
        let mut calls = 0;
        let hashes = load_with(&meta, dir.path(), |url, _| {
            assert_eq!(url, source);
            calls += 1;
            BTreeMap::from([("file".into(), [3; 32])])
        });
        assert_eq!(calls, 1);
        assert_eq!(hashes["file"], [3; 32]);
        assert_eq!(load_with(&meta, dir.path(), |_, _| Hashes::new()), hashes);
    }

    /// Regression: absent v1 identity and an absent manifest infohash matched for a v2-only torrent.
    #[test]
    fn regression_v2_manifest_requires_explicit_infohash() {
        let mut meta = Metainfo::parse(super::super::tests::single_file_fixture()).unwrap();
        meta.v1_hash = None;
        meta.v2_hash = Some("a".repeat(64));
        let mut value = json!({"repoId":"org/repo", "revision":"rev", "files":[]});
        assert!(pirate_hashes(&value, &meta, "org/repo", "rev").is_err());
        value["infohash"] = json!(meta.v2_hash);
        assert!(pirate_hashes(&value, &meta, "org/repo", "rev").is_ok());
    }
}
