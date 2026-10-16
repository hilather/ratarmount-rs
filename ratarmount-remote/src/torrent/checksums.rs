//! Independent whole-file hashes. Cache only observations bound to this infohash.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::Path;

use serde_json::{json, Value};
use url::Url;

use super::metainfo::{invalid, Metainfo};
use super::{hub_file, web_seed_url};
use crate::HfRepo;

type Hashes = BTreeMap<String, [u8; 32]>;
const MAX_HASHES: u64 = 64 * 1024 * 1024;

fn digest(value: &str) -> Option<[u8; 32]> {
    hex::decode(value.strip_prefix("sha256:").unwrap_or(value))
        .ok()?
        .try_into()
        .ok()
}

fn pirate_hashes(value: &Value, meta: &Metainfo, repo: &str, revision: &str) -> io::Result<Hashes> {
    if value["infohash"].as_str() != meta.v1_hash.as_deref()
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

pub(super) fn load(meta: &Metainfo, dir: &Path) -> Hashes {
    let path = dir.join(format!("{}.sha256.json", meta.identity()));
    if let Ok(file) = std::fs::File::open(&path) {
        let mut bytes = Vec::new();
        if file.take(MAX_HASHES + 1).read_to_end(&mut bytes).is_ok()
            && bytes.len() as u64 <= MAX_HASHES
        {
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                if value["infohash"].as_str() == Some(meta.identity()) {
                    if let Some(files) = value["files"].as_object() {
                        let hashes: Hashes = files
                            .iter()
                            .filter_map(|(p, h)| Some((p.clone(), digest(h.as_str()?)?)))
                            .collect();
                        if !hashes.is_empty() {
                            return hashes;
                        }
                    }
                }
            }
        }
    }
    let mut hashes = BTreeMap::new();
    let mut repos = BTreeMap::new();
    let mut pirate_manifests = BTreeMap::new();
    for file in 0..meta.files.len() {
        if meta.files[file].padding {
            continue;
        }
        for seed in 0..meta.web_seeds.len() {
            let Ok(url) = web_seed_url(meta, seed, file) else {
                continue;
            };
            let Some((repo_url, file_path)) = hub_file(&url) else {
                continue;
            };
            let repo_hashes =
                repos.entry(repo_url.clone()).or_insert_with(|| {
                    match HfRepo::resolve(&repo_url).and_then(|repo| repo.torrent_sha256s()) {
                        Ok(hashes) => hashes,
                        Err(e) => {
                            log::warn!("torrent Hub checksum lookup: {e}");
                            BTreeMap::new()
                        }
                    }
                });
            if let Some(hash) = repo_hashes.get(&file_path).and_then(|h| digest(h)) {
                hashes.insert(meta.files[file].path.clone(), hash);
                break;
            }
            if Url::parse(&url).is_ok_and(|u| u.host_str() == Some("pirateface.co")) {
                let manifest = pirate_manifests.entry(repo_url.clone()).or_insert_with(|| {
                    let location = crate::parse_hf_url(&repo_url).ok()?;
                    let mut api = Url::parse("https://pirateface.co/api/torrents").unwrap();
                    api.query_pairs_mut().append_pair("repo", &location.repo);
                    let bytes = crate::fetch_http_bytes_capped(api.as_str(), MAX_HASHES).ok()?;
                    let value = serde_json::from_slice(&bytes).ok()?;
                    pirate_hashes(&value, meta, &location.repo, &location.revision).ok()
                });
                if let Some(manifest) = manifest {
                    if let Some(hash) = manifest.get(&file_path) {
                        hashes.insert(meta.files[file].path.clone(), *hash);
                        break;
                    }
                }
            }
        }
    }
    if !hashes.is_empty() {
        let save = || -> io::Result<()> {
            std::fs::create_dir_all(dir)?;
            let mut temp = tempfile::NamedTempFile::new_in(dir)?;
            let files: BTreeMap<_, _> = hashes.iter().map(|(p, h)| (p, hex::encode(h))).collect();
            serde_json::to_writer(
                &mut temp,
                &json!({"infohash": meta.identity(), "files": files}),
            )?;
            temp.flush()?;
            temp.as_file().sync_all()?;
            temp.persist(path).map_err(|e| e.error)?;
            Ok(())
        };
        if let Err(e) = save() {
            log::warn!("torrent checksum cache: {e}");
        }
    }
    hashes
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
}
