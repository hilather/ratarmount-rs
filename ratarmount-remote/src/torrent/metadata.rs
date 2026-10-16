use std::io::{self, Read, Write};
use std::path::Path;

use url::Url;

use super::metainfo::{invalid, Metainfo, MAX_META};
use super::swarm::Swarm;
use super::TorrentOptions;

#[derive(Default, Debug)]
pub(crate) struct Magnet {
    v1: Option<String>,
    v2: Option<String>,
    pub web_seeds: Vec<String>,
    sources: Vec<String>,
    trackers: Vec<String>,
}

fn btih(s: &str) -> io::Result<String> {
    if s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(s.to_ascii_lowercase());
    }
    if s.len() != 32 {
        return Err(invalid("invalid magnet btih"));
    }
    let mut bits = 0u32;
    let mut count = 0;
    let mut bytes = Vec::new();
    for b in s.bytes().map(|b| b.to_ascii_uppercase()) {
        let value = match b {
            b'A'..=b'Z' => b - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return Err(invalid("invalid base32 btih")),
        };
        bits = (bits << 5) | value as u32;
        count += 5;
        if count >= 8 {
            count -= 8;
            bytes.push((bits >> count) as u8);
        }
    }
    Ok(hex::encode(bytes))
}

impl Magnet {
    pub fn parse(input: &str) -> io::Result<Self> {
        let url = Url::parse(input).map_err(|_| invalid("invalid magnet URL"))?;
        if url.scheme() != "magnet" {
            return Err(invalid("expected magnet URL"));
        }
        let mut magnet = Self::default();
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "xt" if value.starts_with("urn:btih:") => {
                    let hash = btih(&value[9..])?;
                    if magnet.v1.as_ref().is_some_and(|h| h != &hash) {
                        return Err(invalid("conflicting btih hashes"));
                    }
                    magnet.v1 = Some(hash);
                }
                "xt" if value.starts_with("urn:btmh:1220") => {
                    let hash = &value[13..];
                    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(invalid("invalid SHA-256 btmh"));
                    }
                    let hash = hash.to_ascii_lowercase();
                    if magnet.v2.as_ref().is_some_and(|h| h != &hash) {
                        return Err(invalid("conflicting btmh hashes"));
                    }
                    magnet.v2 = Some(hash);
                }
                "xs" => magnet.sources.push(value.into_owned()),
                "ws" => magnet.web_seeds.push(value.into_owned()),
                "tr" => magnet.trackers.push(value.into_owned()),
                _ => {}
            }
        }
        if magnet.v1.is_none() && magnet.v2.is_none() {
            return Err(invalid("magnet requires urn:btih or SHA-256 urn:btmh"));
        }
        Ok(magnet)
    }

    pub fn matches(&self, meta: &Metainfo) -> bool {
        self.v1
            .as_ref()
            .is_none_or(|h| meta.v1_hash.as_ref() == Some(h))
            && self
                .v2
                .as_ref()
                .is_none_or(|h| meta.v2_hash.as_ref() == Some(h))
    }

    fn swarm_url(&self) -> io::Result<String> {
        let v1 = self.v1.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported,
            "librqbit 9.0.1 cannot resolve v2-only magnets; supply an xs=.torrent URL or local .torrent"))?;
        let mut url = Url::parse(&format!("magnet:?xt=urn:btih:{v1}")).unwrap();
        for tracker in &self.trackers {
            url.query_pairs_mut().append_pair("tr", tracker);
        }
        Ok(url.to_string())
    }
}

fn read_metadata(path: &Path) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_META + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_META {
        return Err(invalid("torrent metadata exceeds 64 MiB"));
    }
    Ok(data)
}

fn fetch(url: &str, timeout: std::time::Duration) -> io::Result<Vec<u8>> {
    let parsed = Url::parse(url).map_err(|_| invalid("invalid metadata URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(invalid("torrent metadata source must use HTTP(S)"));
    }
    let source = crate::HttpRangeSource::new(
        crate::HttpLocation {
            url: url.into(),
            auth: None,
            cookie: None,
        },
        crate::HttpAuthOptions::default(),
    )
    .without_range_cache();
    let response = source
        .request_with_timeout("GET", None, Some(timeout))
        .map_err(|e| io::Error::other(crate::map_ureq_http_error(e, url).to_string()))?;
    let bytes = crate::read_at_most(&mut response.into_reader(), MAX_META)?;
    if bytes.len() as u64 > MAX_META {
        return Err(invalid("torrent metadata exceeds 64 MiB"));
    }
    Ok(bytes)
}

pub(crate) fn save(meta: &Metainfo, dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    for hash in [meta.v1_hash.as_ref(), meta.v2_hash.as_ref()]
        .into_iter()
        .flatten()
    {
        let mut temp = tempfile::NamedTempFile::new_in(dir)?;
        temp.write_all(&meta.bytes)?;
        temp.as_file().sync_all()?;
        temp.persist(dir.join(format!("{hash}.torrent")))
            .map_err(|e| e.error)?;
    }
    Ok(())
}

pub(crate) fn resolve(input: &str, options: &TorrentOptions) -> io::Result<Metainfo> {
    if input
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("magnet:"))
    {
        let magnet = Magnet::parse(input)?;
        let mut found = None;
        for hash in [magnet.v2.as_ref(), magnet.v1.as_ref()]
            .into_iter()
            .flatten()
        {
            if let Ok(bytes) = read_metadata(&options.metadata_dir.join(format!("{hash}.torrent")))
            {
                if let Ok(meta) = Metainfo::parse(bytes) {
                    if magnet.matches(&meta) {
                        found = Some(meta);
                        break;
                    }
                }
            }
        }
        if found.is_none() {
            // BEP 19 ws is a payload base, not a metadata endpoint. Only probe ws
            // when it explicitly names a .torrent; never download a weight file.
            for url in magnet.sources.iter().chain(
                magnet
                    .web_seeds
                    .iter()
                    .filter(|u| Url::parse(u).is_ok_and(|u| u.path().ends_with(".torrent"))),
            ) {
                if let Ok(meta) = fetch(url, options.swarm.timeout).and_then(Metainfo::parse) {
                    if magnet.matches(&meta) {
                        found = Some(meta);
                        break;
                    }
                }
            }
        }
        let mut meta = match found {
            Some(m) => m,
            None => {
                let swarm_url = magnet.swarm_url()?;
                let swarm =
                    Swarm::new(options.swarm.clone(), options.metadata_dir.join("scratch"))?;
                let meta = Metainfo::parse(swarm.resolve(swarm_url)?)?;
                if !magnet.matches(&meta) {
                    return Err(invalid("magnet metadata infohash mismatch"));
                }
                meta
            }
        };
        for seed in magnet.web_seeds {
            if !meta.web_seeds.contains(&seed) {
                meta.web_seeds.push(seed);
            }
        }
        for tracker in magnet.trackers {
            if !meta.trackers.contains(&tracker) {
                meta.trackers.push(tracker);
            }
        }
        // Preserve magnet ws/tr additions in the cached envelope (outside info).
        meta.bytes = envelope(&meta)?;
        if let Err(e) = save(&meta, &options.metadata_dir) {
            log::warn!("torrent metadata cache: {e}");
        }
        Ok(meta)
    } else {
        let url = Url::parse(input).ok().filter(|_| input.contains("://"));
        let bytes = match url.as_ref().map(Url::scheme) {
            Some("http" | "https") => fetch(input, options.swarm.timeout)?,
            Some("file") => read_metadata(
                &url.unwrap()
                    .to_file_path()
                    .map_err(|_| invalid("invalid file URL"))?,
            )?,
            _ => read_metadata(Path::new(input))?,
        };
        let meta = Metainfo::parse(bytes)?;
        if let Err(e) = save(&meta, &options.metadata_dir) {
            log::warn!("torrent metadata cache: {e}");
        }
        Ok(meta)
    }
}

fn string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(value);
}

fn envelope(meta: &Metainfo) -> io::Result<Vec<u8>> {
    let top = super::metainfo::parse(&meta.bytes)?;
    let mut out = b"d".to_vec();
    if !meta.trackers.is_empty() {
        string(&mut out, b"announce-list");
        out.push(b'l');
        for url in &meta.trackers {
            out.push(b'l');
            string(&mut out, url.as_bytes());
            out.push(b'e');
        }
        out.push(b'e');
    }
    string(&mut out, b"info");
    out.extend_from_slice(&meta.info);
    if let Some(layers) = top.get(b"piece layers") {
        string(&mut out, b"piece layers");
        out.extend_from_slice(layers.raw);
    }
    string(&mut out, b"url-list");
    out.push(b'l');
    for url in &meta.web_seeds {
        string(&mut out, url.as_bytes());
    }
    out.extend_from_slice(b"ee");
    Ok(out)
}
