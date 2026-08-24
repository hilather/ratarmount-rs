//! Overlayfs-style OCI layer union (bottom → top).
//!
//! [`OciImageMountSource`] **is** the union. It does not wrap
//! [`crate::UnionMountSource`] (`union.rs` stays on B-4 dir-over-symlink).
//!
//! Lookup/list walk **top → bottom**:
//! - file whiteout `.wh.<name>` in a higher layer hides that name from lower layers
//! - opaque dir `.wh..wh..opq` in layer *i* skips children from layers `< i`
//! - `.wh.*` names are never emitted

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::sync::Arc;

use ratarmount_core::{
    create_root_file_info, is_dir_mode, normpath, CheapDirent, FileInfo, ListModeResult,
    ListResult, MountSource, UserData,
};

const WHITEOUT_PREFIX: &str = ".wh.";
/// Overlayfs opaque-directory marker (do not merge lower children).
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";
const LAYER_TAG_PREFIX: &str = "oci:";

/// Overlayfs union of image layers. `layers[0]` is the bottom / base.
pub struct OciImageMountSource {
    layers: Vec<Arc<dyn MountSource>>,
}

impl OciImageMountSource {
    /// `layers_bottom_to_top`: index 0 is the lowest layer (first `rootfs` diff).
    pub fn new(layers_bottom_to_top: Vec<Arc<dyn MountSource>>) -> Self {
        Self {
            layers: layers_bottom_to_top,
        }
    }

    pub fn layers(&self) -> &[Arc<dyn MountSource>] {
        &self.layers
    }

    fn tag(mut fi: FileInfo, layer_index: usize) -> FileInfo {
        fi.userdata
            .push(UserData::Other(format!("{LAYER_TAG_PREFIX}{layer_index}")));
        fi
    }

    fn layer_from_info(&self, file_info: &FileInfo) -> Option<usize> {
        file_info.userdata.iter().rev().find_map(|u| match u {
            UserData::Other(s) if s.starts_with(LAYER_TAG_PREFIX) => {
                s[LAYER_TAG_PREFIX.len()..].parse().ok()
            }
            _ => None,
        })
    }

    fn strip_tag(file_info: &FileInfo) -> FileInfo {
        let mut fi = file_info.clone();
        if let Some(UserData::Other(s)) = fi.userdata.last() {
            if s.starts_with(LAYER_TAG_PREFIX) {
                fi.userdata.pop();
            }
        }
        fi
    }

    fn overlay_list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let path = normpath(path);
        let mut by_name: BTreeMap<String, CheapDirent> = BTreeMap::new();
        let mut hidden: HashSet<String> = HashSet::new();
        let mut any = false;

        for layer in self.layers.iter().rev() {
            if path != "/" {
                if let Some(fi) = layer.lookup(&path, 0) {
                    if !is_dir_mode(fi.mode) {
                        return if any {
                            Some(by_name.into_values().collect())
                        } else {
                            None
                        };
                    }
                }
            }
            let Some(dents) = layer.list_dirents(&path) else {
                continue;
            };
            any = true;
            let mut opaque = false;
            let mut this_whiteouts = HashSet::new();
            for d in &dents {
                if d.name == OPAQUE_WHITEOUT {
                    opaque = true;
                } else if let Some(orig) = whiteout_target(&d.name) {
                    this_whiteouts.insert(orig.to_string());
                }
            }
            for d in dents {
                if is_whiteout_name(&d.name) {
                    continue;
                }
                if hidden.contains(&d.name) {
                    continue;
                }
                by_name.entry(d.name.clone()).or_insert(d);
            }
            hidden.extend(this_whiteouts);
            if opaque {
                break;
            }
        }
        any.then(|| by_name.into_values().collect())
    }

    fn overlay_list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        let mut map: BTreeMap<String, FileInfo> = BTreeMap::new();
        let mut hidden: HashSet<String> = HashSet::new();
        let mut any = false;

        for (li, layer) in self.layers.iter().enumerate().rev() {
            if path != "/" {
                if let Some(fi) = layer.lookup(&path, 0) {
                    if !is_dir_mode(fi.mode) {
                        return if any {
                            Some(ListResult::Infos(map))
                        } else {
                            None
                        };
                    }
                }
            }
            let Some(listing) = layer.list(&path) else {
                continue;
            };
            any = true;
            let entries: Vec<(String, Option<FileInfo>)> = match listing {
                ListResult::Infos(m) => m.into_iter().map(|(k, v)| (k, Some(v))).collect(),
                ListResult::Names(names) => names.into_iter().map(|n| (n, None)).collect(),
            };
            let mut opaque = false;
            let mut this_whiteouts = HashSet::new();
            for (name, _) in &entries {
                if name == OPAQUE_WHITEOUT {
                    opaque = true;
                } else if let Some(orig) = whiteout_target(name) {
                    this_whiteouts.insert(orig.to_string());
                }
            }
            for (name, fi) in entries {
                if is_whiteout_name(&name) {
                    continue;
                }
                if hidden.contains(&name) || map.contains_key(&name) {
                    continue;
                }
                let fi = match fi {
                    Some(fi) => fi,
                    None => match layer.lookup(&join(&path, &name), 0) {
                        Some(fi) => fi,
                        None => continue,
                    },
                };
                map.insert(name, Self::tag(fi, li));
            }
            hidden.extend(this_whiteouts);
            if opaque {
                break;
            }
        }
        any.then_some(ListResult::Infos(map))
    }
}

impl MountSource for OciImageMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.overlay_list(path)
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.overlay_list_dirents(path)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        let dents = self.list_dirents(path)?;
        Some(ListModeResult::Modes(
            dents.into_iter().map(|d| (d.name, d.mode)).collect(),
        ))
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(create_root_file_info());
        }
        let parts: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if parts.iter().any(|p| is_whiteout_name(p)) {
            return None;
        }
        for (li, layer) in self.layers.iter().enumerate().rev() {
            match walk_layer(layer.as_ref(), &parts, file_version) {
                Walk::Found(fi) => return Some(Self::tag(fi, li)),
                Walk::Hidden => return None,
                Walk::Miss => continue,
            }
        }
        None
    }

    fn open(
        &self,
        file_info: &FileInfo,
        buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if let Some(li) = self.layer_from_info(file_info) {
            if let Some(src) = self.layers.get(li) {
                return src.open(&Self::strip_tag(file_info), buffering);
            }
        }
        let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no OCI layer could open");
        for src in self.layers.iter().rev() {
            match src.open(file_info, buffering) {
                Ok(r) => return Ok(r),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn member_seek_is_cheap(&self, file_info: &FileInfo) -> bool {
        if let Some(li) = self.layer_from_info(file_info) {
            if let Some(src) = self.layers.get(li) {
                return src.member_seek_is_cheap(&Self::strip_tag(file_info));
            }
        }
        true
    }

    fn content_generation(&self) -> u64 {
        self.layers
            .iter()
            .map(|l| l.content_generation())
            .max()
            .unwrap_or(0)
    }

    fn is_immutable(&self) -> bool {
        self.layers.iter().all(|l| l.is_immutable())
    }
}

enum Walk {
    Found(FileInfo),
    Hidden,
    Miss,
}

fn walk_layer(layer: &dyn MountSource, parts: &[&str], file_version: i32) -> Walk {
    let mut prefix = String::from("/");
    for (k, part) in parts.iter().enumerate() {
        let last = k + 1 == parts.len();
        let child = join(&prefix, part);
        let wh = join(&prefix, &format!("{WHITEOUT_PREFIX}{part}"));
        let has_wh = layer.lookup(&wh, 0).is_some();
        let fi = if last {
            layer.lookup(&child, file_version)
        } else {
            layer.lookup(&child, 0)
        };

        if last {
            if let Some(fi) = fi {
                return Walk::Found(fi);
            }
            if has_wh || layer.lookup(&join(&prefix, OPAQUE_WHITEOUT), 0).is_some() {
                return Walk::Hidden;
            }
            return Walk::Miss;
        }

        if let Some(fi) = fi {
            if !is_dir_mode(fi.mode) {
                return Walk::Hidden;
            }
            prefix = child;
            continue;
        }
        if has_wh || layer.lookup(&join(&prefix, OPAQUE_WHITEOUT), 0).is_some() {
            return Walk::Hidden;
        }
        return Walk::Miss;
    }
    Walk::Miss
}

fn is_whiteout_name(name: &str) -> bool {
    name.starts_with(WHITEOUT_PREFIX)
}

fn whiteout_target(name: &str) -> Option<&str> {
    if name == OPAQUE_WHITEOUT {
        return None;
    }
    name.strip_prefix(WHITEOUT_PREFIX)
        .filter(|s| !s.is_empty() && *s != "..wh..opq")
}

fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};
    use std::sync::Arc;

    use ratarmount_core::{OpenOptions, S_IFDIR};
    use ratarmount_formats_tar::{
        write_tar_eof, write_ustar_members, SqliteIndexedTar, UstarMember, UstarPayload,
    };

    fn member_file<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
        UstarMember {
            path,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn member_dir(path: &str) -> UstarMember<'_> {
        UstarMember {
            path,
            payload: UstarPayload::Directory,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn pack(members: &[UstarMember<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        write_ustar_members(&mut out, members).expect("write members");
        write_tar_eof(&mut out).expect("eof");
        out
    }

    fn open_layer(bytes: Vec<u8>, label: &str) -> Arc<dyn MountSource> {
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let tar =
            SqliteIndexedTar::open_from_reader(Cursor::new(bytes), label, None, &opts, "test")
                .expect("index layer tar");
        Arc::new(tar)
    }

    fn names(src: &dyn MountSource, path: &str) -> Vec<String> {
        let dents = src.list_dirents(path).expect("list_dirents");
        let mut n: Vec<String> = dents.into_iter().map(|d| d.name).collect();
        n.sort();
        n
    }

    fn read_file(src: &dyn MountSource, path: &str) -> Vec<u8> {
        let fi = src
            .lookup(path, 0)
            .unwrap_or_else(|| panic!("lookup {path}"));
        let mut r = src.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        buf
    }

    fn two_layer_rootfs() -> OciImageMountSource {
        // Bottom: hello.txt, foo, dir/{a,b}.txt
        let lower = pack(&[
            member_file("hello.txt", b"from-lower"),
            member_file("foo", b"hide-me"),
            member_dir("dir"),
            member_file("dir/a.txt", b"lower-a"),
            member_file("dir/b.txt", b"lower-b"),
        ]);
        // Top: .wh.foo, world.txt, opaque dir with c.txt only
        let upper = pack(&[
            member_file(".wh.foo", b""),
            member_file("world.txt", b"from-upper"),
            member_dir("dir"),
            member_file("dir/.wh..wh..opq", b""),
            member_file("dir/c.txt", b"upper-c"),
        ]);
        OciImageMountSource::new(vec![
            open_layer(lower, "lower.tar"),
            open_layer(upper, "upper.tar"),
        ])
    }

    #[test]
    fn file_whiteout_hides_lower_name() {
        let img = two_layer_rootfs();
        assert!(img.lookup("/foo", 0).is_none(), "whiteout foo must hide");
        assert_eq!(read_file(&img, "/hello.txt"), b"from-lower");
        assert_eq!(read_file(&img, "/world.txt"), b"from-upper");
        let root = names(&img, "/");
        assert!(!root.iter().any(|n| n == "foo"));
        assert!(!root.iter().any(|n| n.starts_with(".wh.")));
    }

    /// Regression: opaque dir does not leak lower children.
    #[test]
    fn regression_opaque_dir_does_not_leak_lower_children() {
        let img = two_layer_rootfs();
        let dir = names(&img, "/dir");
        assert_eq!(dir, vec!["c.txt".to_string()]);
        assert!(img.lookup("/dir/a.txt", 0).is_none());
        assert!(img.lookup("/dir/b.txt", 0).is_none());
        assert_eq!(read_file(&img, "/dir/c.txt"), b"upper-c");
        assert!(!dir.iter().any(|n| n.starts_with(".wh.")));
    }

    /// Regression: rootfs listing is overlayfs union not layer tarballs.
    #[test]
    fn regression_rootfs_listing_is_overlayfs_union_not_layer_tarballs() {
        let img = two_layer_rootfs();
        let root = names(&img, "/");
        assert!(
            !root
                .iter()
                .any(|n| n.ends_with(".tar") || n.contains("layer")),
            "rootfs listed layer tarballs: {root:?}"
        );
        assert!(root.contains(&"hello.txt".to_string()), "{root:?}");
        assert!(root.contains(&"world.txt".to_string()), "{root:?}");
        assert!(root.contains(&"dir".to_string()), "{root:?}");
        match img.list("/") {
            Some(ListResult::Infos(map)) => {
                assert!(map.contains_key("hello.txt"));
                assert!(map.contains_key("world.txt"));
                assert!(!map.contains_key("foo"));
                assert!(!map.keys().any(|k| k.starts_with(".wh.")));
            }
            other => panic!("expected Infos listing, got {other:?}"),
        }
        let dir_fi = img.lookup("/dir", 0).expect("dir");
        assert_eq!(dir_fi.mode & ratarmount_core::S_IFMT, S_IFDIR);
        assert!(img.member_seek_is_cheap(&img.lookup("/hello.txt", 0).unwrap()));
    }

    #[test]
    fn empty_layers_still_have_root() {
        let img = OciImageMountSource::new(vec![]);
        assert!(img.lookup("/", 0).is_some());
        assert!(img.list("/").is_none());
        assert!(img.list_dirents("/").is_none());
    }
}
