//! Linux Docker volume protocol v1. The only mount dependency is an executable.
#![cfg(target_os = "linux")]

pub mod http;
pub mod options;
pub mod process;

use options::{validate, validate_name, Options};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub trait Mounter: Send {
    fn mount(&mut self, opts: &Options, path: &Path) -> Result<(), String>;
    fn unmount(&mut self, path: &Path, lazy: bool) -> Result<(), String>;
    /// Polling must reap a dead child before returning false.
    fn alive(&mut self, path: &Path) -> Result<bool, String>;
    fn reconcile(&mut self, root: &Path) -> Result<(), String>;
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    opts: Options,
}

#[derive(Default)]
struct Runtime {
    mounted: bool,
    ids: BTreeSet<String>,
}

pub struct Driver<M: Mounter> {
    state: PathBuf,
    definitions: BTreeMap<String, Definition>,
    runtime: BTreeMap<String, Runtime>,
    mounter: M,
    _lock: File,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Request {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "ID")]
    id: String,
    #[serde(default, deserialize_with = "deserialize_options")]
    opts: Options,
}

fn deserialize_options<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Options, D::Error> {
    Ok(Option::<Options>::deserialize(deserializer)?.unwrap_or_default())
}

impl<M: Mounter> Driver<M> {
    pub fn open(state: &Path, mut mounter: M) -> Result<Self, String> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state)
            .map_err(|_| "cannot create state directory")?;
        let state = state
            .canonicalize()
            .map_err(|_| "cannot resolve state directory")?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state.join("driver.lock"))
            .map_err(|_| "cannot open state lock")?;
        // SAFETY: lock is an open file retained for the lifetime of Driver.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("state directory is already in use".into());
        }
        let definitions: BTreeMap<String, Definition> = match fs::read(state.join("volumes.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| "invalid volumes.json")?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(_) => return Err("cannot read volumes.json".into()),
        };
        for (name, def) in &definitions {
            validate_name(name)?;
            validate(&def.opts)?;
        }
        let root = state.join("mnt");
        fs::DirBuilder::new()
            .mode(0o755)
            .create(&root)
            .or_else(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .map_err(|_| "cannot create mount root")?;
        if root
            .symlink_metadata()
            .map_err(|_| "cannot stat mount root")?
            .file_type()
            .is_symlink()
        {
            return Err("mount root must not be a symlink".into());
        }
        mounter.reconcile(&root)?;
        Ok(Self {
            state,
            definitions,
            runtime: BTreeMap::new(),
            mounter,
            _lock: lock,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.state.join("mnt").join(name)
    }

    fn persist(&self, definitions: &BTreeMap<String, Definition>) -> Result<(), String> {
        let temp = self.state.join("volumes.json.tmp");
        let result = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temp)?;
            serde_json::to_writer(&mut file, definitions)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&temp, self.state.join("volumes.json"))?;
            File::open(&self.state)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result.map_err(|_| "cannot persist volume definitions".into())
    }

    /// Called periodically even when no HTTP requests arrive.
    pub fn supervise(&mut self) {
        let mounted: Vec<_> = self
            .runtime
            .iter()
            .filter(|(_, r)| r.mounted)
            .map(|(n, _)| n.clone())
            .collect();
        for name in mounted {
            let path = self.path(&name);
            match self.mounter.alive(&path) {
                Ok(true) => {}
                Ok(false) => {
                    let _ = writeln!(
                        io::stderr(),
                        "ratarmount volume {name}: child exited; volume is unmounted"
                    );
                    if self.mounter.unmount(&path, true).is_err() {
                        let _ = writeln!(
                            io::stderr(),
                            "ratarmount volume {name}: stale mount cleanup failed"
                        );
                    }
                    self.runtime.insert(name, Runtime::default());
                }
                Err(_) => {
                    let _ = writeln!(io::stderr(), "ratarmount volume {name}: cannot poll child");
                }
            }
        }
    }

    pub fn handle(&mut self, endpoint: &str, body: &[u8]) -> Value {
        self.supervise();
        match self.dispatch(endpoint, body) {
            Ok(mut value) => {
                value["Err"] = json!("");
                value
            }
            Err(error) => json!({"Err": error}),
        }
    }

    fn volume(&self, name: &str) -> Value {
        let rt = self.runtime.get(name);
        json!({"Name": name, "Mountpoint": self.path(name), "Status": {
            "Mounted": rt.is_some_and(|r| r.mounted),
            "References": rt.map_or(0, |r| r.ids.len())
        }})
    }

    fn dispatch(&mut self, endpoint: &str, body: &[u8]) -> Result<Value, String> {
        let req: Request = if body.is_empty() {
            Request::default()
        } else {
            serde_json::from_slice(body).map_err(|_| "invalid JSON request")?
        };
        match endpoint {
            "/Plugin.Activate" => return Ok(json!({"Implements": ["VolumeDriver"]})),
            "/VolumeDriver.Capabilities" => return Ok(json!({"Capabilities": {"Scope": "local"}})),
            "/VolumeDriver.List" => {
                return Ok(
                    json!({"Volumes": self.definitions.keys().map(|n| self.volume(n)).collect::<Vec<_>>()}),
                )
            }
            _ => {}
        }
        validate_name(&req.name)?;
        let path = self.path(&req.name);
        if endpoint == "/VolumeDriver.Create" {
            if let Some(existing) = self.definitions.get(&req.name) {
                if req.opts.is_empty() || req.opts == existing.opts {
                    return Ok(json!({}));
                }
                return Err("volume already exists with different options".into());
            }
            validate(&req.opts)?;
            let mut definitions = self.definitions.clone();
            definitions.insert(req.name, Definition { opts: req.opts });
            self.persist(&definitions)?;
            self.definitions = definitions;
            return Ok(json!({}));
        }
        let def = self.definitions.get(&req.name).ok_or("unknown volume")?;
        match endpoint {
            "/VolumeDriver.Get" => Ok(json!({"Volume": self.volume(&req.name)})),
            "/VolumeDriver.Path" => Ok(json!({"Mountpoint": path})),
            "/VolumeDriver.Mount" => {
                validate_id(&req.id)?;
                let rt = self.runtime.entry(req.name).or_default();
                if !rt.mounted {
                    match path.symlink_metadata() {
                        Ok(meta) if meta.file_type().is_symlink() => {
                            return Err("mountpoint must not be a symlink".into());
                        }
                        Ok(meta) if !meta.is_dir() => {
                            return Err("mountpoint must be a directory".into());
                        }
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            fs::create_dir(&path).map_err(|_| "cannot create mountpoint")?;
                        }
                        // ProcessMounter detaches an abandoned FUSE mount before
                        // spawning. stat on that mount can return ENOTCONN.
                        Err(error) if error.raw_os_error() == Some(libc::ENOTCONN) => {}
                        Err(_) => return Err("cannot inspect mountpoint".into()),
                    }
                    self.mounter.mount(&def.opts, &path)?;
                    rt.mounted = true;
                }
                rt.ids.insert(req.id);
                Ok(json!({"Mountpoint": path}))
            }
            "/VolumeDriver.Unmount" => {
                validate_id(&req.id)?;
                let rt = self.runtime.entry(req.name).or_default();
                if rt.ids.contains(&req.id) && rt.ids.len() == 1 {
                    self.mounter.unmount(&path, false)?;
                    rt.mounted = false;
                }
                rt.ids.remove(&req.id);
                Ok(json!({}))
            }
            "/VolumeDriver.Remove" => {
                if self
                    .runtime
                    .get(&req.name)
                    .is_some_and(|r| r.mounted || !r.ids.is_empty())
                {
                    return Err("volume is in use".into());
                }
                // Also remove a stale FUSE mount left after an earlier child death.
                self.mounter.unmount(&path, true)?;
                let mut definitions = self.definitions.clone();
                definitions.remove(&req.name);
                self.persist(&definitions)?;
                self.definitions = definitions;
                self.runtime.remove(&req.name);
                let _ = fs::remove_dir(path);
                Ok(json!({}))
            }
            _ => Err("unknown endpoint".into()),
        }
    }
}

fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
        Err("ID must be nonempty, at most 256 bytes, with no control characters".into())
    } else {
        Ok(())
    }
}
