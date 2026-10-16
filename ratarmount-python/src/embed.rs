//! Native Session operations. Blocking work and final Session drops run detached.

use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use pyo3::exceptions::{PyException, PyIsADirectoryError, PyKeyError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyBytes, PyDict, PyType};
use ratarmount_session::{
    DirCursor, DirEnt, Error, ExtractRequest, IndexPolicy, OffsetCursor, OpenRequest, Overwrite,
    ParallelizationSpec, ReadRequest, Recreate, Session,
};
use secrecy::SecretString;

pyo3::create_exception!(
    ratarmount_rs,
    RatarmountError,
    PyException,
    "Archive operation failed."
);
pyo3::create_exception!(
    ratarmount_rs,
    BadPassword,
    RatarmountError,
    "Password rejected or required."
);
pyo3::create_exception!(
    ratarmount_rs,
    NotMappable,
    RatarmountError,
    "Member has no contiguous local extent; use read()."
);

fn member_not_found_type<'py>(py: Python<'py>) -> PyResult<&'py Bound<'py, PyType>> {
    static TYPE: PyOnceLock<Py<PyType>> = PyOnceLock::new();
    TYPE.get_or_try_init(py, || {
        let dict = PyDict::new(py);
        dict.set_item("__module__", "ratarmount_rs")?;
        dict.set_item("__doc__", "Archive member or source was not found.")?;
        py.get_type::<PyType>()
            .call1((
                "MemberNotFound",
                (
                    py.get_type::<PyKeyError>(),
                    py.get_type::<RatarmountError>(),
                ),
                dict,
            ))?
            .cast_into::<PyType>()
            .map(Bound::unbind)
            .map_err(Into::into)
    })
    .map(|ty| ty.bind(py))
}

fn to_py(err: Error) -> PyErr {
    match err {
        Error::NotFound => Python::attach(|py| match member_not_found_type(py) {
            Ok(ty) => PyErr::from_type(ty.clone(), "not found"),
            Err(err) => err,
        }),
        Error::BadPassword => BadPassword::new_err("password rejected or required"),
        Error::PathEscape(path) => {
            PyValueError::new_err(format!("member path escapes destination: {path}"))
        }
        Error::UnsupportedFormat(kind) => {
            RatarmountError::new_err(format!("unsupported format: {kind}"))
        }
        Error::CorruptIndex(detail) => {
            RatarmountError::new_err(format!("corrupt or mismatched index: {detail}"))
        }
        other => RatarmountError::new_err(other.to_string()),
    }
}

fn open_request(
    path: &str,
    password: Option<String>,
    index: Option<String>,
    recursive: bool,
    parallelization: u32,
) -> OpenRequest {
    let (policy, explicit_index) = match index.as_deref() {
        None | Some("temp") => (IndexPolicy::Temp, None),
        Some("sidecar") => (IndexPolicy::Sibling, None),
        Some(path) => (IndexPolicy::Explicit, Some(PathBuf::from(path))),
    };
    OpenRequest {
        source: crate::split_ratar_url(path),
        index: policy,
        explicit_index,
        extra_dirs: Vec::new(),
        password: password.map(SecretString::new),
        recursive,
        recursion_depth: None,
        parallelization: ParallelizationSpec::new(parallelization),
        recreate: Recreate::IfInvalid,
    }
}

/// Metadata for an archive entry. `mtime` is Unix seconds, or None on cheap pages.
#[pyclass(frozen, get_all, module = "ratarmount_rs")]
struct Entry {
    name: String,
    path: String,
    is_dir: bool,
    is_file: bool,
    is_symlink: bool,
    size: u64,
    mtime: Option<i64>,
    mode: u32,
}

impl From<DirEnt> for Entry {
    fn from(ent: DirEnt) -> Self {
        Self {
            name: ent.name,
            path: ent.path,
            is_dir: ent.is_dir,
            is_file: ent.mode & 0o170000 == 0o100000,
            is_symlink: ent.mode & 0o170000 == 0o120000,
            size: ent.size,
            mtime: ent.mtime,
            mode: ent.mode,
        }
    }
}

#[pyclass(frozen, module = "ratarmount_rs._native")]
struct Archive {
    // Backends can share a seek position between member readers. Keep each
    // complete Session operation atomic, including consuming RangeReader.
    session: Mutex<Option<Arc<Mutex<Session>>>>,
}

impl Archive {
    fn session(&self) -> PyResult<Arc<Mutex<Session>>> {
        self.session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| PyValueError::new_err("archive is closed"))
    }
}

impl Drop for Archive {
    fn drop(&mut self) {
        let session = self
            .session
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        Python::try_attach(move |py| py.detach(move || drop(session)));
    }
}

type OffsetKey = (Option<i64>, String);
type EntryPage = (Vec<Entry>, Option<OffsetKey>);

#[pymethods]
impl Archive {
    /// List every immediate child using directory keyset pages.
    fn ls(&self, py: Python<'_>, path: String) -> PyResult<Vec<Entry>> {
        let session = self.session()?;
        py.detach(move || {
            let session = session.lock().unwrap_or_else(|e| e.into_inner());
            let info = session.lookup(&path)?.ok_or(Error::NotFound)?;
            if !info.is_dir {
                return Err(Error::UnsupportedFormat("ls requires a directory".into()));
            }
            let mut cursor = DirCursor::Start;
            let mut entries = Vec::new();
            loop {
                let page = session.list_dirents_page(&path, cursor, 1024)?;
                entries.extend(page.entries.into_iter().map(Entry::from));
                match page.next_cursor {
                    Some(next) => cursor = next,
                    None => return Ok(entries),
                }
            }
        })
        .map_err(to_py)
    }

    /// Look up complete metadata for one entry.
    fn stat(&self, py: Python<'_>, path: String) -> PyResult<Entry> {
        let session = self.session()?;
        py.detach(move || {
            let session = session.lock().unwrap_or_else(|e| e.into_inner());
            session.lookup(&path)?.ok_or(Error::NotFound)
        })
        .map(Entry::from)
        .map_err(to_py)
    }

    /// Read a bounded range as bytes. -1 reads through EOF; zero reads nothing.
    fn read<'py>(
        &self,
        py: Python<'py>,
        path: String,
        offset: i64,
        size: i64,
    ) -> PyResult<Bound<'py, PyBytes>> {
        if offset < 0 || size < -1 {
            return Err(PyValueError::new_err("offset must be >= 0 and size >= -1"));
        }
        let session = self.session()?;
        let bytes = py.detach(move || -> PyResult<Vec<u8>> {
            let session = session.lock().unwrap_or_else(|e| e.into_inner());
            let info = session
                .lookup(&path)
                .map_err(to_py)?
                .ok_or_else(|| to_py(Error::NotFound))?;
            if info.is_dir {
                return Err(PyIsADirectoryError::new_err(path));
            }
            let remaining = info.size.saturating_sub(offset as u64);
            let max_len = if size == -1 {
                remaining
            } else {
                remaining.min(size as u64)
            };
            let mut reader = session
                .read_range(ReadRequest {
                    path,
                    offset: offset as u64,
                    max_len,
                })
                .map_err(to_py)?;
            let mut bytes = Vec::new();
            reader
                .read_to_end(&mut bytes)
                .map_err(|e| RatarmountError::new_err(e.to_string()))?;
            Ok(bytes)
        })?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Return the local backing path, data offset and length, or NotMappable.
    fn extent(&self, py: Python<'_>, path: String) -> PyResult<(PathBuf, u64, u64)> {
        let session = self.session()?;
        let extent = py
            .detach(move || {
                let session = session.lock().unwrap_or_else(|e| e.into_inner());
                session.member_extent(&path)
            })
            .map_err(to_py)?;
        extent.map(|e| (e.file, e.offset, e.len)).ok_or_else(|| {
            NotMappable::new_err(
                "member is not a contiguous local plain-TAR payload; use read() instead",
            )
        })
    }

    /// One bounded page of newest-wins regular payloads in archive order.
    fn offset_page(&self, py: Python<'_>, cursor: Option<OffsetKey>) -> PyResult<EntryPage> {
        let session = self.session()?;
        let cursor = cursor.map_or(OffsetCursor::Start, |(offsetheader, path)| {
            OffsetCursor::AfterOffset { offsetheader, path }
        });
        let page = py
            .detach(move || {
                let session = session.lock().unwrap_or_else(|e| e.into_inner());
                session.iter_by_offset_page(cursor, 1024)
            })
            .map_err(to_py)?;
        let next = match page.next {
            Some(OffsetCursor::AfterOffset { offsetheader, path }) => Some((offsetheader, path)),
            _ => None,
        };
        Ok((page.entries.into_iter().map(Entry::from).collect(), next))
    }

    /// Stream members to a directory, rejecting path escapes.
    fn extract(
        &self,
        py: Python<'_>,
        members: Vec<String>,
        dest: PathBuf,
        existing: &str,
    ) -> PyResult<()> {
        let overwrite = match existing {
            "skip" => Overwrite::Skip,
            "replace" => Overwrite::Replace,
            _ => {
                return Err(PyValueError::new_err(
                    "existing must be 'skip' or 'replace'",
                ))
            }
        };
        let session = self.session()?;
        py.detach(move || {
            let session = session.lock().unwrap_or_else(|e| e.into_inner());
            session.extract_to(
                ExtractRequest {
                    members,
                    dest_dir: dest,
                    overwrite,
                    allow_unsafe_paths: false,
                },
                None,
                None,
            )
        })
        .map_err(to_py)
    }

    /// Close the archive. In-flight operations may finish using their Session reference.
    fn close(&self, py: Python<'_>) {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        py.detach(move || drop(session));
    }

    #[getter]
    fn closed(&self) -> bool {
        self.session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none()
    }
}

/// Open any local path or archive URL supported by Session.
#[pyfunction]
#[pyo3(signature = (path, *, password=None, index=None, recursive=false, parallelization=1))]
fn open(
    py: Python<'_>,
    path: &str,
    password: Option<String>,
    index: Option<String>,
    recursive: bool,
    parallelization: u32,
) -> PyResult<Archive> {
    let path = path.to_string();
    let session = py
        .detach(move || {
            Session::open(open_request(
                &path,
                password,
                index,
                recursive,
                parallelization,
            ))
        })
        .map_err(to_py)?;
    Ok(Archive {
        session: Mutex::new(Some(Arc::new(Mutex::new(session)))),
    })
}

/// Strip an optional ratar:// prefix without splitting an inner archive URL.
#[pyfunction]
fn split_url(url: &str) -> String {
    match crate::split_ratar_url(url) {
        ratarmount_session::SourceSpec::Url(url) => url,
        ratarmount_session::SourceSpec::Path(path) => path.to_string_lossy().into_owned(),
    }
}

#[pymodule]
fn _native(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Archive>()?;
    module.add_class::<Entry>()?;
    module.add("RatarmountError", py.get_type::<RatarmountError>())?;
    module.add("MemberNotFound", member_not_found_type(py)?)?;
    module.add("BadPassword", py.get_type::<BadPassword>())?;
    module.add("NotMappable", py.get_type::<NotMappable>())?;
    module.add_function(wrap_pyfunction!(open, module)?)?;
    module.add_function(wrap_pyfunction!(split_url, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};

    /// Regression: Session errors retain their Python exception families.
    #[test]
    fn regression_error_mapping_preserves_exception_families() {
        Python::initialize();
        Python::attach(|py| {
            let missing = to_py(Error::NotFound);
            assert!(missing.is_instance_of::<PyKeyError>(py));
            assert!(missing.is_instance_of::<RatarmountError>(py));
            assert!(to_py(Error::BadPassword).is_instance_of::<BadPassword>(py));
            assert!(to_py(Error::PathEscape("../x".into())).is_instance_of::<PyValueError>(py));
            for error in [
                Error::NotWritable("/x".into()),
                Error::SiblingNotWritable("/x".into()),
                Error::UnsupportedFormat("format".into()),
                Error::CorruptIndex("bad".into()),
                Error::Cancelled,
                Error::Internal("io".into()),
            ] {
                assert!(to_py(error).is_instance_of::<RatarmountError>(py));
            }
        });
    }

    /// Regression: request options and secrets survive the Python boundary.
    #[test]
    fn regression_open_request_keeps_options_and_redacts_password() {
        let request = open_request(
            "set.tar",
            Some("secret-password".into()),
            Some("index.sqlite".into()),
            true,
            4,
        );
        assert!(!format!("{request:?}").contains("secret-password"));
        assert!(request.password.is_some());
        assert!(request.recursive);
        assert_eq!(request.index, IndexPolicy::Explicit);
        assert_eq!(request.explicit_index, Some("index.sqlite".into()));
        assert_eq!(request.parallelization, ParallelizationSpec::new(4));
        assert_eq!(
            open_request("x", None, None, false, 1).index,
            IndexPolicy::Temp
        );
        assert_eq!(
            open_request("x", None, Some("sidecar".into()), false, 0).index,
            IndexPolicy::Sibling
        );
    }

    /// Regression: the in-process module still opens, pages, reads bytes and extracts.
    #[test]
    fn regression_embedding_open_list_read_extract() {
        let dir = tempfile::tempdir().unwrap();
        let tar = dir.path().join("set.tar");
        let mut file = std::fs::File::create(&tar).unwrap();
        write_ustar_members(
            &mut file,
            &[UstarMember {
                path: "hello.txt",
                payload: UstarPayload::File { bytes: b"abcdWXYZ" },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            }],
        )
        .unwrap();
        write_tar_eof(&mut file).unwrap();
        drop(file);
        Python::initialize();
        Python::attach(|py| -> PyResult<()> {
            let module = pyo3::wrap_pymodule!(_native)(py);
            let archive = module
                .getattr(py, "open")?
                .call1(py, (tar.to_str().unwrap(),))?;
            assert_eq!(archive.call_method1(py, "ls", ("/",))?.bind(py).len()?, 1);
            let bytes: Vec<u8> = archive
                .call_method1(py, "read", ("/hello.txt", 0, 4))?
                .extract(py)?;
            assert_eq!(bytes, b"abcd");
            let out = dir.path().join("out");
            archive.call_method1(py, "extract", (vec!["hello.txt"], &out, "skip"))?;
            assert_eq!(std::fs::read(out.join("hello.txt")).unwrap(), b"abcdWXYZ");
            archive.call_method0(py, "close")?;
            assert!(archive.getattr(py, "closed")?.extract::<bool>(py)?);
            Ok(())
        })
        .unwrap();
    }
}
