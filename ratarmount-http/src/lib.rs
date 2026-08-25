//! HTTP Range and WebDAV export of a [`ratarmount_core::MountSource`] (P-5 / P-6).
//!
//! GET/HEAD with byte ranges (default bind `127.0.0.1:20491`). WebDAV PROPFIND
//! Depth 0/1 plus overlay PUT/DELETE/MKCOL/MOVE (`127.0.0.1:20492`). Writes
//! need `-w`. `--http` serves the **indexed tree**, not host archive bytes.
//! Portable index download is HTTP-only `GET /.ratarmount-control/index.sqlite`
//! ([`INDEX_MEDIA_TYPE`]), not a FUSE control file.

/// Portable 0.7.x SQLite sidecar Content-Type (G-2 blob family `v1`).
///
/// Same string as `ratarmount_index::INDEX_MEDIA_TYPE`. Not SOCI / eStargz.
pub const INDEX_MEDIA_TYPE: &str = "application/vnd.ratarmount.index.v1+sqlite";

/// HTTP-only download path for the sidecar (not a FUSE `/.ratarmount-control` file).
pub const INDEX_SIDECAR_PATH: &str = "/.ratarmount-control/index.sqlite";

mod handler;
mod request;
mod serve;
mod webdav;

pub use ratarmount_export_core::{
    default_export_bind, export_bind_string, parse_export_bind, BindError, ExportServerHandle,
    ExportStop, DEFAULT_HTTP_PORT, DEFAULT_WEBDAV_PORT,
};

pub use serve::{
    parse_http_bind, serve_blocking, serve_webdav_blocking, spawn_http_thread, spawn_webdav_thread,
    HttpOptions, DEFAULT_HTTP_BIND,
};
pub use webdav::{
    parse_webdav_bind, webdav_credentials_from_env, WebDavOptions, DEFAULT_WEBDAV_BIND,
};

#[cfg(test)]
mod tests;
