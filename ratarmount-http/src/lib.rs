//! HTTP Range and WebDAV export of a [`ratarmount_core::MountSource`] (P-5 / P-6).
//!
//! GET/HEAD with byte ranges (default bind `127.0.0.1:20491`). WebDAV PROPFIND
//! Depth 0/1 plus overlay PUT/DELETE/MKCOL/MOVE (`127.0.0.1:20492`). Writes
//! need `-w`. CLI `--http` / `--webdav` are wired in a later PR.

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
pub use webdav::{parse_webdav_bind, WebDavOptions, DEFAULT_WEBDAV_BIND};

#[cfg(test)]
mod tests;
