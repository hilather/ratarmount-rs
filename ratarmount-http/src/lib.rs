//! HTTP Range export of a [`ratarmount_core::MountSource`] (P-5).
//!
//! Userspace GET/HEAD only (no WebDAV). Default bind `127.0.0.1:20491`.
//! Overlay writes are out of v1. CLI `--http` is wired in a later PR.

mod handler;
mod request;
mod serve;

pub use ratarmount_export_core::{
    default_export_bind, export_bind_string, parse_export_bind, BindError, ExportServerHandle,
    ExportStop, DEFAULT_HTTP_PORT,
};

pub use serve::{
    parse_http_bind, serve_blocking, spawn_http_thread, HttpOptions, DEFAULT_HTTP_BIND,
};

#[cfg(test)]
mod tests;
