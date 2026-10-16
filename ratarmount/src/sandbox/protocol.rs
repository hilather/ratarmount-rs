//! Versioned JSON-lines messages. Unknown fields fail closed.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

pub const VERSION: u32 = 1;
pub const MAX_REQUEST: usize = 1024 * 1024;
pub const MAX_RESPONSE: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BaseOptions {
    pub git_synthetic_head: bool,
    pub recursive: bool,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Octal string, like the mount CLI.
    pub umask: Option<String>,
    pub readonly_globs: Vec<String>,
    /// Logical bytes (not a filesystem block limit).
    pub quota: Option<u64>,
    pub passthrough: Option<String>,
    pub binds: Vec<String>,
    pub allow_other: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Overlay {
    Tmpfs,
    #[default]
    Disk,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    CreateBase {
        name: String,
        source: String,
        #[serde(default)]
        options: BaseOptions,
    },
    New {
        base: String,
        #[serde(default = "one")]
        count: usize,
        #[serde(default)]
        overlay: Overlay,
        #[serde(default)]
        quota: Option<u64>,
        #[serde(default)]
        readonly_globs: Vec<String>,
    },
    List {
        #[serde(default)]
        base: Option<String>,
    },
    Diff {
        id: String,
        #[serde(default)]
        git: bool,
    },
    Stats {
        id: String,
    },
    Destroy {
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        base: Option<String>,
    },
    Shutdown,
}

fn one() -> usize {
    1
}

#[derive(Debug, Serialize)]
pub struct Request {
    pub version: u32,
    #[serde(flatten)]
    pub operation: Operation,
}

impl Request {
    pub fn parse(line: &[u8]) -> Result<Self, ApiError> {
        // Deserialize separately so deny_unknown_fields also covers the envelope.
        let mut value: Value = serde_json::from_slice(line)
            .map_err(|e| ApiError::new("invalid_request", e.to_string()))?;
        let version = value.as_object_mut().and_then(|m| m.remove("version"));
        if version != Some(Value::from(VERSION)) {
            return Err(ApiError::new("unsupported_version", "version must be 1"));
        }
        let operation = serde_json::from_value(value)
            .map_err(|e| ApiError::new("invalid_request", e.to_string()))?;
        Ok(Self {
            version: VERSION,
            operation,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Base {
    pub name: String,
    pub source: String,
    pub options: BaseOptions,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Attempt {
    pub id: String,
    pub base: String,
    pub path: PathBuf,
    pub overlay_dir: PathBuf,
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> Self {
        Self::new("io", error.to_string())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Response {
    pub version: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

impl Response {
    pub fn from_result(result: Result<Value, ApiError>) -> Self {
        match result {
            Ok(result) => Self {
                version: VERSION,
                ok: true,
                result: Some(result),
                error: None,
            },
            Err(error) => Self {
                version: VERSION,
                ok: false,
                result: None,
                error: Some(error),
            },
        }
    }
}
