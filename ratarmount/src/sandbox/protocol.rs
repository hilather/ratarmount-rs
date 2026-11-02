//! Versioned JSON-lines messages. Unknown fields fail closed.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::path::PathBuf;

/// Version 1 is frozen: its requests and answers keep their baseline bytes.
pub const VERSION: u32 = 1;
pub const VERSION_2: u32 = 2;
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow_globs: Vec<String>,
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

/// Which reads the per-attempt operation journal records (`--journal-reads`).
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum JournalReads {
    #[default]
    All,
    First,
}

/// Only the strings `"all"` and `"first"`: a derived enum also takes the
/// map form `{"first": null}`.
impl<'de> Deserialize<'de> for JournalReads {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "all" => Ok(Self::All),
            "first" => Ok(Self::First),
            other => Err(serde::de::Error::unknown_variant(other, &["all", "first"])),
        }
    }
}

/// The per-attempt operation journal of a v2 `new` (§5.6). Every member is
/// always serialized, so `journal: {}` never hashes like an absent journal.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct JournalSpec {
    /// `--journal-exclude` globs, in order.
    pub exclude: Vec<String>,
    pub reads: JournalReads,
    /// Fsync the journal at unmount (`--journal-sync`).
    pub sync: bool,
}

/// Version 2: the v1 operations, where `new` also takes a `request_id`,
/// `lowers`, a `journal` and `retain`, and `list` takes `all`; plus
/// `finalize`. Fields and defaults are v1's, and they never change within
/// version 2; later releases only add fields, which an older daemon refuses
/// as unknown. Only `new` and `finalize` take a request ID: `create_base`,
/// `destroy` and every other operation take none, and a `request_id` there is
/// an unknown field (`invalid_request`).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationV2 {
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
        /// A string when present: `null` is refused, never read as "no ID".
        #[serde(
            default,
            deserialize_with = "some",
            skip_serializing_if = "Option::is_none"
        )]
        request_id: Option<String>,
        /// Sealed layer directories or bundles, bottom first, as sent (an
        /// array: `null` is refused). Empty means no lower stack.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        lowers: Vec<String>,
        /// An object when present: `null`, an array or a scalar is refused,
        /// never read as "no journal".
        #[serde(
            default,
            deserialize_with = "journal_object",
            skip_serializing_if = "Option::is_none"
        )]
        journal: Option<JournalSpec>,
        /// Keep each attempt in `retained/ID` once a `finalize` succeeds
        /// (R1c-1 §5.6). Linux only, TAR, directory and `git:///` bases only.
        #[serde(default, skip_serializing_if = "is_false")]
        retain: bool,
    },
    List {
        #[serde(default)]
        base: Option<String>,
        /// Also list this run's retained attempts, after the attempts map.
        /// Without it the answer is exactly v1 `list`'s.
        #[serde(default, skip_serializing_if = "is_false")]
        all: bool,
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
    /// A struct variant, so unknown fields are refused: serde drains and
    /// ignores the remaining keys of an internally tagged unit variant, as
    /// v1's `Shutdown` still does.
    Shutdown {},
    /// Stop, check, seal, hash and optionally pack an attempt (R1c-1 §5.4);
    /// retry-safe under `request_id`. Linux only. No v1 form.
    Finalize {
        id: String,
        #[serde(default, skip_serializing_if = "is_false")]
        pack: bool,
        /// A string when present: `null` is refused, never read as "no ID".
        #[serde(
            default,
            deserialize_with = "some",
            skip_serializing_if = "Option::is_none"
        )]
        request_id: Option<String>,
    },
}

fn is_false(value: &bool) -> bool {
    !value
}

impl OperationV2 {
    /// The same v1 operation; a `request_id` is not part of it. A `new` with
    /// `lowers`, a `journal` or `retain`, a `list` with `all` and `finalize`
    /// have no v1 form: the supervisor never converts one (§5.1).
    pub fn into_v1(self) -> Operation {
        match self {
            Self::CreateBase {
                name,
                source,
                options,
            } => Operation::CreateBase {
                name,
                source,
                options,
            },
            Self::New {
                base,
                count,
                overlay,
                quota,
                readonly_globs,
                request_id: _,
                lowers,
                journal,
                retain,
            } => {
                // `Supervisor::handle` takes every v2 `new` before this.
                assert!(
                    lowers.is_empty() && journal.is_none() && !retain,
                    "a layered, journaled or retained new has no v1 form"
                );
                Operation::New {
                    base,
                    count,
                    overlay,
                    quota,
                    readonly_globs,
                }
            }
            Self::List { base, all } => {
                assert!(!all, "a list of retained attempts has no v1 form");
                Operation::List { base }
            }
            Self::Diff { id, git } => Operation::Diff { id, git },
            Self::Stats { id } => Operation::Stats { id },
            Self::Destroy { id, base } => Operation::Destroy { id, base },
            Self::Shutdown {} => Operation::Shutdown,
            Self::Finalize { .. } => unreachable!("`Supervisor::handle` takes every finalize"),
        }
    }
}

pub(super) fn one() -> usize {
    1
}

/// `Some` of a present member: `null` is refused by `T`, never read as `None`.
fn some<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// A present `journal`, which must be a JSON object: the derived
/// `Deserialize` of a struct also accepts an array of its fields in order.
fn journal_object<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<JournalSpec>, D::Error> {
    struct Object;
    impl<'de> serde::de::Visitor<'de> for Object {
        type Value = JournalSpec;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a journal object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<JournalSpec, A::Error> {
            JournalSpec::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object).map(Some)
}

/// An operation of either version. `Request::parse` chooses the variant
/// itself; the untagged derive is only used to serialize.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum Op {
    V1(Operation),
    V2(OperationV2),
}

impl Op {
    pub fn version(&self) -> u32 {
        match self {
            Self::V1(_) => VERSION,
            Self::V2(_) => VERSION_2,
        }
    }
}

impl From<Operation> for Op {
    fn from(operation: Operation) -> Self {
        Self::V1(operation)
    }
}

impl From<OperationV2> for Op {
    fn from(operation: OperationV2) -> Self {
        Self::V2(operation)
    }
}

#[derive(Debug, Serialize)]
pub struct Request {
    pub version: u32,
    #[serde(flatten)]
    pub operation: Op,
}

/// A refused request line and the version its answer carries.
#[derive(Debug)]
pub struct Rejection {
    pub version: u32,
    pub error: ApiError,
}

impl Request {
    pub fn new(operation: impl Into<Op>) -> Self {
        let operation = operation.into();
        Self {
            version: operation.version(),
            operation,
        }
    }

    /// Before its version is known (invalid JSON, or a `version` that is not
    /// the integer 1 or 2) a line is refused in a v1 answer with the baseline
    /// bytes; afterwards in an answer of its own version.
    pub fn parse(line: &[u8]) -> Result<Self, Rejection> {
        let invalid = |version, error: serde_json::Error| Rejection {
            version,
            error: ApiError::new("invalid_request", error.to_string()),
        };
        // Deserialize separately so deny_unknown_fields also covers the envelope.
        let mut value: Value = serde_json::from_slice(line).map_err(|e| invalid(VERSION, e))?;
        let version = value.as_object_mut().and_then(|m| m.remove("version"));
        let operation = match version.as_ref().and_then(Value::as_u64) {
            Some(1) => Op::V1(serde_json::from_value(value).map_err(|e| invalid(VERSION, e))?),
            Some(2) => Op::V2(serde_json::from_value(value).map_err(|e| invalid(VERSION_2, e))?),
            _ => {
                return Err(Rejection {
                    version: VERSION,
                    error: ApiError::new("unsupported_version", "version must be 1"),
                })
            }
        };
        Ok(Self::new(operation))
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
    pub fn from_result(version: u32, result: Result<Value, ApiError>) -> Self {
        match result {
            Ok(result) => Self {
                version,
                ok: true,
                result: Some(result),
                error: None,
            },
            Err(error) => Self {
                version,
                ok: false,
                result: None,
                error: Some(error),
            },
        }
    }
}
