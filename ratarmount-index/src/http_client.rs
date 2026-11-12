//! Migration facade for #311 (ureq 2 → 3), hidden until callers move in S2/S3.
//! S1a–S3 use ureq 2's native redirects, gzip, Accept-Encoding and URL parsing.

use std::error::Error as StdError;
use std::fmt;
use std::io::{self, Read};
use std::sync::OnceLock;
use std::time::Duration;

const DIRECT_REDIRECTS: u32 = 5;
const NO_REDIRECTS: u32 = 0;
const POOLED_IDLE: usize = 128;
const POOLED_IDLE_PER_HOST: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const INTO_STRING_LIMIT: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Pooled,
    Direct,
    Probe { timeout: Duration },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSummary {
    pub redirects: u32,
    pub reuse: bool,
    // Fresh agents have no cross-request pool; their internal limits are immaterial.
    pub max_idle_connections: Option<usize>,
    pub max_idle_connections_per_host: Option<usize>,
    pub idle_timeout: Option<Duration>,
    pub connect_timeout: Option<Duration>,
    pub overall_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub env_proxy: bool,
}

pub fn profile_summary(profile: &Profile) -> ProfileSummary {
    let pooled = matches!(profile, Profile::Pooled);
    ProfileSummary {
        redirects: if matches!(profile, Profile::Direct) {
            DIRECT_REDIRECTS
        } else {
            NO_REDIRECTS
        },
        reuse: pooled,
        max_idle_connections: pooled.then_some(POOLED_IDLE),
        max_idle_connections_per_host: pooled.then_some(POOLED_IDLE_PER_HOST),
        idle_timeout: None,
        connect_timeout: Some(CONNECT_TIMEOUT),
        overall_timeout: match profile {
            Profile::Probe { timeout } => Some(*timeout),
            _ => None,
        },
        read_timeout: None,
        write_timeout: None,
        env_proxy: false,
    }
}

#[derive(Debug)]
pub struct Request {
    profile: Profile,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    timeout: Option<Duration>,
}

pub fn request(profile: Profile, method: &str, url: &str) -> Request {
    Request {
        profile,
        method: method.into(),
        url: url.into(),
        headers: Vec::new(),
        timeout: None,
    }
}

pub fn get(profile: Profile, url: &str) -> Request {
    request(profile, "GET", url)
}

pub fn head(profile: Profile, url: &str) -> Request {
    request(profile, "HEAD", url)
}

pub fn put(profile: Profile, url: &str) -> Request {
    request(profile, "PUT", url)
}

pub fn post(profile: Profile, url: &str) -> Request {
    request(profile, "POST", url)
}

// Status errors keep the readable response, as existing callers require.
#[allow(clippy::result_large_err)]
impl Request {
    pub fn set(mut self, name: &str, value: &str) -> Self {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn call(self) -> Result<HttpResponse, HttpError> {
        self.into_native()
            .call()
            .map(HttpResponse::from_native)
            .map_err(Into::into)
    }

    pub fn send_bytes(self, body: &[u8]) -> Result<HttpResponse, HttpError> {
        self.into_native()
            .send_bytes(body)
            .map(HttpResponse::from_native)
            .map_err(Into::into)
    }

    pub fn send_string(self, body: &str) -> Result<HttpResponse, HttpError> {
        self.into_native()
            .send_string(body)
            .map(HttpResponse::from_native)
            .map_err(Into::into)
    }

    pub fn send_reader(self, body: impl Read) -> Result<HttpResponse, HttpError> {
        self.into_native()
            .send(body)
            .map(HttpResponse::from_native)
            .map_err(Into::into)
    }
}

#[derive(Debug)]
struct HeaderValues {
    name: String,
    first: Option<String>,
    all: Vec<String>,
}

pub struct HttpResponse {
    status: u16,
    url: String,
    header_names: Vec<String>,
    headers: Vec<HeaderValues>,
    body: Box<dyn Read + Send + Sync + 'static>,
    redirected_from: Option<String>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("url", &self.url)
            .field("header_names", &self.header_names)
            .field("headers", &self.headers)
            .field("redirected_from", &self.redirected_from)
            .finish_non_exhaustive()
    }
}

impl HttpResponse {
    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn get_url(&self) -> &str {
        &self.url
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))?
            .first
            .as_deref()
    }

    pub fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.all.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub fn header_names(&self) -> Vec<String> {
        self.header_names.clone()
    }

    pub fn into_reader(self) -> Box<dyn Read + Send + Sync + 'static> {
        self.body
    }

    pub fn into_string(self) -> io::Result<String> {
        let mut bytes = Vec::new();
        self.into_reader()
            .take((INTO_STRING_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > INTO_STRING_LIMIT {
            return Err(io::Error::other("response too big for into_string"));
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn for_test(
        status: u16,
        url: &str,
        headers: &[(&str, &str)],
        body: impl Into<Vec<u8>>,
    ) -> Self {
        let mut values: Vec<HeaderValues> = Vec::new();
        let mut names = Vec::new();
        for &(name, value) in headers {
            let name = name.to_ascii_lowercase();
            names.push(name.clone());
            // Keep ureq 2's trimmed ASCII values and invalid-first-line semantics.
            let value = value.trim();
            let valid = value
                .bytes()
                .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b));
            let value = valid.then(|| value.to_owned());
            if let Some(h) = values.iter_mut().find(|h| h.name == name) {
                h.all.extend(value);
            } else {
                values.push(HeaderValues {
                    name,
                    first: value.clone(),
                    all: value.into_iter().collect(),
                });
            }
        }
        Self {
            status,
            url: url.into(),
            header_names: names,
            headers: values,
            body: Box::new(io::Cursor::new(body.into())),
            redirected_from: None,
        }
    }
}

#[derive(Debug)]
pub enum HttpError {
    Status(u16, HttpResponse),
    Transport(TransportError),
}

impl HttpError {
    pub fn into_io(self) -> io::Error {
        let kind = match &self {
            Self::Transport(e) => e
                .source()
                .and_then(|s| s.downcast_ref::<io::Error>())
                .map_or(io::ErrorKind::Other, io::Error::kind),
            Self::Status(..) => io::ErrorKind::Other,
        };
        io::Error::new(kind, self.to_string())
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status(code, response) => {
                write!(f, "{}: status code {code}", response.get_url())?;
                if let Some(first) = &response.redirected_from {
                    write!(f, " (redirected from {first})")?;
                }
                Ok(())
            }
            Self::Transport(error) => error.fmt(f),
        }
    }
}

impl StdError for HttpError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Transport(error) => error.source(),
            Self::Status(..) => None,
        }
    }
}

#[derive(Debug)]
pub struct TransportError {
    repr: TransportRepr,
}

#[derive(Debug)]
enum TransportRepr {
    Native(ureq::Transport),
    Owned {
        kind: TransportKind,
        message: Option<String>,
        url: Option<String>,
        source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    },
}

impl TransportError {
    pub fn kind(&self) -> TransportKind {
        match &self.repr {
            TransportRepr::Native(error) => error.kind().into(),
            TransportRepr::Owned { kind, .. } => *kind,
        }
    }

    pub fn message(&self) -> Option<&str> {
        match &self.repr {
            TransportRepr::Native(error) => error.message(),
            TransportRepr::Owned { message, .. } => message.as_deref(),
        }
    }

    pub fn url(&self) -> Option<&str> {
        match &self.repr {
            TransportRepr::Native(error) => error.url().map(|url| url.as_str()),
            TransportRepr::Owned { url, .. } => url.as_deref(),
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let TransportRepr::Native(error) = &self.repr {
            return error.fmt(f);
        }
        if let Some(url) = self.url() {
            write!(f, "{url}: ")?;
        }
        write!(f, "{}", self.kind())?;
        if let Some(message) = self.message() {
            write!(f, ": {message}")?;
        }
        if let Some(source) = self.source() {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl StdError for TransportError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.repr {
            TransportRepr::Native(error) => error.source(),
            TransportRepr::Owned { source, .. } => source.as_ref().map(|s| s.as_ref() as _),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    InvalidUrl,
    UnknownScheme,
    Dns,
    InsecureRequestHttpsOnly,
    ConnectionFailed,
    TooManyRedirects,
    BadStatus,
    BadHeader,
    Io,
    InvalidProxyUrl,
    ProxyConnect,
    ProxyUnauthorized,
    HTTP,
}

impl fmt::Display for TransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidUrl => "Bad URL",
            Self::UnknownScheme => "Unknown Scheme",
            Self::Dns => "Dns Failed",
            Self::InsecureRequestHttpsOnly => "Insecure request attempted with https_only set",
            Self::ConnectionFailed => "Connection Failed",
            Self::TooManyRedirects => "Too Many Redirects",
            Self::BadStatus => "Bad Status",
            Self::BadHeader => "Bad Header",
            Self::Io => "Network Error",
            Self::InvalidProxyUrl => "Malformed proxy",
            Self::ProxyConnect => "Proxy failed to connect",
            Self::ProxyUnauthorized => "Provided proxy credentials are incorrect",
            Self::HTTP => "HTTP status error",
        })
    }
}

impl From<io::Error> for HttpError {
    fn from(error: io::Error) -> Self {
        Self::Transport(TransportError {
            repr: TransportRepr::Owned {
                kind: TransportKind::Io,
                message: None,
                url: None,
                source: Some(Box::new(error)),
            },
        })
    }
}

impl From<url::ParseError> for HttpError {
    fn from(error: url::ParseError) -> Self {
        Self::Transport(TransportError {
            repr: TransportRepr::Owned {
                kind: TransportKind::InvalidUrl,
                message: Some(format!("failed to parse URL: {error:?}")),
                url: None,
                source: Some(Box::new(error)),
            },
        })
    }
}

// ureq 2 engine and temporary S1a–S3 bridges; replaced in S4a/S4b.
fn build_agent(profile: &Profile) -> ureq::Agent {
    let summary = profile_summary(profile);
    let mut builder = ureq::AgentBuilder::new()
        .redirects(summary.redirects)
        .timeout_connect(CONNECT_TIMEOUT)
        .redirect_auth_headers(ureq::RedirectAuthHeaders::Never);
    if let (Some(max), Some(per_host)) = (
        summary.max_idle_connections,
        summary.max_idle_connections_per_host,
    ) {
        builder = builder
            .max_idle_connections(max)
            .max_idle_connections_per_host(per_host);
    }
    if let Some(timeout) = summary.overall_timeout {
        builder = builder.timeout(timeout);
    }
    builder.build()
}

impl Request {
    fn into_native(self) -> ureq::Request {
        static POOLED: OnceLock<ureq::Agent> = OnceLock::new();
        let agent = match self.profile {
            Profile::Pooled => POOLED.get_or_init(|| build_agent(&Profile::Pooled)).clone(),
            profile => build_agent(&profile),
        };
        let mut request = agent.request(&self.method, &self.url);
        for (name, value) in self.headers {
            request = request.set(&name, &value);
        }
        if let Some(timeout) = self.timeout {
            request = request.timeout(timeout);
        }
        request
    }
}

impl HttpResponse {
    fn from_native(response: ureq::Response) -> Self {
        let names = response.headers_names();
        let mut headers: Vec<HeaderValues> = Vec::new();
        for name in &names {
            if !headers.iter().any(|h| h.name == *name) {
                // `all().first()` loses an invalid first line; snapshot both APIs.
                headers.push(HeaderValues {
                    name: name.clone(),
                    first: response.header(name).map(str::to_owned),
                    all: response.all(name).into_iter().map(str::to_owned).collect(),
                });
            }
        }
        Self {
            status: response.status(),
            url: response.get_url().into(),
            header_names: names,
            headers,
            body: response.into_reader(),
            redirected_from: None,
        }
    }
}

impl From<ureq::Error> for HttpError {
    fn from(error: ureq::Error) -> Self {
        match error {
            error @ ureq::Error::Status(..) => {
                // ureq 2 exposes history only through Display. Keep just the origin
                // until the facade owns the redirect loop in S4a.
                let display = error.to_string();
                let ureq::Error::Status(code, response) = error else {
                    unreachable!()
                };
                let prefix = format!("{}: status code {code}", response.get_url());
                let origin = display
                    .strip_prefix(&prefix)
                    .and_then(|s| s.strip_prefix(" (redirected from "))
                    .and_then(|s| s.strip_suffix(')'))
                    .map(str::to_owned);
                let mut response = HttpResponse::from_native(response);
                response.redirected_from = origin;
                Self::Status(code, response)
            }
            ureq::Error::Transport(error) => Self::Transport(TransportError {
                repr: TransportRepr::Native(error),
            }),
        }
    }
}

impl From<ureq::ErrorKind> for TransportKind {
    fn from(kind: ureq::ErrorKind) -> Self {
        match kind {
            ureq::ErrorKind::InvalidUrl => Self::InvalidUrl,
            ureq::ErrorKind::UnknownScheme => Self::UnknownScheme,
            ureq::ErrorKind::Dns => Self::Dns,
            ureq::ErrorKind::InsecureRequestHttpsOnly => Self::InsecureRequestHttpsOnly,
            ureq::ErrorKind::ConnectionFailed => Self::ConnectionFailed,
            ureq::ErrorKind::TooManyRedirects => Self::TooManyRedirects,
            ureq::ErrorKind::BadStatus => Self::BadStatus,
            ureq::ErrorKind::BadHeader => Self::BadHeader,
            ureq::ErrorKind::Io => Self::Io,
            ureq::ErrorKind::InvalidProxyUrl => Self::InvalidProxyUrl,
            ureq::ErrorKind::ProxyConnect => Self::ProxyConnect,
            ureq::ErrorKind::ProxyUnauthorized => Self::ProxyUnauthorized,
            ureq::ErrorKind::HTTP => Self::HTTP,
        }
    }
}

#[cfg(test)]
#[test]
fn ureq_2_engine_only_error_display_cross_check() {
    use tests::{response, Mock, TIMEOUT};
    let mock = Mock::new(vec![
        response(302, &[("Location", "/final")], b""),
        response(404, &[], b"missing"),
    ]);
    let native = ureq::get(&mock.url("/first"))
        .timeout(TIMEOUT)
        .call()
        .unwrap_err();
    let expected = native.to_string();
    let facade = HttpError::from(native);
    assert_eq!(facade.to_string(), expected);
    mock.finish();
    for native in [
        ureq::Error::from(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
        ureq::Error::from(url::ParseError::RelativeUrlWithoutBase),
    ] {
        let expected = native.to_string();
        assert_eq!(HttpError::from(native).to_string(), expected);
    }
    assert_eq!(
        HttpError::from(io::Error::other("owned")).to_string(),
        ureq::Error::from(io::Error::other("owned")).to_string()
    );
    assert_eq!(
        HttpError::from(url::ParseError::EmptyHost).to_string(),
        ureq::Error::from(url::ParseError::EmptyHost).to_string()
    );
}

const _: fn() = || {
    fn assert_traits<T: Send + Sync + 'static>() {}
    assert_traits::<HttpResponse>();
    assert_traits::<HttpError>();
    assert_traits::<Request>();
    assert_traits::<Box<dyn Read + Send + Sync + 'static>>();
    assert_traits::<ureq::Transport>();
};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_behaviour;
