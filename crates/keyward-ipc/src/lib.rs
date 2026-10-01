//! IPC protocol between keyward frontends and `keyward-agent`.
//!
//! Wire format: each message is a 4-byte big-endian length followed by a UTF-8
//! JSON document. One request yields exactly one response. The protocol is
//! deliberately tiny and depends only on serde + tokio, so any frontend (GTK,
//! CLI, a future Slint/Qt app, or a non-Rust client) can implement it.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

/// Protocol version; bump on incompatible changes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Upper bound on a single frame. Vaults are big but not this big.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Sensitive strings
// ---------------------------------------------------------------------------

/// A string that must never be logged. `Debug` is redacted and the buffer is
/// overwritten on drop. Kept dependency-free (no `zeroize`) so this crate only
/// needs serde + tokio; the wipe uses volatile writes so it is not optimised out.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sensitive(String);

impl Sensitive {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// Access the plaintext. Callers must not log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Sensitive {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Debug for Sensitive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sensitive(<redacted>)")
    }
}

impl Drop for Sensitive {
    fn drop(&mut self) {
        let v = std::mem::take(&mut self.0).into_bytes();
        wipe(v);
    }
}

/// Overwrite a byte vector (including spare capacity) before freeing it.
pub fn wipe(mut v: Vec<u8>) {
    let cap = v.capacity();
    v.resize(cap, 0);
    for b in v.iter_mut() {
        let p: *mut u8 = b;
        // SAFETY: `p` comes from a live `&mut u8`, so it is valid, aligned and exclusive.
        #[allow(unsafe_code)]
        unsafe {
            std::ptr::write_volatile(p, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Server endpoints. `identity_url`/`api_url` default to `{base}/identity` and `{base}/api`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub base_url: String,
    #[serde(default)]
    pub identity_url: Option<String>,
    #[serde(default)]
    pub api_url: Option<String>,
    /// Permit plain `http://` to hosts other than localhost.
    #[serde(default)]
    pub insecure_allow_http: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretField {
    Password,
    Notes,
    /// The raw TOTP seed / otpauth URI. Prefer `Request::GenerateTotp`.
    TotpSeed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Status,
    Login {
        server: ServerConfig,
        email: String,
        password: Sensitive,
        /// Authenticator-app code; send after a `TwoFactorRequired` reply.
        #[serde(default)]
        totp: Option<Sensitive>,
    },
    /// Unlock with the master password using the cached account.
    Unlock {
        password: Sensitive,
    },
    Lock,
    /// Forget the account entirely (cache + keychain entry).
    Logout,
    Sync,
    List,
    GetSecret {
        id: String,
        field: SecretField,
    },
    GenerateTotp {
        id: String,
    },
    /// Change the inactivity auto-lock timeout.
    SetAutoLock {
        seconds: u64,
    },
    /// Lock and terminate the agent.
    Shutdown,
}

impl Request {
    /// Whether this request counts as user activity for the auto-lock timer.
    /// Passive polling (`Ping`, `Status`) must not keep the vault open.
    pub fn is_activity(&self) -> bool {
        !matches!(self, Request::Ping | Request::Status)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockState {
    LoggedOut,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusInfo {
    pub state: LockState,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    /// Unix seconds of the last successful sync.
    #[serde(default)]
    pub last_sync: Option<i64>,
    pub auto_lock_seconds: u64,
    pub protocol_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Login,
    SecureNote,
}

/// Non-secret projection of a vault item, as returned by `List`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSummary {
    pub id: String,
    pub kind: ItemKind,
    pub name: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub uri_host: Option<String>,
    #[serde(default)]
    pub has_password: bool,
    #[serde(default)]
    pub has_totp: bool,
    #[serde(default)]
    pub has_notes: bool,
    #[serde(default)]
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// The vault is locked; unlock first.
    Locked,
    /// No account is configured; log in first.
    LoggedOut,
    /// Wrong master password (or wrong email).
    InvalidCredentials,
    /// Wrong or missing two-factor code.
    InvalidTwoFactor,
    NotFound,
    Network,
    /// Server rejected us in some other way.
    Server,
    /// Refused for policy reasons (e.g. plain http).
    Policy,
    BadRequest,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Pong {
        protocol_version: u32,
    },
    Ok,
    Status(StatusInfo),
    /// Login needs an authenticator code. `providers` are Bitwarden provider ids (0 = TOTP).
    TwoFactorRequired {
        providers: Vec<u32>,
    },
    Items {
        items: Vec<ItemSummary>,
    },
    Secret {
        value: Option<Sensitive>,
    },
    Totp {
        code: Sensitive,
        period: u64,
        remaining: u64,
    },
    Error {
        kind: ErrorKind,
        message: String,
    },
}

impl Response {
    pub fn error(kind: ErrorKind, message: impl Into<String>) -> Self {
        Response::Error {
            kind,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum IpcError {
    Io(std::io::Error),
    Json(serde_json::Error),
    FrameTooLarge(usize),
    /// The agent answered with something we did not expect for this request.
    Unexpected(String),
    /// The agent returned an error.
    Agent {
        kind: ErrorKind,
        message: String,
    },
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpcError::Io(e) => write!(f, "agent connection error: {e}"),
            IpcError::Json(e) => write!(f, "malformed IPC message: {e}"),
            IpcError::FrameTooLarge(n) => write!(f, "IPC frame too large ({n} bytes)"),
            IpcError::Unexpected(s) => write!(f, "unexpected agent response: {s}"),
            IpcError::Agent { message, .. } => f.write_str(message),
        }
    }
}

impl std::error::Error for IpcError {}

impl From<std::io::Error> for IpcError {
    fn from(e: std::io::Error) -> Self {
        IpcError::Io(e)
    }
}
impl From<serde_json::Error> for IpcError {
    fn from(e: serde_json::Error) -> Self {
        IpcError::Json(e)
    }
}

impl IpcError {
    pub fn kind(&self) -> Option<ErrorKind> {
        match self {
            IpcError::Agent { kind, .. } => Some(*kind),
            _ => None,
        }
    }
}

/// Write one length-prefixed JSON frame. The serialized buffer is wiped afterwards
/// because requests/responses may carry `Sensitive` values.
pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), IpcError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let buf = serde_json::to_vec(msg)?;
    if buf.len() > MAX_FRAME {
        let n = buf.len();
        wipe(buf);
        return Err(IpcError::FrameTooLarge(n));
    }
    let len = (buf.len() as u32).to_be_bytes();
    let res = async {
        w.write_all(&len).await?;
        w.write_all(&buf).await?;
        w.flush().await
    }
    .await;
    wipe(buf);
    res.map_err(IpcError::Io)
}

/// Read one frame. Returns `Ok(None)` on clean EOF before a frame starts.
pub async fn read_frame<R, T>(r: &mut R) -> Result<Option<T>, IpcError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(IpcError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    let parsed = serde_json::from_slice(&buf);
    wipe(buf);
    Ok(Some(parsed?))
}

// ---------------------------------------------------------------------------
// Socket location + client
// ---------------------------------------------------------------------------

/// `$XDG_RUNTIME_DIR/keyward/agent.sock`. `KEYWARD_SOCKET` overrides (tests, systemd).
pub fn default_socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("KEYWARD_SOCKET") {
        return PathBuf::from(p);
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("keyward-{}", uid_hint())));
    runtime.join("keyward").join("agent.sock")
}

fn uid_hint() -> String {
    std::env::var("USER").unwrap_or_else(|_| "user".into())
}

/// Async client for the agent. One request per connection keeps the agent
/// stateless with respect to connections and makes cancellation trivial.
#[derive(Debug, Clone)]
pub struct Client {
    socket: PathBuf,
}

impl Client {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    /// Send a request and return the raw response (including `Response::Error`).
    pub async fn call_raw(&self, req: &Request) -> Result<Response, IpcError> {
        let mut stream = UnixStream::connect(&self.socket).await?;
        write_frame(&mut stream, req).await?;
        match read_frame::<_, Response>(&mut stream).await? {
            Some(r) => Ok(r),
            None => Err(IpcError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "agent closed the connection",
            ))),
        }
    }

    /// Send a request; `Response::Error` becomes `IpcError::Agent`.
    pub async fn call(&self, req: &Request) -> Result<Response, IpcError> {
        match self.call_raw(req).await? {
            Response::Error { kind, message } => Err(IpcError::Agent { kind, message }),
            other => Ok(other),
        }
    }

    pub async fn ping(&self) -> Result<u32, IpcError> {
        match self.call(&Request::Ping).await? {
            Response::Pong { protocol_version } => Ok(protocol_version),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn status(&self) -> Result<StatusInfo, IpcError> {
        match self.call(&Request::Status).await? {
            Response::Status(s) => Ok(s),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn list(&self) -> Result<Vec<ItemSummary>, IpcError> {
        match self.call(&Request::List).await? {
            Response::Items { items } => Ok(items),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn get_secret(
        &self,
        id: &str,
        field: SecretField,
    ) -> Result<Option<Sensitive>, IpcError> {
        match self
            .call(&Request::GetSecret {
                id: id.to_owned(),
                field,
            })
            .await?
        {
            Response::Secret { value } => Ok(value),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn totp(&self, id: &str) -> Result<(Sensitive, u64), IpcError> {
        match self
            .call(&Request::GenerateTotp { id: id.to_owned() })
            .await?
        {
            Response::Totp {
                code, remaining, ..
            } => Ok((code, remaining)),
            other => Err(unexpected(&other)),
        }
    }

    /// Send a request that answers with `Response::Ok`.
    pub async fn simple(&self, req: &Request) -> Result<(), IpcError> {
        match self.call(req).await? {
            Response::Ok => Ok(()),
            other => Err(unexpected(&other)),
        }
    }
}

fn unexpected(r: &Response) -> IpcError {
    // Only the variant name: the payload may contain secrets.
    let name = match r {
        Response::Pong { .. } => "pong",
        Response::Ok => "ok",
        Response::Status(_) => "status",
        Response::TwoFactorRequired { .. } => "two_factor_required",
        Response::Items { .. } => "items",
        Response::Secret { .. } => "secret",
        Response::Totp { .. } => "totp",
        Response::Error { .. } => "error",
    };
    IpcError::Unexpected(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_debug_is_redacted() {
        let s = Sensitive::new("hunter2");
        assert!(!format!("{s:?}").contains("hunter2"));
        let req = Request::Unlock { password: s };
        assert!(!format!("{req:?}").contains("hunter2"));
    }

    #[test]
    fn request_json_shape() {
        let j = serde_json::to_value(Request::GetSecret {
            id: "x".into(),
            field: SecretField::Password,
        })
        .unwrap();
        assert_eq!(j["type"], "get_secret");
        assert_eq!(j["field"], "password");
    }

    #[tokio::test]
    async fn frame_roundtrip_and_limits() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, &Request::Ping).await.unwrap();
        let got: Request = read_frame(&mut b).await.unwrap().unwrap();
        assert!(matches!(got, Request::Ping));

        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(MAX_FRAME as u32 + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(matches!(
            read_frame::<_, Request>(&mut b).await,
            Err(IpcError::FrameTooLarge(_))
        ));

        drop(a);
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(read_frame::<_, Request>(&mut b).await.unwrap().is_none());
    }

    #[test]
    fn activity_classification() {
        assert!(!Request::Status.is_activity());
        assert!(!Request::Ping.is_activity());
        assert!(Request::List.is_activity());
    }
}
