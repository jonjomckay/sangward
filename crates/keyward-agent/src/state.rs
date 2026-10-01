//! Agent state machine: LoggedOut -> Locked <-> Unlocked.
//!
//! While unlocked we hold the user/org keys (zeroized on drop) and the parsed
//! sync data whose secret fields remain EncStrings. Nothing here is logged
//! beyond ids, counts and error kinds.

use std::sync::Arc;
use std::time::{Duration, Instant};

use keyward_core::api::{self, ApiClient, ApiError, Endpoints, PasswordLogin};
use keyward_core::cache::{Account, CACHE_VERSION, Cache, CacheFile};
use keyward_core::crypto::MasterKey;
use keyward_core::models::SyncResponse;
use keyward_core::vault::{self, Field, Keys};
use keyward_ipc::{
    ErrorKind, ItemKind, ItemSummary, LockState, PROTOCOL_VERSION, Request, Response, SecretField,
    Sensitive, StatusInfo,
};
use keyward_platform::{SecretStore, StoredCredentials};
use secrecy::{ExposeSecret, SecretString};

pub struct Unlocked {
    keys: Keys,
    sync: Option<SyncResponse>,
    access_token: Option<SecretString>,
    access_expires_at: i64,
}

pub struct Agent {
    cache: Cache,
    secrets: Arc<dyn SecretStore>,
    pub auto_lock: Duration,
    pub last_activity: Instant,
    account: Option<CacheFile>,
    unlocked: Option<Unlocked>,
    pub shutdown_requested: bool,
}

type Res = Result<Response, (ErrorKind, String)>;

fn err<T>(kind: ErrorKind, msg: impl Into<String>) -> Result<T, (ErrorKind, String)> {
    Err((kind, msg.into()))
}

fn api_err(e: ApiError) -> (ErrorKind, String) {
    let kind = match &e {
        ApiError::InsecureUrl(_) => ErrorKind::Policy,
        ApiError::BadUrl(_) => ErrorKind::BadRequest,
        ApiError::Network(_) => ErrorKind::Network,
        ApiError::InvalidCredentials => ErrorKind::InvalidCredentials,
        ApiError::InvalidTwoFactor | ApiError::TwoFactorRequired { .. } => {
            ErrorKind::InvalidTwoFactor
        }
        ApiError::InvalidRefreshToken => ErrorKind::LoggedOut,
        ApiError::Server { .. } | ApiError::Decode(_) => ErrorKind::Server,
    };
    (kind, e.to_string())
}

fn ipc_field(f: SecretField) -> Field {
    match f {
        SecretField::Password => Field::Password,
        SecretField::Notes => Field::Notes,
        SecretField::TotpSeed => Field::TotpSeed,
    }
}

impl Agent {
    pub fn new(cache: Cache, secrets: Arc<dyn SecretStore>, auto_lock: Duration) -> Self {
        let account = match cache.load() {
            Ok(a) => a.filter(|a| a.version == CACHE_VERSION),
            Err(e) => {
                tracing::warn!(error = %e, "ignoring unreadable cache");
                None
            }
        };
        Self {
            cache,
            secrets,
            auto_lock,
            last_activity: Instant::now(),
            account,
            unlocked: None,
            shutdown_requested: false,
        }
    }

    pub fn state(&self) -> LockState {
        match (&self.account, &self.unlocked) {
            (None, _) => LockState::LoggedOut,
            (Some(_), None) => LockState::Locked,
            (Some(_), Some(_)) => LockState::Unlocked,
        }
    }

    /// Drop all key material. `Keys`/`SymmetricKey` zeroize on drop.
    pub fn lock(&mut self) {
        if self.unlocked.take().is_some() {
            tracing::info!("vault locked");
        }
    }

    /// Called periodically; locks if idle past the timeout.
    pub fn tick(&mut self) {
        if self.unlocked.is_some() && self.last_activity.elapsed() >= self.auto_lock {
            tracing::info!(
                timeout_secs = self.auto_lock.as_secs(),
                "auto-locking after inactivity"
            );
            self.lock();
        }
    }

    pub async fn handle(&mut self, req: Request) -> Response {
        if req.is_activity() {
            self.last_activity = Instant::now();
        }
        let name = request_name(&req);
        let res = self.dispatch(req).await;
        match res {
            Ok(r) => r,
            Err((kind, message)) => {
                tracing::info!(request = name, ?kind, "request failed");
                Response::Error { kind, message }
            }
        }
    }

    async fn dispatch(&mut self, req: Request) -> Res {
        match req {
            Request::Ping => Ok(Response::Pong {
                protocol_version: PROTOCOL_VERSION,
            }),
            Request::Status => Ok(Response::Status(self.status())),
            Request::Login {
                server,
                email,
                password,
                totp,
            } => self.login(server, email, password, totp).await,
            Request::Unlock { password } => self.unlock(password).await,
            Request::Lock => {
                self.lock();
                Ok(Response::Ok)
            }
            Request::Logout => self.logout().await,
            Request::Sync => self.sync().await,
            Request::List => self.list(),
            Request::GetSecret { id, field } => {
                let (u, sync) = self.unlocked_sync()?;
                let v = vault::secret(&u.keys, sync, &id, ipc_field(field)).map_err(vault_err)?;
                tracing::debug!(%id, ?field, "secret requested");
                Ok(Response::Secret {
                    value: v.map(|z| Sensitive::new(z.as_str())),
                })
            }
            Request::GenerateTotp { id } => {
                let (u, sync) = self.unlocked_sync()?;
                let t =
                    vault::totp(&u.keys, sync, &id, api::now_unix() as u64).map_err(vault_err)?;
                Ok(Response::Totp {
                    code: Sensitive::new(t.code.as_str()),
                    period: t.period,
                    remaining: t.remaining,
                })
            }
            Request::SetAutoLock { seconds } => {
                if seconds == 0 {
                    return err(ErrorKind::BadRequest, "auto-lock timeout must be > 0");
                }
                self.auto_lock = Duration::from_secs(seconds);
                Ok(Response::Ok)
            }
            Request::Shutdown => {
                self.lock();
                self.shutdown_requested = true;
                Ok(Response::Ok)
            }
        }
    }

    fn status(&self) -> StatusInfo {
        StatusInfo {
            state: self.state(),
            email: self.account.as_ref().map(|a| a.account.email.clone()),
            server: self
                .account
                .as_ref()
                .map(|a| a.account.endpoints.base.clone()),
            last_sync: self.account.as_ref().and_then(|a| a.last_sync),
            auto_lock_seconds: self.auto_lock.as_secs(),
            protocol_version: PROTOCOL_VERSION,
        }
    }

    fn unlocked_sync(&self) -> Result<(&Unlocked, &SyncResponse), (ErrorKind, String)> {
        let u = self.require_unlocked()?;
        match &u.sync {
            Some(s) => Ok((u, s)),
            None => err(ErrorKind::NotFound, "vault not synced yet"),
        }
    }

    fn require_unlocked(&self) -> Result<&Unlocked, (ErrorKind, String)> {
        match (self.account.is_some(), &self.unlocked) {
            (false, _) => err(ErrorKind::LoggedOut, "not logged in"),
            (true, None) => err(ErrorKind::Locked, "vault is locked"),
            (true, Some(u)) => Ok(u),
        }
    }

    fn list(&self) -> Res {
        let (u, sync) = self.unlocked_sync()?;
        let items = vault::summaries(&u.keys, sync)
            .into_iter()
            .map(|s| ItemSummary {
                id: s.id,
                kind: match s.kind {
                    vault::Kind::Login => ItemKind::Login,
                    vault::Kind::SecureNote => ItemKind::SecureNote,
                },
                name: s.name,
                username: s.username,
                uri_host: s.uri_host,
                has_password: s.has_password,
                has_totp: s.has_totp,
                has_notes: s.has_notes,
                organization_id: s.organization_id,
            })
            .collect();
        Ok(Response::Items { items })
    }

    async fn login(
        &mut self,
        server: keyward_ipc::ServerConfig,
        email: String,
        password: Sensitive,
        totp: Option<Sensitive>,
    ) -> Res {
        let endpoints = Endpoints::resolve(
            &server.base_url,
            server.identity_url.as_deref(),
            server.api_url.as_deref(),
            server.insecure_allow_http,
        )
        .map_err(api_err)?;
        let email = keyward_core::crypto::normalize_email(&email);
        if email.is_empty() || password.is_empty() {
            return err(ErrorKind::BadRequest, "email and password are required");
        }
        let api = ApiClient::new(endpoints.clone()).map_err(api_err)?;
        let kdf = api.prelogin(&email).await.map_err(api_err)?;
        let master = MasterKey::derive(password.expose().as_bytes(), &email, &kdf)
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
        let hash = zeroize::Zeroizing::new(master.password_hash(password.expose().as_bytes()));

        // Reuse a persistent device identifier so the server doesn't see a new device each login.
        let existing = self
            .secrets
            .load(&endpoints.base, &email)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "keychain read failed");
                None
            });
        let device_id = existing
            .as_ref()
            .map(|c| c.device_id.clone())
            .unwrap_or_else(uuid_v4);

        let tokens = match api
            .login_password(&PasswordLogin {
                email: &email,
                password_hash: &hash,
                device_id: &device_id,
                totp: totp.as_ref().map(|t| t.expose()),
            })
            .await
        {
            Ok(t) => t,
            Err(ApiError::TwoFactorRequired { providers }) => {
                if !providers.contains(&0) {
                    return err(
                        ErrorKind::Server,
                        "account requires a two-factor method keyward does not support (only authenticator apps)",
                    );
                }
                return Ok(Response::TwoFactorRequired { providers });
            }
            Err(e) => return Err(api_err(e)),
        };

        let protected_key = tokens.key.clone().ok_or((
            ErrorKind::Server,
            "server did not return the account key".to_owned(),
        ))?;
        // Verify we can actually decrypt before persisting anything.
        let keys = Keys::unlock(&master, &protected_key, None, None).map_err(|_| {
            (
                ErrorKind::InvalidCredentials,
                "could not decrypt account key".to_owned(),
            )
        })?;
        // SecretBox zeroizes on drop; don't keep the master key or password past this point.
        drop(master);
        drop(hash);
        drop(password);

        if let Err(e) = self
            .secrets
            .store(
                &endpoints.base,
                &email,
                &StoredCredentials {
                    device_id,
                    refresh_token: tokens.refresh_token.clone(),
                },
            )
            .await
        {
            tracing::warn!(error = %e, "could not store refresh token in keychain; unlock after restart will need a full login");
        }

        // Replace any previous account.
        self.lock();
        let file = CacheFile {
            version: CACHE_VERSION,
            account: Account {
                endpoints,
                email,
                kdf: tokens.kdf.unwrap_or(kdf),
                protected_key,
                private_key: tokens.private_key.clone(),
            },
            sync: None,
            last_sync: None,
        };
        self.cache
            .store(&file)
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
        self.account = Some(file);
        self.unlocked = Some(Unlocked {
            keys,
            sync: None,
            access_token: Some(tokens.access_token),
            access_expires_at: tokens.expires_at,
        });
        tracing::info!("logged in");
        self.sync().await
    }

    async fn unlock(&mut self, password: Sensitive) -> Res {
        let Some(file) = &self.account else {
            return err(ErrorKind::LoggedOut, "not logged in");
        };
        if self.unlocked.is_some() {
            return Ok(Response::Ok);
        }
        let acct = &file.account;
        let master = MasterKey::derive(password.expose().as_bytes(), &acct.email, &acct.kdf)
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
        let sync = match &file.sync {
            Some(raw) => SyncResponse::from_json(raw.clone()).ok(),
            None => None,
        };
        // A wrong password fails the MAC on the protected user key.
        let keys = Keys::unlock(
            &master,
            &acct.protected_key,
            acct.private_key.as_deref(),
            sync.as_ref(),
        )
        .map_err(|_| {
            (
                ErrorKind::InvalidCredentials,
                "invalid master password".to_owned(),
            )
        })?;
        // The master key is only needed to unwrap the user key; zeroize it now.
        drop(master);
        drop(password);
        self.unlocked = Some(Unlocked {
            keys,
            sync,
            access_token: None,
            access_expires_at: 0,
        });
        tracing::info!("vault unlocked");

        // Refresh the session silently so a later sync works; failure is not fatal for unlock.
        if let Err((kind, msg)) = self.ensure_access_token().await {
            tracing::info!(?kind, "token refresh after unlock failed: {msg}");
        }
        Ok(Response::Ok)
    }

    async fn ensure_access_token(&mut self) -> Result<String, (ErrorKind, String)> {
        let file = self
            .account
            .as_ref()
            .ok_or((ErrorKind::LoggedOut, "not logged in".to_owned()))?;
        let u = self
            .unlocked
            .as_ref()
            .ok_or((ErrorKind::Locked, "vault is locked".to_owned()))?;
        if let Some(t) = &u.access_token
            && u.access_expires_at - 60 > api::now_unix()
        {
            return Ok(t.expose_secret().to_owned());
        }
        let endpoints = file.account.endpoints.clone();
        let email = file.account.email.clone();
        let creds = self
            .secrets
            .load(&endpoints.base, &email)
            .await
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?
            .ok_or((
                ErrorKind::LoggedOut,
                "no stored session; log in again".to_owned(),
            ))?;
        let rt = creds.refresh_token.as_ref().ok_or((
            ErrorKind::LoggedOut,
            "no stored session; log in again".to_owned(),
        ))?;
        let api = ApiClient::new(endpoints.clone()).map_err(api_err)?;
        let tokens = api.refresh(rt.expose_secret()).await.map_err(api_err)?;
        tracing::debug!("access token refreshed");
        if let Some(new_rt) = tokens.refresh_token.clone()
            && new_rt.expose_secret() != rt.expose_secret()
        {
            let updated = StoredCredentials {
                device_id: creds.device_id.clone(),
                refresh_token: Some(new_rt),
            };
            if let Err(e) = self.secrets.store(&endpoints.base, &email, &updated).await {
                tracing::warn!(error = %e, "could not update refresh token in keychain");
            }
        }
        let access = tokens.access_token.expose_secret().to_owned();
        if let Some(u) = self.unlocked.as_mut() {
            u.access_token = Some(tokens.access_token);
            u.access_expires_at = tokens.expires_at;
        }
        Ok(access)
    }

    async fn sync(&mut self) -> Res {
        self.require_unlocked()?;
        let access = zeroize::Zeroizing::new(self.ensure_access_token().await?);
        let file = self.account.as_mut().expect("checked");
        let api = ApiClient::new(file.account.endpoints.clone()).map_err(api_err)?;
        let (parsed, raw) = api.sync(&access).await.map_err(api_err)?;

        let u = self.unlocked.as_mut().expect("checked");
        // Keys may have been rotated server-side; keep cache in step with what we can decrypt.
        if let Some(pk) = parsed.profile.private_key.clone() {
            file.account.private_key = Some(pk);
        }
        if let Some(pk) = file.account.private_key.as_deref() {
            u.keys
                .load_org_keys(pk, &parsed)
                .map_err(|e| (ErrorKind::Internal, format!("organization keys: {e}")))?;
        }
        file.sync = Some(raw);
        file.last_sync = Some(api::now_unix());
        self.cache
            .store(file)
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
        tracing::info!(
            ciphers = parsed.ciphers.len(),
            orgs = u.keys.orgs.len(),
            "sync complete"
        );
        u.sync = Some(parsed);
        Ok(Response::Ok)
    }

    async fn logout(&mut self) -> Res {
        self.lock();
        if let Some(file) = self.account.take() {
            let a = &file.account;
            if let Err(e) = self.secrets.delete(&a.endpoints.base, &a.email).await {
                tracing::warn!(error = %e, "could not delete keychain entry");
            }
        }
        self.cache
            .clear()
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
        tracing::info!("logged out");
        Ok(Response::Ok)
    }
}

fn vault_err(e: vault::VaultError) -> (ErrorKind, String) {
    let kind = match e {
        vault::VaultError::NotFound | vault::VaultError::NoTotp => ErrorKind::NotFound,
        _ => ErrorKind::Internal,
    };
    (kind, e.to_string())
}

fn request_name(r: &Request) -> &'static str {
    match r {
        Request::Ping => "ping",
        Request::Status => "status",
        Request::Login { .. } => "login",
        Request::Unlock { .. } => "unlock",
        Request::Lock => "lock",
        Request::Logout => "logout",
        Request::Sync => "sync",
        Request::List => "list",
        Request::GetSecret { .. } => "get_secret",
        Request::GenerateTotp { .. } => "generate_totp",
        Request::SetAutoLock { .. } => "set_auto_lock",
        Request::Shutdown => "shutdown",
    }
}

/// Persistent device identifier sent to the server (random v4 UUID).
fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyward_platform::InMemorySecretStore;

    fn agent(dir: &std::path::Path) -> Agent {
        Agent::new(
            Cache::new(dir),
            Arc::new(InMemorySecretStore::new()),
            Duration::from_secs(900),
        )
    }

    #[tokio::test]
    async fn logged_out_errors_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let mut a = agent(tmp.path());
        assert_eq!(a.state(), LockState::LoggedOut);
        match a.handle(Request::List).await {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::LoggedOut),
            other => panic!("{other:?}"),
        }
        match a
            .handle(Request::Unlock {
                password: Sensitive::new("x"),
            })
            .await
        {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::LoggedOut),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn plain_http_is_refused_for_remote_hosts() {
        let tmp = tempfile::tempdir().unwrap();
        let mut a = agent(tmp.path());
        let server = keyward_ipc::ServerConfig {
            base_url: "http://vault.example.com".into(),
            identity_url: None,
            api_url: None,
            insecure_allow_http: false,
        };
        match a
            .handle(Request::Login {
                server,
                email: "a@b".into(),
                password: Sensitive::new("p"),
                totp: None,
            })
            .await
        {
            Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::Policy),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn uuid_shape() {
        let u = uuid_v4();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
    }
}
