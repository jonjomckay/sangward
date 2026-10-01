//! HTTP client for Bitwarden-compatible servers (Vaultwarden / official self-hosted).

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::StatusCode;
use serde_json::Value;
use url::Url;

use crate::crypto::{Kdf, normalize_email};
use crate::models::{PreloginResponse, SyncResponse, TokenError, TokenResponse, normalize_keys};

/// Identifies us to the server. Bitwarden servers gate some behaviour on these.
pub const CLIENT_NAME: &str = "desktop";
pub const CLIENT_VERSION: &str = "2025.6.0";
/// Bitwarden device type 8 = "Linux Desktop".
pub const DEVICE_TYPE: u32 = 8;
pub const DEVICE_NAME: &str = "sangward";

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("refusing insecure URL {0}: use https, or pass --insecure-allow-http")]
    InsecureUrl(String),
    #[error("invalid server URL: {0}")]
    BadUrl(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid email or master password")]
    InvalidCredentials,
    #[error("two-factor authentication required")]
    TwoFactorRequired { providers: Vec<u32> },
    #[error("invalid two-factor code")]
    InvalidTwoFactor,
    #[error("session expired; log in again")]
    InvalidRefreshToken,
    #[error("server error ({status}): {message}")]
    Server { status: u16, message: String },
    #[error("unexpected server response: {0}")]
    Decode(String),
}

impl From<reqwest::Error> for ApiError {
    fn from(e: reqwest::Error) -> Self {
        // `without_url` keeps query strings (none carry secrets, but be tidy) out of messages.
        ApiError::Network(e.without_url().to_string())
    }
}

/// Resolved server endpoints.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Endpoints {
    pub base: String,
    pub identity: String,
    pub api: String,
    #[serde(default)]
    pub insecure_allow_http: bool,
}

impl Endpoints {
    /// Derive `/identity` and `/api` from `base`, applying overrides and the http policy.
    pub fn resolve(
        base: &str,
        identity: Option<&str>,
        api: Option<&str>,
        insecure_allow_http: bool,
    ) -> Result<Self, ApiError> {
        let base = base.trim().trim_end_matches('/').to_owned();
        check_url(&base, insecure_allow_http)?;
        let identity = match identity {
            Some(i) if !i.trim().is_empty() => i.trim().trim_end_matches('/').to_owned(),
            _ => format!("{base}/identity"),
        };
        let api = match api {
            Some(a) if !a.trim().is_empty() => a.trim().trim_end_matches('/').to_owned(),
            _ => format!("{base}/api"),
        };
        check_url(&identity, insecure_allow_http)?;
        check_url(&api, insecure_allow_http)?;
        Ok(Self {
            base,
            identity,
            api,
            insecure_allow_http,
        })
    }
}

/// https always; http only for loopback unless explicitly allowed.
pub fn check_url(raw: &str, insecure_allow_http: bool) -> Result<(), ApiError> {
    let u = Url::parse(raw).map_err(|e| ApiError::BadUrl(format!("{raw}: {e}")))?;
    match u.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = matches!(
                u.host(),
                Some(url::Host::Domain("localhost"))
                    | Some(url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST))
                    | Some(url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST))
            );
            if loopback || insecure_allow_http {
                Ok(())
            } else {
                Err(ApiError::InsecureUrl(raw.to_owned()))
            }
        }
        other => Err(ApiError::BadUrl(format!("unsupported scheme {other}"))),
    }
}

/// Tokens obtained from `/connect/token`.
pub struct Tokens {
    pub access_token: secrecy::SecretString,
    pub refresh_token: Option<secrecy::SecretString>,
    /// Unix seconds when the access token expires.
    pub expires_at: i64,
    pub key: Option<String>,
    pub private_key: Option<String>,
    pub kdf: Option<Kdf>,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tokens")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct PasswordLogin<'a> {
    pub email: &'a str,
    /// Base64 master password hash (never the password itself).
    pub password_hash: &'a str,
    pub device_id: &'a str,
    pub totp: Option<&'a str>,
}

#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    pub endpoints: Endpoints,
}

impl ApiClient {
    pub fn new(endpoints: Endpoints) -> Result<Self, ApiError> {
        use reqwest::header::{HeaderMap, HeaderValue};
        let mut headers = HeaderMap::new();
        headers.insert(
            "Bitwarden-Client-Name",
            HeaderValue::from_static(CLIENT_NAME),
        );
        headers.insert(
            "Bitwarden-Client-Version",
            HeaderValue::from_static(CLIENT_VERSION),
        );
        headers.insert("Device-Type", HeaderValue::from_static("8"));
        // reqwest's `rustls` feature uses rustls-platform-verifier, i.e. the system trust store.
        let http = reqwest::Client::builder()
            .user_agent(concat!("sangward/", env!("CARGO_PKG_VERSION")))
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .https_only(false) // enforced by `check_url` so loopback http works
            .build()
            .map_err(|e| ApiError::Network(e.to_string()))?;
        Ok(Self { http, endpoints })
    }

    /// `POST {identity}/accounts/prelogin`, falling back to `{api}/accounts/prelogin`.
    pub async fn prelogin(&self, email: &str) -> Result<Kdf, ApiError> {
        let body = serde_json::json!({ "email": normalize_email(email) });
        let mut last_err = None;
        for base in [&self.endpoints.identity, &self.endpoints.api] {
            let url = format!("{base}/accounts/prelogin");
            match self.http.post(&url).json(&body).send().await {
                Ok(r) if r.status().is_success() => {
                    let v: Value = r
                        .json()
                        .await
                        .map_err(|e| ApiError::Decode(e.to_string()))?;
                    let p: PreloginResponse = serde_json::from_value(normalize_keys(v))
                        .map_err(|e| ApiError::Decode(e.to_string()))?;
                    return Kdf::from_server(
                        p.kdf,
                        p.kdf_iterations,
                        p.kdf_memory,
                        p.kdf_parallelism,
                    )
                    .map_err(|e| ApiError::Decode(e.to_string()));
                }
                Ok(r) => {
                    tracing::debug!(status = %r.status(), %url, "prelogin endpoint failed, trying fallback");
                    last_err = Some(ApiError::Server {
                        status: r.status().as_u16(),
                        message: "prelogin failed".into(),
                    });
                }
                Err(e) => last_err = Some(e.into()),
            }
        }
        Err(last_err.unwrap_or_else(|| ApiError::Decode("prelogin".into())))
    }

    /// Password grant. On `TwoFactorRequired`, call again with `totp` set.
    pub async fn login_password(&self, req: &PasswordLogin<'_>) -> Result<Tokens, ApiError> {
        let email = normalize_email(req.email);
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "password".into()),
            ("scope", "api offline_access".into()),
            ("client_id", "desktop".into()),
            ("username", email.clone()),
            ("password", req.password_hash.to_owned()),
            ("deviceType", DEVICE_TYPE.to_string()),
            ("deviceIdentifier", req.device_id.to_owned()),
            ("deviceName", DEVICE_NAME.into()),
        ];
        if let Some(code) = req.totp {
            form.push(("twoFactorToken", code.trim().to_owned()));
            form.push(("twoFactorProvider", "0".into()));
            form.push(("twoFactorRemember", "0".into()));
        }
        let resp = self
            .http
            .post(format!("{}/connect/token", self.endpoints.identity))
            .header("Auth-Email", URL_SAFE_NO_PAD.encode(email.as_bytes()))
            .form(&form)
            .send()
            .await;
        // Scrub the form (it contains the password hash) regardless of outcome.
        for (_, v) in form.iter_mut() {
            zeroize::Zeroize::zeroize(v);
        }
        self.token_response(resp?, req.totp.is_some()).await
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<Tokens, ApiError> {
        let form = [
            ("grant_type", "refresh_token"),
            ("client_id", "desktop"),
            ("refresh_token", refresh_token),
        ];
        let resp = self
            .http
            .post(format!("{}/connect/token", self.endpoints.identity))
            .form(&form)
            .send()
            .await?;
        match self.token_response(resp, false).await {
            Err(ApiError::InvalidCredentials) => Err(ApiError::InvalidRefreshToken),
            other => other,
        }
    }

    async fn token_response(
        &self,
        resp: reqwest::Response,
        sent_2fa: bool,
    ) -> Result<Tokens, ApiError> {
        let status = resp.status();
        let text = resp.text().await?;
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let v = normalize_keys(v);
        if status.is_success() {
            let t: TokenResponse =
                serde_json::from_value(v).map_err(|e| ApiError::Decode(e.to_string()))?;
            let kdf = match (t.kdf, t.kdf_iterations) {
                (Some(k), Some(i)) => Kdf::from_server(k, i, t.kdf_memory, t.kdf_parallelism).ok(),
                _ => None,
            };
            return Ok(Tokens {
                access_token: t.access_token.into(),
                refresh_token: t.refresh_token.map(Into::into),
                expires_at: now_unix() + t.expires_in.unwrap_or(3600),
                key: t.key,
                private_key: t.private_key,
                kdf,
            });
        }
        let err: TokenError = serde_json::from_value(v).unwrap_or_default();
        if let Some(providers) = err.two_factor_providers.as_ref().filter(|p| !p.is_empty()) {
            if sent_2fa {
                return Err(ApiError::InvalidTwoFactor);
            }
            let providers = providers
                .iter()
                .filter_map(|p| {
                    p.as_u64()
                        .or_else(|| p.as_str().and_then(|s| s.parse().ok()))
                })
                .map(|p| p as u32)
                .collect();
            return Err(ApiError::TwoFactorRequired { providers });
        }
        let message = err
            .error_model
            .and_then(|m| m.message)
            .or(err.error_description)
            .or(err.error)
            .unwrap_or_else(|| status.to_string());
        if status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED {
            let lower = message.to_lowercase();
            if sent_2fa
                && (lower.contains("two") || lower.contains("totp") || lower.contains("2fa"))
            {
                return Err(ApiError::InvalidTwoFactor);
            }
            if lower.contains("username or password")
                || lower.contains("invalid_grant")
                || lower.contains("incorrect")
            {
                return Err(ApiError::InvalidCredentials);
            }
        }
        Err(ApiError::Server {
            status: status.as_u16(),
            message,
        })
    }

    /// `GET {api}/sync`. Returns the parsed response plus the raw JSON for the cache.
    pub async fn sync(&self, access_token: &str) -> Result<(SyncResponse, Value), ApiError> {
        let resp = self
            .http
            .get(format!("{}/sync?excludeDomains=true", self.endpoints.api))
            .bearer_auth(access_token)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(ApiError::Server {
                status: status.as_u16(),
                message: "sync failed".into(),
            });
        }
        let raw: Value = resp
            .json()
            .await
            .map_err(|e| ApiError::Decode(e.to_string()))?;
        let parsed =
            SyncResponse::from_json(raw.clone()).map_err(|e| ApiError::Decode(e.to_string()))?;
        Ok((parsed, raw))
    }

    /// Authenticated JSON POST to the API (used by test-support helpers).
    pub async fn post_api(
        &self,
        access_token: &str,
        path: &str,
        body: &Value,
    ) -> Result<Value, ApiError> {
        let resp = self
            .http
            .post(format!("{}{}", self.endpoints.api, path))
            .bearer_auth(access_token)
            .json(body)
            .send()
            .await?;
        json_or_error(resp).await
    }

    /// Unauthenticated JSON POST to the identity server (registration).
    pub async fn post_identity(&self, path: &str, body: &Value) -> Result<Value, ApiError> {
        let resp = self
            .http
            .post(format!("{}{}", self.endpoints.identity, path))
            .json(body)
            .send()
            .await?;
        json_or_error(resp).await
    }
}

async fn json_or_error(resp: reqwest::Response) -> Result<Value, ApiError> {
    let status = resp.status();
    let text = resp.text().await?;
    if status.is_success() {
        return Ok(serde_json::from_str(&text).unwrap_or(Value::Null));
    }
    let message = serde_json::from_str::<Value>(&text)
        .ok()
        .map(normalize_keys)
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(str::to_owned))
        .unwrap_or_else(|| status.to_string());
    Err(ApiError::Server {
        status: status.as_u16(),
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_derived_and_overridden() {
        let e = Endpoints::resolve("https://vault.example.com/", None, None, false).unwrap();
        assert_eq!(e.identity, "https://vault.example.com/identity");
        assert_eq!(e.api, "https://vault.example.com/api");
        let e = Endpoints::resolve("https://x.test", Some("https://id.x.test"), Some(""), false)
            .unwrap();
        assert_eq!(e.identity, "https://id.x.test");
        assert_eq!(e.api, "https://x.test/api");
    }

    #[test]
    fn http_policy() {
        assert!(check_url("http://localhost:8087", false).is_ok());
        assert!(check_url("http://127.0.0.1:8087", false).is_ok());
        assert!(check_url("http://[::1]:8087", false).is_ok());
        assert!(matches!(
            check_url("http://vault.example.com", false),
            Err(ApiError::InsecureUrl(_))
        ));
        assert!(check_url("http://vault.example.com", true).is_ok());
        assert!(check_url("ftp://x", true).is_err());
        assert!(check_url("not a url", true).is_err());
        // Overrides are checked too.
        assert!(
            Endpoints::resolve("https://x.test", Some("http://evil.test"), None, false).is_err()
        );
    }
}
