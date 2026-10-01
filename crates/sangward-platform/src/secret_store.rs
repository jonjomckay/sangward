//! OS keychain access. Stores **only** the refresh token and device identifier.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    #[error("keychain unavailable: {0}")]
    Unavailable(String),
    #[error("keychain error: {0}")]
    Backend(String),
    #[error("stored credentials are corrupt")]
    Corrupt,
}

/// What we persist per (server, email).
pub struct StoredCredentials {
    pub device_id: String,
    pub refresh_token: Option<SecretString>,
}

impl std::fmt::Debug for StoredCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredCredentials")
            .field("device_id", &self.device_id)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Serialized form inside the keychain entry.
#[derive(Serialize, Deserialize)]
struct Blob {
    device_id: String,
    refresh_token: Option<String>,
}

impl StoredCredentials {
    fn to_blob(&self) -> zeroize::Zeroizing<String> {
        let blob = Blob {
            device_id: self.device_id.clone(),
            refresh_token: self
                .refresh_token
                .as_ref()
                .map(|t| t.expose_secret().to_owned()),
        };
        let s = serde_json::to_string(&blob).expect("serializable");
        if let Some(mut t) = blob.refresh_token {
            zeroize::Zeroize::zeroize(&mut t);
        }
        zeroize::Zeroizing::new(s)
    }

    fn from_blob(bytes: &[u8]) -> Result<Self, SecretStoreError> {
        let mut blob: Blob =
            serde_json::from_slice(bytes).map_err(|_| SecretStoreError::Corrupt)?;
        let rt = blob.refresh_token.take().map(SecretString::from);
        Ok(Self {
            device_id: std::mem::take(&mut blob.device_id),
            refresh_token: rt,
        })
    }
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Keychain abstraction. Keyed by server URL + (normalised) email.
pub trait SecretStore: Send + Sync {
    fn load<'a>(
        &'a self,
        server: &'a str,
        email: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredCredentials>, SecretStoreError>>;
    fn store<'a>(
        &'a self,
        server: &'a str,
        email: &'a str,
        creds: &'a StoredCredentials,
    ) -> BoxFuture<'a, Result<(), SecretStoreError>>;
    fn delete<'a>(
        &'a self,
        server: &'a str,
        email: &'a str,
    ) -> BoxFuture<'a, Result<(), SecretStoreError>>;
}

fn key(server: &str, email: &str) -> (String, String) {
    (
        server.trim_end_matches('/').to_owned(),
        email.trim().to_lowercase(),
    )
}

/// In-process store for tests and the e2e harness. Contents die with the process.
#[derive(Default)]
pub struct InMemorySecretStore {
    items: Mutex<HashMap<(String, String), zeroize::Zeroizing<String>>>,
}

impl InMemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for InMemorySecretStore {
    fn load<'a>(
        &'a self,
        server: &'a str,
        email: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredCredentials>, SecretStoreError>> {
        Box::pin(async move {
            let items = self.items.lock().expect("poisoned");
            items
                .get(&key(server, email))
                .map(|b| StoredCredentials::from_blob(b.as_bytes()))
                .transpose()
        })
    }

    fn store<'a>(
        &'a self,
        server: &'a str,
        email: &'a str,
        creds: &'a StoredCredentials,
    ) -> BoxFuture<'a, Result<(), SecretStoreError>> {
        Box::pin(async move {
            self.items
                .lock()
                .expect("poisoned")
                .insert(key(server, email), creds.to_blob());
            Ok(())
        })
    }

    fn delete<'a>(
        &'a self,
        server: &'a str,
        email: &'a str,
    ) -> BoxFuture<'a, Result<(), SecretStoreError>> {
        Box::pin(async move {
            self.items
                .lock()
                .expect("poisoned")
                .remove(&key(server, email));
            Ok(())
        })
    }
}

/// Secret Service (GNOME Keyring, KWallet via its SS bridge, KeePassXC) through `oo7`.
/// The connection is opened lazily so the agent starts even without a session bus.
#[cfg(target_os = "linux")]
pub struct Oo7SecretStore {
    keyring: tokio::sync::OnceCell<oo7::Keyring>,
}

#[cfg(target_os = "linux")]
impl Default for Oo7SecretStore {
    fn default() -> Self {
        Self {
            keyring: tokio::sync::OnceCell::new(),
        }
    }
}

#[cfg(target_os = "linux")]
impl Oo7SecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    async fn keyring(&self) -> Result<&oo7::Keyring, SecretStoreError> {
        self.keyring
            .get_or_try_init(|| async {
                let kr = oo7::Keyring::new()
                    .await
                    .map_err(|e| SecretStoreError::Unavailable(e.to_string()))?;
                // Unlock may prompt the user; errors surface on the actual read/write.
                let _ = kr.unlock().await;
                Ok(kr)
            })
            .await
    }

    fn attributes<'a>(server: &'a str, email: &'a str) -> HashMap<&'static str, &'a str> {
        HashMap::from([
            ("application", "sangward"),
            ("server", server),
            ("email", email),
        ])
    }
}

#[cfg(target_os = "linux")]
impl SecretStore for Oo7SecretStore {
    fn load<'a>(
        &'a self,
        server: &'a str,
        email: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredCredentials>, SecretStoreError>> {
        Box::pin(async move {
            let (s, e) = key(server, email);
            let kr = self.keyring().await?;
            let items = kr
                .search_items(&Self::attributes(&s, &e))
                .await
                .map_err(|e| SecretStoreError::Backend(e.to_string()))?;
            let Some(item) = items.first() else {
                return Ok(None);
            };
            let secret = item
                .secret()
                .await
                .map_err(|e| SecretStoreError::Backend(e.to_string()))?;
            StoredCredentials::from_blob(secret.as_bytes()).map(Some)
        })
    }

    fn store<'a>(
        &'a self,
        server: &'a str,
        email: &'a str,
        creds: &'a StoredCredentials,
    ) -> BoxFuture<'a, Result<(), SecretStoreError>> {
        Box::pin(async move {
            let (s, e) = key(server, email);
            let kr = self.keyring().await?;
            let blob = creds.to_blob();
            kr.create_item(
                &format!("sangward: {e} @ {s}"),
                &Self::attributes(&s, &e),
                oo7::Secret::text(blob.as_str()),
                true,
            )
            .await
            .map_err(|e| SecretStoreError::Backend(e.to_string()))
        })
    }

    fn delete<'a>(
        &'a self,
        server: &'a str,
        email: &'a str,
    ) -> BoxFuture<'a, Result<(), SecretStoreError>> {
        Box::pin(async move {
            let (s, e) = key(server, email);
            let kr = self.keyring().await?;
            kr.delete(&Self::attributes(&s, &e))
                .await
                .map_err(|e| SecretStoreError::Backend(e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_roundtrip_and_key_normalisation() {
        let s = InMemorySecretStore::new();
        assert!(s.load("https://x/", "A@B").await.unwrap().is_none());
        let c = StoredCredentials {
            device_id: "dev".into(),
            refresh_token: Some("rt".to_owned().into()),
        };
        s.store("https://x/", " A@B ", &c).await.unwrap();
        let got = s.load("https://x", "a@b").await.unwrap().unwrap();
        assert_eq!(got.device_id, "dev");
        assert_eq!(got.refresh_token.unwrap().expose_secret(), "rt");
        assert!(!format!("{c:?}").contains("rt\""));
        s.delete("https://x", "a@b").await.unwrap();
        assert!(s.load("https://x", "a@b").await.unwrap().is_none());
    }
}
