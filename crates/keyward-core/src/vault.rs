//! Unlocked vault: key material plus the still-encrypted sync data.
//!
//! The ciphers stay encrypted in memory. `summaries()` decrypts only names,
//! usernames and URI hosts; secrets are decrypted one field at a time.

use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::crypto::{
    CryptoError, EncString, MasterKey, SymmetricKey, decrypt_opt, decrypt_private_key,
};
use crate::models::{CIPHER_TYPE_LOGIN, CIPHER_TYPE_SECURE_NOTE, Cipher, SyncResponse};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Login,
    SecureNote,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub id: String,
    pub kind: Kind,
    pub name: String,
    pub username: Option<String>,
    pub uri_host: Option<String>,
    pub has_password: bool,
    pub has_totp: bool,
    pub has_notes: bool,
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Password,
    Notes,
    TotpSeed,
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("item not found")]
    NotFound,
    #[error("item has no TOTP configured")]
    NoTotp,
    #[error("invalid TOTP configuration: {0}")]
    BadTotp(String),
    #[error("no key available for organization {0}")]
    MissingOrgKey(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Keys held while unlocked. Dropping this zeroizes everything.
pub struct Keys {
    pub user: SymmetricKey,
    pub orgs: HashMap<String, SymmetricKey>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("orgs", &self.orgs.len())
            .finish_non_exhaustive()
    }
}

impl Keys {
    /// Derive all keys from the master password. A wrong password fails the MAC on `protected_key`.
    pub fn unlock(
        master_key: &MasterKey,
        protected_key: &str,
        private_key: Option<&str>,
        sync: Option<&SyncResponse>,
    ) -> Result<Self, CryptoError> {
        let user = master_key.decrypt_user_key(&protected_key.parse()?)?;
        let mut keys = Keys {
            user,
            orgs: HashMap::new(),
        };
        if let (Some(pk), Some(sync)) = (private_key, sync) {
            keys.load_org_keys(pk, sync)?;
        }
        Ok(keys)
    }

    /// Decrypt org keys with the RSA private key. The private key is dropped afterwards.
    pub fn load_org_keys(
        &mut self,
        private_key: &str,
        sync: &SyncResponse,
    ) -> Result<(), CryptoError> {
        self.orgs.clear();
        if sync.profile.organizations.iter().all(|o| o.key.is_none()) {
            return Ok(());
        }
        let rsa = decrypt_private_key(&private_key.parse()?, &self.user)?;
        for org in &sync.profile.organizations {
            let Some(k) = org.key.as_deref() else {
                continue;
            };
            match k
                .parse::<EncString>()
                .and_then(|e| e.decrypt_rsa(&rsa))
                .and_then(|b| SymmetricKey::from_slice(&b))
            {
                Ok(key) => {
                    self.orgs.insert(org.id.clone(), key);
                }
                Err(e) => {
                    tracing::warn!(org = %org.id, error = %e, "could not decrypt organization key")
                }
            }
        }
        Ok(())
    }

    /// The key that decrypts a cipher's fields: per-cipher key if present, else org/user key.
    fn cipher_key(&self, c: &Cipher) -> Result<CipherKey<'_>, VaultError> {
        let outer = match c.organization_id.as_deref() {
            Some(org) => self
                .orgs
                .get(org)
                .ok_or_else(|| VaultError::MissingOrgKey(org.to_owned()))?,
            None => &self.user,
        };
        match c.key.as_deref().filter(|k| !k.is_empty()) {
            Some(k) => {
                let bytes = k.parse::<EncString>()?.decrypt_with(outer)?;
                Ok(CipherKey::Owned(SymmetricKey::from_slice(&bytes)?))
            }
            None => Ok(CipherKey::Borrowed(outer)),
        }
    }
}

enum CipherKey<'a> {
    Borrowed(&'a SymmetricKey),
    Owned(SymmetricKey),
}

impl CipherKey<'_> {
    fn get(&self) -> &SymmetricKey {
        match self {
            CipherKey::Borrowed(k) => k,
            CipherKey::Owned(k) => k,
        }
    }
}

fn kind_of(c: &Cipher) -> Option<Kind> {
    match c.kind {
        CIPHER_TYPE_LOGIN => Some(Kind::Login),
        CIPHER_TYPE_SECURE_NOTE => Some(Kind::SecureNote),
        _ => None,
    }
}

fn nonempty(s: &Option<String>) -> bool {
    s.as_deref().is_some_and(|s| !s.is_empty())
}

/// Extract just the host of a URI (no path/query, which may carry tokens).
pub fn uri_host(uri: &str) -> Option<String> {
    let u = uri.trim();
    if u.is_empty() {
        return None;
    }
    let parsed = url::Url::parse(u)
        .or_else(|_| url::Url::parse(&format!("https://{u}")))
        .ok()?;
    parsed.host_str().map(str::to_owned)
}

/// Visible ciphers: logins and notes that are not in the trash.
pub fn visible(sync: &SyncResponse) -> impl Iterator<Item = &Cipher> {
    sync.ciphers
        .iter()
        .filter(|c| c.deleted_date.is_none() && kind_of(c).is_some())
}

pub fn summaries(keys: &Keys, sync: &SyncResponse) -> Vec<Summary> {
    let mut out = Vec::new();
    for c in visible(sync) {
        match summarize(keys, c) {
            Ok(s) => out.push(s),
            // Never let one bad item break the list; ids are not secret.
            Err(e) => tracing::warn!(id = %c.id, error = %e, "skipping undecryptable item"),
        }
    }
    out.sort_by_key(|s| s.name.to_lowercase());
    out
}

fn summarize(keys: &Keys, c: &Cipher) -> Result<Summary, VaultError> {
    let kind = kind_of(c).ok_or(VaultError::NotFound)?;
    let ck = keys.cipher_key(c)?;
    let key = ck.get();
    let name = decrypt_opt(c.name.as_deref(), key)?.unwrap_or_default();
    let (username, uri_host_v, has_password, has_totp) = match &c.login {
        Some(l) => {
            let username = decrypt_opt(l.username.as_deref(), key)?;
            let first_uri = l
                .uris
                .as_ref()
                .and_then(|u| u.iter().find_map(|u| u.uri.clone()))
                .or_else(|| l.uri.clone());
            let host = match first_uri {
                Some(u) => decrypt_opt(Some(&u), key)?.and_then(|u| uri_host(&u)),
                None => None,
            };
            (username, host, nonempty(&l.password), nonempty(&l.totp))
        }
        None => (None, None, false, false),
    };
    Ok(Summary {
        id: c.id.clone(),
        kind,
        name,
        username,
        uri_host: uri_host_v,
        has_password,
        has_totp,
        has_notes: nonempty(&c.notes),
        organization_id: c.organization_id.clone(),
    })
}

fn find<'a>(sync: &'a SyncResponse, id: &str) -> Result<&'a Cipher, VaultError> {
    visible(sync)
        .find(|c| c.id == id)
        .ok_or(VaultError::NotFound)
}

/// Decrypt a single secret field.
pub fn secret(
    keys: &Keys,
    sync: &SyncResponse,
    id: &str,
    field: Field,
) -> Result<Option<Zeroizing<String>>, VaultError> {
    let c = find(sync, id)?;
    let ck = keys.cipher_key(c)?;
    let enc = match field {
        Field::Notes => c.notes.as_deref(),
        Field::Password => c.login.as_ref().and_then(|l| l.password.as_deref()),
        Field::TotpSeed => c.login.as_ref().and_then(|l| l.totp.as_deref()),
    };
    Ok(decrypt_opt(enc, ck.get())?.map(Zeroizing::new))
}

pub struct TotpCode {
    pub code: Zeroizing<String>,
    pub period: u64,
    pub remaining: u64,
}

pub fn totp(keys: &Keys, sync: &SyncResponse, id: &str, now: u64) -> Result<TotpCode, VaultError> {
    let seed = secret(keys, sync, id, Field::TotpSeed)?.ok_or(VaultError::NoTotp)?;
    totp_from_seed(&seed, now)
}

/// Accepts `otpauth://` URIs, `steam://<secret>`, or a bare base32 secret.
pub fn totp_from_seed(seed: &str, now: u64) -> Result<TotpCode, VaultError> {
    use totp_rs::{Algorithm, Secret, TOTP};
    let seed = seed.trim();
    let bad = |e: &dyn std::fmt::Display| VaultError::BadTotp(e.to_string());
    let totp = if seed.to_ascii_lowercase().starts_with("otpauth://") {
        TOTP::from_url_unchecked(seed).map_err(|e| bad(&e))?
    } else if let Some(rest) = seed.strip_prefix("steam://") {
        let secret = Secret::Encoded(rest.to_owned())
            .to_bytes()
            .map_err(|e| bad(&format!("{e:?}")))?;
        TOTP::new_steam(secret, String::new())
    } else {
        let cleaned: String = seed
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '=')
            .collect::<String>()
            .to_uppercase();
        let secret = Secret::Encoded(cleaned)
            .to_bytes()
            .map_err(|e| bad(&format!("{e:?}")))?;
        TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret, None, String::new())
    };
    let period = totp.step;
    Ok(TotpCode {
        code: Zeroizing::new(totp.generate(now)),
        period,
        remaining: period - (now % period),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction() {
        assert_eq!(
            uri_host("https://Example.com/login?token=abc").as_deref(),
            Some("example.com")
        );
        assert_eq!(uri_host("example.org/path").as_deref(), Some("example.org"));
        assert_eq!(uri_host("androidapp://com.foo").as_deref(), Some("com.foo"));
        assert_eq!(uri_host(""), None);
    }

    #[test]
    fn totp_rfc6238_vector() {
        // RFC 6238 SHA1 test secret "12345678901234567890", T=59 -> 94287082 (8 digits) / 287082 (6).
        let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(totp_from_seed(seed, 59).unwrap().code.as_str(), "287082");
        let uri = format!("otpauth://totp/x:y?secret={seed}&digits=8&issuer=x");
        assert_eq!(totp_from_seed(&uri, 59).unwrap().code.as_str(), "94287082");
        let t = totp_from_seed(seed, 61).unwrap();
        assert_eq!((t.period, t.remaining), (30, 29));
    }

    #[test]
    fn totp_steam() {
        let t = totp_from_seed("steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap();
        assert_eq!(t.code.len(), 5);
    }

    #[test]
    fn totp_garbage_is_an_error() {
        assert!(totp_from_seed("!!!not base32!!!", 0).is_err());
    }
}
