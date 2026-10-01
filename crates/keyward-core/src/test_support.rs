//! Test-only helpers (feature `test-support`). Never compiled into release frontends.
//!
//! `register` creates an account using *our* crypto (user key, RSA key pair,
//! master password hash). The official `bw` CLI then logs into it, which
//! cross-validates our KDF + EncString implementation against Bitwarden's.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use serde_json::{Value, json};

use crate::api::{ApiClient, ApiError, PasswordLogin, Tokens};
use crate::crypto::{
    EncString, Kdf, MasterKey, SymmetricKey, generate_key_pair, normalize_email,
    public_key_from_b64,
};

#[derive(Debug, thiserror::Error)]
pub enum SupportError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("{0}")]
    Other(String),
}

/// Register a new account via `POST {identity}/accounts/register`.
pub async fn register(
    api: &ApiClient,
    email: &str,
    password: &str,
    kdf: Kdf,
) -> Result<(), SupportError> {
    let master = MasterKey::derive(password.as_bytes(), email, &kdf)?;
    let hash = master.password_hash(password.as_bytes());
    let user_key = SymmetricKey::generate();
    let protected = EncString::encrypt(&master.stretch(), user_key.expose_bytes());
    let pair = generate_key_pair(&user_key)?;
    let (memory, parallelism) = match kdf {
        Kdf::Argon2id {
            memory_mib,
            parallelism,
            ..
        } => (Some(memory_mib), Some(parallelism)),
        Kdf::Pbkdf2 { .. } => (None, None),
    };
    let iterations = match kdf {
        Kdf::Pbkdf2 { iterations } | Kdf::Argon2id { iterations, .. } => iterations,
    };
    let body = json!({
        "email": normalize_email(email),
        "name": "keyward test user",
        "masterPasswordHash": hash,
        "masterPasswordHint": null,
        "key": protected.to_string(),
        "kdf": kdf.kind(),
        "kdfIterations": iterations,
        "kdfMemory": memory,
        "kdfParallelism": parallelism,
        "keys": {
            "publicKey": pair.public_key_b64,
            "encryptedPrivateKey": pair.encrypted_private_key.to_string(),
        },
    });
    api.post_identity("/accounts/register", &body).await?;
    Ok(())
}

/// Log in with the password grant (handles an optional TOTP secret for 2FA accounts).
pub async fn login(
    api: &ApiClient,
    email: &str,
    password: &str,
    totp_secret: Option<&str>,
) -> Result<(Tokens, MasterKey), SupportError> {
    let kdf = api.prelogin(email).await?;
    let master = MasterKey::derive(password.as_bytes(), email, &kdf)?;
    let hash = master.password_hash(password.as_bytes());
    let code = totp_secret.map(current_totp).transpose()?;
    let tokens = api
        .login_password(&PasswordLogin {
            email,
            password_hash: &hash,
            device_id: "00000000-0000-4000-8000-00000000c0de",
            totp: code.as_deref(),
        })
        .await?;
    Ok((tokens, master))
}

pub fn current_totp(secret: &str) -> Result<String, SupportError> {
    let now = crate::api::now_unix() as u64;
    crate::vault::totp_from_seed(secret, now)
        .map(|t| t.code.to_string())
        .map_err(|e| SupportError::Other(e.to_string()))
}

/// Random base32 TOTP secret (20 bytes, as Vaultwarden requires).
pub fn random_totp_secret() -> String {
    let mut b = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut b);
    base32_encode(&b)
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHA: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &byte in data {
        buf = (buf << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHA[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHA[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Enable authenticator-app 2FA for the account. Returns the base32 secret.
pub async fn enable_totp(
    api: &ApiClient,
    email: &str,
    password: &str,
) -> Result<String, SupportError> {
    let (tokens, master) = login(api, email, password, None).await?;
    let hash = master.password_hash(password.as_bytes());
    let secret = random_totp_secret();
    let code = current_totp(&secret)?;
    use secrecy::ExposeSecret;
    let body = json!({ "key": secret, "token": code, "masterPasswordHash": hash });
    api.post_api(
        tokens.access_token.expose_secret(),
        "/two-factor/authenticator",
        &body,
    )
    .await?;
    Ok(secret)
}

/// Create an organization owned by the user, with one default collection.
/// Returns `(org_id, collection_id)`.
pub async fn create_org(
    api: &ApiClient,
    email: &str,
    password: &str,
    totp_secret: Option<&str>,
    name: &str,
) -> Result<(String, String), SupportError> {
    use secrecy::ExposeSecret;
    let (tokens, master) = login(api, email, password, totp_secret).await?;
    let access = tokens.access_token.expose_secret();
    let user_key = master.decrypt_user_key(
        &tokens
            .key
            .as_deref()
            .ok_or_else(|| SupportError::Other("no key".into()))?
            .parse()?,
    )?;

    // The org key is wrapped with the owner's RSA public key.
    let (_, raw) = api.sync(access).await?;
    let sync = crate::models::SyncResponse::from_json(raw)
        .map_err(|e| SupportError::Other(e.to_string()))?;
    let pk_enc = sync
        .profile
        .private_key
        .ok_or_else(|| SupportError::Other("no private key".into()))?;
    let private = crate::crypto::decrypt_private_key(&pk_enc.parse()?, &user_key)?;
    let public = rsa::RsaPublicKey::from(&private);
    let spki = {
        use rsa::pkcs8::EncodePublicKey;
        B64.encode(
            public
                .to_public_key_der()
                .map_err(|_| SupportError::Other("spki".into()))?
                .as_bytes(),
        )
    };
    let _ = public_key_from_b64(&spki)?;

    let org_key = SymmetricKey::generate();
    let wrapped = EncString::encrypt_rsa_sha1(&public, org_key.expose_bytes())?;
    let collection_name = EncString::encrypt(&org_key, b"Default collection").to_string();
    let org_pair = generate_key_pair(&org_key)?;
    let body = json!({
        "name": name,
        "billingEmail": normalize_email(email),
        "collectionName": collection_name,
        "key": wrapped.to_string(),
        "keys": { "publicKey": org_pair.public_key_b64, "encryptedPrivateKey": org_pair.encrypted_private_key.to_string() },
        "planType": 0,
    });
    let org = api.post_api(access, "/organizations", &body).await?;
    let org = crate::models::normalize_keys(org);
    let org_id = org
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| SupportError::Other("org id".into()))?
        .to_owned();

    // Find the default collection id from a fresh sync.
    let (_, raw) = api.sync(access).await?;
    let raw = crate::models::normalize_keys(raw);
    let coll = raw
        .get("collections")
        .and_then(Value::as_array)
        .and_then(|c| {
            c.iter()
                .find(|c| c.get("organizationId").and_then(Value::as_str) == Some(org_id.as_str()))
        })
        .and_then(|c| c.get("id").and_then(Value::as_str))
        .ok_or_else(|| SupportError::Other("collection id".into()))?
        .to_owned();
    Ok((org_id, coll))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(random_totp_secret().len(), 32);
    }
}
