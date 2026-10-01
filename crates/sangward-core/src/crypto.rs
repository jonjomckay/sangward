//! Bitwarden-compatible cryptography: KDFs, key stretching and EncString handling.
//!
//! Reference: the `rbw` project and Bitwarden's published security whitepaper.
//! Nothing here depends on Bitwarden's `sdk-internal`.

use std::fmt;
use std::str::FromStr;

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::mlock;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid EncString: {0}")]
    InvalidEncString(&'static str),
    #[error("unsupported EncString type {0}")]
    UnsupportedType(u8),
    #[error("MAC verification failed")]
    MacMismatch,
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid key length")]
    KeyLength,
    #[error("invalid KDF parameters: {0}")]
    Kdf(String),
    #[error("RSA error")]
    Rsa,
    #[error("decrypted data is not valid UTF-8")]
    Utf8,
}

// ---------------------------------------------------------------------------
// KDF
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Kdf {
    Pbkdf2 {
        iterations: u32,
    },
    /// `memory_mib` is in MiB as sent by the server.
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

impl Kdf {
    /// Build from the server's numeric representation (0 = PBKDF2, 1 = Argon2id).
    pub fn from_server(
        kind: i64,
        iterations: i64,
        memory: Option<i64>,
        parallelism: Option<i64>,
    ) -> Result<Self, CryptoError> {
        let it = u32::try_from(iterations).map_err(|_| CryptoError::Kdf("iterations".into()))?;
        match kind {
            0 => {
                if it == 0 {
                    return Err(CryptoError::Kdf("PBKDF2 iterations must be > 0".into()));
                }
                Ok(Kdf::Pbkdf2 { iterations: it })
            }
            1 => {
                let m = memory.ok_or_else(|| CryptoError::Kdf("Argon2 memory missing".into()))?;
                let p = parallelism
                    .ok_or_else(|| CryptoError::Kdf("Argon2 parallelism missing".into()))?;
                Ok(Kdf::Argon2id {
                    iterations: it,
                    memory_mib: u32::try_from(m).map_err(|_| CryptoError::Kdf("memory".into()))?,
                    parallelism: u32::try_from(p)
                        .map_err(|_| CryptoError::Kdf("parallelism".into()))?,
                })
            }
            other => Err(CryptoError::Kdf(format!("unknown KDF type {other}"))),
        }
    }

    pub fn kind(&self) -> i64 {
        match self {
            Kdf::Pbkdf2 { .. } => 0,
            Kdf::Argon2id { .. } => 1,
        }
    }
}

/// Bitwarden normalises the email used as salt: trimmed and lowercased.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// 32-byte master key derived from the master password.
pub struct MasterKey(SecretBox<[u8; 32]>);

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

impl MasterKey {
    pub fn derive(password: &[u8], email: &str, kdf: &Kdf) -> Result<Self, CryptoError> {
        let salt = normalize_email(email);
        let mut out = SecretBox::new(Box::new([0u8; 32]));
        match *kdf {
            Kdf::Pbkdf2 { iterations } => {
                pbkdf2::pbkdf2_hmac::<Sha256>(
                    password,
                    salt.as_bytes(),
                    iterations,
                    out_mut(&mut out),
                );
            }
            Kdf::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                let salt_hash = Sha256::digest(salt.as_bytes());
                let params = argon2::Params::new(
                    memory_mib.saturating_mul(1024),
                    iterations,
                    parallelism,
                    Some(32),
                )
                .map_err(|e| CryptoError::Kdf(e.to_string()))?;
                let a2 = argon2::Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    params,
                );
                a2.hash_password_into(password, &salt_hash, out_mut(&mut out))
                    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
            }
        }
        Ok(MasterKey(out))
    }

    /// Server-side authentication hash: PBKDF2-SHA256(master_key, password, 1), base64.
    pub fn password_hash(&self, password: &[u8]) -> String {
        let mut h = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(self.0.expose_secret(), password, 1, h.as_mut());
        B64.encode(h.as_ref())
    }

    /// HKDF-Expand the master key into a 64-byte enc+mac key.
    pub fn stretch(&self) -> SymmetricKey {
        let hk =
            hkdf::Hkdf::<Sha256>::from_prk(self.0.expose_secret()).expect("32-byte PRK is valid");
        let mut buf = Zeroizing::new([0u8; 64]);
        hk.expand(b"enc", &mut buf[..32])
            .expect("32 bytes is a valid HKDF length");
        hk.expand(b"mac", &mut buf[32..])
            .expect("32 bytes is a valid HKDF length");
        SymmetricKey::from_slice(buf.as_ref()).expect("64 bytes")
    }

    /// Decrypt the protected user key (`key` from the server). Wrong passwords fail the MAC.
    pub fn decrypt_user_key(&self, protected: &EncString) -> Result<SymmetricKey, CryptoError> {
        let stretched = self.stretch();
        let bytes = protected.decrypt_with(&stretched)?;
        SymmetricKey::from_slice(&bytes)
    }
}

fn out_mut(b: &mut SecretBox<[u8; 32]>) -> &mut [u8] {
    use secrecy::ExposeSecretMut;
    b.expose_secret_mut().as_mut_slice()
}

// ---------------------------------------------------------------------------
// Symmetric keys
// ---------------------------------------------------------------------------

/// AES-256-CBC + HMAC-SHA256 key pair (64 bytes: 32 enc || 32 mac).
/// Heap-allocated, mlock'd where permitted, zeroized on drop.
pub struct SymmetricKey {
    inner: SecretBox<[u8; 64]>,
    locked: bool,
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(<redacted>)")
    }
}

impl SymmetricKey {
    pub fn from_slice(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() != 64 {
            return Err(CryptoError::KeyLength);
        }
        let mut inner = SecretBox::new(Box::new([0u8; 64]));
        {
            use secrecy::ExposeSecretMut;
            inner.expose_secret_mut().copy_from_slice(b);
        }
        let locked = mlock::lock(inner.expose_secret().as_slice());
        Ok(Self { inner, locked })
    }

    pub fn generate() -> Self {
        let mut buf = Zeroizing::new([0u8; 64]);
        rand::rngs::OsRng.fill_bytes(buf.as_mut());
        Self::from_slice(buf.as_ref()).expect("64 bytes")
    }

    fn enc(&self) -> &[u8] {
        &self.inner.expose_secret()[..32]
    }
    fn mac(&self) -> &[u8] {
        &self.inner.expose_secret()[32..]
    }

    /// Raw bytes, needed only to re-wrap this key (registration, cipher keys).
    pub fn expose_bytes(&self) -> &[u8] {
        self.inner.expose_secret().as_slice()
    }

    pub fn try_clone(&self) -> Self {
        Self::from_slice(self.expose_bytes()).expect("64 bytes")
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        // SecretBox zeroizes the bytes on its own drop; we just undo mlock first.
        if self.locked {
            mlock::unlock(self.inner.expose_secret().as_slice());
        }
    }
}

// ---------------------------------------------------------------------------
// EncString
// ---------------------------------------------------------------------------

/// A Bitwarden "EncString": `<type>.<b64>|<b64>|...`.
#[derive(Clone, PartialEq, Eq)]
pub enum EncString {
    /// Type 2: AES-256-CBC, HMAC-SHA256 over iv||ct.
    AesCbc256HmacSha256 {
        iv: [u8; 16],
        ct: Vec<u8>,
        mac: [u8; 32],
    },
    /// Type 3 (OAEP-SHA256) and 4 (OAEP-SHA1); 5/6 add a (legacy) MAC we ignore.
    Rsa { kind: u8, ct: Vec<u8> },
}

impl fmt::Debug for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncString::AesCbc256HmacSha256 { ct, .. } => {
                write!(f, "EncString(2, {} bytes)", ct.len())
            }
            EncString::Rsa { kind, ct } => write!(f, "EncString({kind}, {} bytes)", ct.len()),
        }
    }
}

impl FromStr for EncString {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ty, rest) = s
            .split_once('.')
            .ok_or(CryptoError::InvalidEncString("missing type"))?;
        let ty: u8 = ty
            .parse()
            .map_err(|_| CryptoError::InvalidEncString("bad type"))?;
        let parts: Vec<&str> = rest.split('|').collect();
        let dec = |p: &str| {
            B64.decode(p)
                .map_err(|_| CryptoError::InvalidEncString("bad base64"))
        };
        match ty {
            2 => {
                if parts.len() != 3 {
                    return Err(CryptoError::InvalidEncString("type 2 needs iv|ct|mac"));
                }
                let iv: [u8; 16] = dec(parts[0])?
                    .try_into()
                    .map_err(|_| CryptoError::InvalidEncString("iv length"))?;
                let ct = dec(parts[1])?;
                let mac: [u8; 32] = dec(parts[2])?
                    .try_into()
                    .map_err(|_| CryptoError::InvalidEncString("mac length"))?;
                Ok(EncString::AesCbc256HmacSha256 { iv, ct, mac })
            }
            3..=6 => Ok(EncString::Rsa {
                kind: ty,
                ct: dec(parts[0])?,
            }),
            other => Err(CryptoError::UnsupportedType(other)),
        }
    }
}

impl fmt::Display for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncString::AesCbc256HmacSha256 { iv, ct, mac } => {
                write!(
                    f,
                    "2.{}|{}|{}",
                    B64.encode(iv),
                    B64.encode(ct),
                    B64.encode(mac)
                )
            }
            EncString::Rsa { kind, ct } => write!(f, "{kind}.{}", B64.encode(ct)),
        }
    }
}

impl EncString {
    pub fn encrypt(key: &SymmetricKey, plaintext: &[u8]) -> Self {
        let mut iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        let ct = Aes256CbcEnc::new_from_slices(key.enc(), &iv)
            .expect("key/iv lengths are fixed")
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        let mac = compute_mac(key.mac(), &iv, &ct);
        EncString::AesCbc256HmacSha256 { iv, ct, mac }
    }

    /// Decrypt a type-2 EncString. The MAC is verified (constant time) before decryption.
    pub fn decrypt_with(&self, key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        match self {
            EncString::AesCbc256HmacSha256 { iv, ct, mac } => {
                let expected = compute_mac(key.mac(), iv, ct);
                if !bool::from(expected.ct_eq(mac)) {
                    return Err(CryptoError::MacMismatch);
                }
                let pt = Aes256CbcDec::new_from_slices(key.enc(), iv)
                    .map_err(|_| CryptoError::KeyLength)?
                    .decrypt_padded_vec_mut::<Pkcs7>(ct)
                    .map_err(|_| CryptoError::Decrypt)?;
                Ok(Zeroizing::new(pt))
            }
            EncString::Rsa { kind, .. } => Err(CryptoError::UnsupportedType(*kind)),
        }
    }

    pub fn decrypt_to_string(&self, key: &SymmetricKey) -> Result<String, CryptoError> {
        let bytes = self.decrypt_with(key)?;
        String::from_utf8(bytes.to_vec()).map_err(|e| {
            let mut v = e.into_bytes();
            v.zeroize();
            CryptoError::Utf8
        })
    }

    /// Decrypt an RSA-wrapped key (types 3/4/5/6) with the user's private key.
    pub fn decrypt_rsa(&self, private: &RsaPrivateKey) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        match self {
            EncString::Rsa { kind, ct } => {
                let pt = match kind {
                    3 | 5 => private.decrypt(Oaep::new::<Sha256>(), ct),
                    4 | 6 => private.decrypt(Oaep::new::<sha1::Sha1>(), ct),
                    k => return Err(CryptoError::UnsupportedType(*k)),
                }
                .map_err(|_| CryptoError::Rsa)?;
                Ok(Zeroizing::new(pt))
            }
            EncString::AesCbc256HmacSha256 { .. } => Err(CryptoError::UnsupportedType(2)),
        }
    }

    /// RSA-OAEP-SHA1 encrypt (type 4), used to wrap org keys for a member.
    pub fn encrypt_rsa_sha1(public: &RsaPublicKey, plaintext: &[u8]) -> Result<Self, CryptoError> {
        let ct = public
            .encrypt(&mut rand::rngs::OsRng, Oaep::new::<sha1::Sha1>(), plaintext)
            .map_err(|_| CryptoError::Rsa)?;
        Ok(EncString::Rsa { kind: 4, ct })
    }
}

fn compute_mac(mac_key: &[u8], iv: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(mac_key).expect("HMAC accepts any key length");
    m.update(iv);
    m.update(ct);
    m.finalize().into_bytes().into()
}

/// Parse an optional EncString field and decrypt it to a string.
pub fn decrypt_opt(field: Option<&str>, key: &SymmetricKey) -> Result<Option<String>, CryptoError> {
    match field {
        None => Ok(None),
        Some("") => Ok(None),
        Some(s) => Ok(Some(s.parse::<EncString>()?.decrypt_to_string(key)?)),
    }
}

// ---------------------------------------------------------------------------
// RSA key pair handling
// ---------------------------------------------------------------------------

/// Decrypt the user's PKCS#8 private key (type-2 EncString under the user key).
pub fn decrypt_private_key(
    enc: &EncString,
    user_key: &SymmetricKey,
) -> Result<RsaPrivateKey, CryptoError> {
    let der = enc.decrypt_with(user_key)?;
    RsaPrivateKey::from_pkcs8_der(&der).map_err(|_| CryptoError::Rsa)
}

/// Freshly generated RSA-2048 key pair, as registered with the server.
pub struct GeneratedKeyPair {
    /// base64 SPKI DER.
    pub public_key_b64: String,
    /// EncString of the PKCS#8 DER private key, under the user key.
    pub encrypted_private_key: EncString,
    pub public_key: RsaPublicKey,
}

pub fn generate_key_pair(user_key: &SymmetricKey) -> Result<GeneratedKeyPair, CryptoError> {
    let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).map_err(|_| CryptoError::Rsa)?;
    let public = RsaPublicKey::from(&private);
    let spki = public.to_public_key_der().map_err(|_| CryptoError::Rsa)?;
    let pkcs8 = private.to_pkcs8_der().map_err(|_| CryptoError::Rsa)?;
    Ok(GeneratedKeyPair {
        public_key_b64: B64.encode(spki.as_bytes()),
        encrypted_private_key: EncString::encrypt(user_key, pkcs8.as_bytes()),
        public_key: public,
    })
}

pub fn public_key_from_b64(b64: &str) -> Result<RsaPublicKey, CryptoError> {
    use rsa::pkcs8::DecodePublicKey;
    let der = B64.decode(b64.trim()).map_err(|_| CryptoError::Rsa)?;
    RsaPublicKey::from_public_key_der(&der).map_err(|_| CryptoError::Rsa)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_known_vector() {
        // Vector from Bitwarden's documentation/tests: "asdfasdf" / "test@bitwarden.com", 100k.
        // Not shipped by `bw`, but cross-checked by the bw-generated fixtures in tests/vectors.rs.
        let mk = MasterKey::derive(
            b"asdfasdf",
            "test@bitwarden.com",
            &Kdf::Pbkdf2 {
                iterations: 100_000,
            },
        )
        .unwrap();
        let hash = mk.password_hash(b"asdfasdf");
        assert_eq!(hash, "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=");
    }

    #[test]
    fn email_is_normalized() {
        let kdf = Kdf::Pbkdf2 { iterations: 5000 };
        let a = MasterKey::derive(b"pw", "  Foo@Example.COM ", &kdf)
            .unwrap()
            .password_hash(b"pw");
        let b = MasterKey::derive(b"pw", "foo@example.com", &kdf)
            .unwrap()
            .password_hash(b"pw");
        assert_eq!(a, b);
    }

    #[test]
    fn encstring_parse_display() {
        let key = SymmetricKey::generate();
        let e = EncString::encrypt(&key, b"hello");
        let s = e.to_string();
        assert!(s.starts_with("2."));
        let back: EncString = s.parse().unwrap();
        assert_eq!(back.decrypt_to_string(&key).unwrap(), "hello");
    }

    #[test]
    fn tampered_mac_is_rejected() {
        let key = SymmetricKey::generate();
        let EncString::AesCbc256HmacSha256 { iv, mut ct, mac } =
            EncString::encrypt(&key, b"secret data")
        else {
            unreachable!()
        };
        ct[0] ^= 1;
        let e = EncString::AesCbc256HmacSha256 { iv, ct, mac };
        assert_eq!(e.decrypt_with(&key).unwrap_err(), CryptoError::MacMismatch);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let e = EncString::encrypt(&SymmetricKey::generate(), b"x");
        assert_eq!(
            e.decrypt_with(&SymmetricKey::generate()).unwrap_err(),
            CryptoError::MacMismatch
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!("".parse::<EncString>().is_err());
        assert!("2.abc".parse::<EncString>().is_err());
        assert!("9.AAAA|AAAA|AAAA".parse::<EncString>().is_err());
        assert!("x.AAAA".parse::<EncString>().is_err());
    }

    #[test]
    fn kdf_from_server() {
        assert_eq!(
            Kdf::from_server(0, 600000, None, None).unwrap(),
            Kdf::Pbkdf2 { iterations: 600000 }
        );
        assert_eq!(
            Kdf::from_server(1, 3, Some(64), Some(4)).unwrap(),
            Kdf::Argon2id {
                iterations: 3,
                memory_mib: 64,
                parallelism: 4
            }
        );
        assert!(Kdf::from_server(1, 3, None, Some(4)).is_err());
        assert!(Kdf::from_server(7, 3, None, None).is_err());
    }
}
