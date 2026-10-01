//! Cross-validation against data encrypted by the official Bitwarden CLI.
//!
//! `just seed` captures `tests/vectors/*.json` from a live Vaultwarden where
//! the items were created by `bw`. Each file holds the *encrypted* material
//! (KDF params, protected user key, raw sync) plus the plaintext that `bw`
//! was asked to store. These tests then check that keyward's KDF, key
//! stretching, EncString and RSA/org-key code decrypt bw's output exactly.
//!
//! Vector files are committed, so `cargo test` needs no server.

use std::path::PathBuf;

use keyward_core::crypto::{Kdf, MasterKey};
use keyward_core::models::SyncResponse;
use keyward_core::vault::{self, Field, Keys};
use serde_json::Value;

fn vector_files() -> Vec<PathBuf> {
    // `just test` points this at vectors freshly captured by `just seed`;
    // otherwise use the committed copies.
    let dir = std::env::var_os("KW_VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors"));
    let mut v: Vec<_> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "json"))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

struct Vector {
    file: String,
    email: String,
    password: String,
    kdf: Kdf,
    protected_key: String,
    sync: SyncResponse,
    expected: Vec<Value>,
}

fn load(path: &PathBuf) -> Vector {
    let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    Vector {
        file: path.file_name().unwrap().to_string_lossy().into_owned(),
        email: v["email"].as_str().unwrap().to_owned(),
        password: v["password"].as_str().unwrap().to_owned(),
        kdf: serde_json::from_value(v["kdf"].clone()).unwrap(),
        protected_key: v["protected_key"].as_str().unwrap().to_owned(),
        sync: SyncResponse::from_json(v["sync"].clone()).unwrap(),
        expected: v["expected"].as_array().unwrap().clone(),
    }
}

#[test]
fn vectors_are_present() {
    // Guard against silently passing with an empty directory.
    let files = vector_files();
    assert!(
        files.len() >= 2,
        "expected bw-generated vectors in tests/vectors (run `just seed`)"
    );
    let kdfs: Vec<_> = files.iter().map(load).map(|v| v.kdf.kind()).collect();
    assert!(
        kdfs.contains(&0) && kdfs.contains(&1),
        "need both a PBKDF2 and an Argon2id vector"
    );
}

#[test]
fn decrypt_bw_created_items() {
    for path in vector_files() {
        let v = load(&path);
        let master = MasterKey::derive(v.password.as_bytes(), &v.email, &v.kdf).unwrap();
        let keys = Keys::unlock(
            &master,
            &v.protected_key,
            v.sync.profile.private_key.as_deref(),
            Some(&v.sync),
        )
        .unwrap_or_else(|e| panic!("{}: unlock failed: {e}", v.file));
        let summaries = vault::summaries(&keys, &v.sync);
        assert!(!v.expected.is_empty(), "{}: no expected items", v.file);
        for exp in &v.expected {
            let name = exp["name"].as_str().unwrap();
            let s = summaries
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| {
                    panic!(
                        "{}: item {name:?} not decrypted; got {:?}",
                        v.file,
                        summaries.iter().map(|s| &s.name).collect::<Vec<_>>()
                    )
                });
            assert_eq!(
                s.username.as_deref(),
                exp["username"].as_str(),
                "{}: username of {name}",
                v.file
            );
            if let Some(host) = exp["uri_host"].as_str() {
                assert_eq!(
                    s.uri_host.as_deref(),
                    Some(host),
                    "{}: host of {name}",
                    v.file
                );
            }
            let pw = vault::secret(&keys, &v.sync, &s.id, Field::Password).unwrap();
            assert_eq!(
                pw.as_deref().map(|s| s.as_str()),
                exp["password"].as_str(),
                "{}: password of {name}",
                v.file
            );
            let notes = vault::secret(&keys, &v.sync, &s.id, Field::Notes).unwrap();
            assert_eq!(
                notes.as_deref().map(|s| s.as_str()),
                exp["notes"].as_str(),
                "{}: notes of {name}",
                v.file
            );
            let totp = vault::secret(&keys, &v.sync, &s.id, Field::TotpSeed).unwrap();
            assert_eq!(
                totp.as_deref().map(|s| s.as_str()),
                exp["totp"].as_str(),
                "{}: totp of {name}",
                v.file
            );
            if let Some(seed) = exp["totp"].as_str() {
                // Code generated from bw's stored seed must match one generated from the plaintext seed.
                let now = 1_700_000_000;
                let a = vault::totp(&keys, &v.sync, &s.id, now).unwrap();
                let b = vault::totp_from_seed(seed, now).unwrap();
                assert_eq!(a.code, b.code);
            }
        }
    }
}

/// bw 2026.x against Vaultwarden doesn't emit per-cipher keys, so wrap one of
/// bw's ciphers in a per-cipher key ourselves: re-encrypt its fields under a
/// fresh cipher key and wrap that key with the user key, as newer clients do.
#[test]
fn per_cipher_key_is_used() {
    use keyward_core::crypto::{EncString, SymmetricKey};
    let Some(path) = vector_files().into_iter().next() else {
        return;
    };
    let v = load(&path);
    let master = MasterKey::derive(v.password.as_bytes(), &v.email, &v.kdf).unwrap();
    let keys = Keys::unlock(&master, &v.protected_key, None, None).unwrap();
    let mut sync = v.sync.clone();
    let c = sync
        .ciphers
        .iter_mut()
        .find(|c| c.organization_id.is_none() && c.kind == 1)
        .unwrap();
    let id = c.id.clone();
    let user_key = &keys.user;
    let cipher_key = SymmetricKey::generate();
    let reenc = |f: &Option<String>| {
        f.as_deref().map(|s| {
            let pt = s
                .parse::<EncString>()
                .unwrap()
                .decrypt_with(user_key)
                .unwrap();
            EncString::encrypt(&cipher_key, &pt).to_string()
        })
    };
    c.name = reenc(&c.name);
    let login = c.login.as_mut().unwrap();
    let pw_before = login.password.clone();
    login.password = reenc(&login.password);
    login.username = reenc(&login.username);
    for u in login.uris.iter_mut().flatten() {
        u.uri = reenc(&u.uri);
    }
    login.totp = reenc(&login.totp);
    c.key = Some(EncString::encrypt(user_key, cipher_key.expose_bytes()).to_string());

    let expected_pw = pw_before.map(|s| {
        s.parse::<EncString>()
            .unwrap()
            .decrypt_to_string(user_key)
            .unwrap()
    });
    let got = vault::secret(&keys, &sync, &id, Field::Password).unwrap();
    assert_eq!(got.as_deref().map(|s| s.as_str()), expected_pw.as_deref());
    assert!(
        vault::summaries(&keys, &sync)
            .iter()
            .any(|s| s.id == id && !s.name.is_empty())
    );
}

#[test]
fn wrong_password_fails_mac() {
    for path in vector_files() {
        let v = load(&path);
        let master = MasterKey::derive(b"definitely not the password", &v.email, &v.kdf).unwrap();
        let err = Keys::unlock(&master, &v.protected_key, None, None).unwrap_err();
        assert_eq!(err, keyward_core::CryptoError::MacMismatch, "{}", v.file);
    }
}
