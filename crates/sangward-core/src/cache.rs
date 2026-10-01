//! Encrypted on-disk cache under `$XDG_DATA_HOME/sangward/`.
//!
//! The cache holds only data that is already encrypted by the server-side
//! scheme (protected user key, encrypted private key, raw sync JSON whose
//! secret fields are EncStrings) plus non-secret metadata (server, email, KDF).
//! It is useless without the master password. Directory 0700, files 0600.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::api::Endpoints;
use crate::crypto::Kdf;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("cache is corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub endpoints: Endpoints,
    pub email: String,
    pub kdf: Kdf,
    /// Protected user key: EncString under the stretched master key.
    pub protected_key: String,
    /// EncString of the RSA private key under the user key.
    #[serde(default)]
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheFile {
    pub version: u32,
    pub account: Account,
    /// Raw `/sync` response (secret fields are EncStrings).
    #[serde(default)]
    pub sync: Option<serde_json::Value>,
    #[serde(default)]
    pub last_sync: Option<i64>,
}

pub const CACHE_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct Cache {
    dir: PathBuf,
}

/// `$XDG_DATA_HOME/sangward` (default `~/.local/share/sangward`).
pub fn default_data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("XDG_DATA_HOME").filter(|d| !d.is_empty()) {
        return PathBuf::from(d).join("sangward");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".local/share/sangward")
}

impl Cache {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn file(&self) -> PathBuf {
        self.dir.join("vault.json")
    }

    fn ensure_dir(&self) -> Result<(), CacheError> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)?;
        // Tighten permissions if the directory pre-existed.
        fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    pub fn load(&self) -> Result<Option<CacheFile>, CacheError> {
        let path = self.file();
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Atomic write: temp file (0600) + fsync + rename.
    pub fn store(&self, data: &CacheFile) -> Result<(), CacheError> {
        self.ensure_dir()?;
        let tmp = self.dir.join(".vault.json.tmp");
        let bytes = serde_json::to_vec(data)?;
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.file())?;
        Ok(())
    }

    pub fn clear(&self) -> Result<(), CacheError> {
        match fs::remove_file(self.file()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_load_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = Cache::new(tmp.path().join("kw"));
        assert!(cache.load().unwrap().is_none());
        let data = CacheFile {
            version: CACHE_VERSION,
            account: Account {
                endpoints: Endpoints::resolve("https://x.test", None, None, false).unwrap(),
                email: "a@b".into(),
                kdf: Kdf::Pbkdf2 {
                    iterations: 600_000,
                },
                protected_key: "2.a|b|c".into(),
                private_key: None,
            },
            sync: None,
            last_sync: None,
        };
        cache.store(&data).unwrap();
        let back = cache.load().unwrap().unwrap();
        assert_eq!(back.account.email, "a@b");
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(cache.dir()), 0o700);
        assert_eq!(mode(&cache.dir().join("vault.json")), 0o600);
        cache.clear().unwrap();
        assert!(cache.load().unwrap().is_none());
    }
}
