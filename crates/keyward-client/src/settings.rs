//! Frontend settings, persisted as JSON under `$XDG_CONFIG_HOME/keyward/`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Last server base URL, prefilled on the login screen.
    pub server_url: String,
    pub identity_url: Option<String>,
    pub api_url: Option<String>,
    /// Last email, prefilled on the login screen.
    pub email: String,
    /// When the frontend quits: keep the agent (and its unlock state) alive?
    /// Default false = lock and stop the agent.
    pub keep_agent_running: bool,
    /// Clipboard auto-clear delay.
    pub clipboard_clear_secs: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            identity_url: None,
            api_url: None,
            email: String::new(),
            keep_agent_running: false,
            clipboard_clear_secs: crate::DEFAULT_CLEAR_SECS,
        }
    }
}

pub fn config_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return PathBuf::from(d).join("keyward");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config/keyward")
}

impl Settings {
    fn path() -> PathBuf {
        config_dir().join("settings.json")
    }

    /// Load settings; a missing or unreadable file yields defaults.
    pub fn load() -> Self {
        std::fs::read(Self::path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(
            path,
            serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_partial_json() {
        let s: Settings = serde_json::from_str(r#"{"email":"a@b"}"#).unwrap();
        assert_eq!(s.email, "a@b");
        assert!(!s.keep_agent_running);
        assert_eq!(s.clipboard_clear_secs, 30);
    }
}
