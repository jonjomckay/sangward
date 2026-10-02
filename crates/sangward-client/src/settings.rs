//! Frontend settings, persisted as JSON under `$XDG_CONFIG_HOME/sangward/`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Default vault auto-lock timeout (seconds).
pub const DEFAULT_AUTO_LOCK_SECS: u64 = 900;

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
    /// Clipboard auto-clear delay (seconds).
    pub clipboard_clear_secs: u64,
    /// Lock the vault after this many seconds without activity.
    pub auto_lock_secs: u64,
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
            auto_lock_secs: DEFAULT_AUTO_LOCK_SECS,
        }
    }
}

pub fn config_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return PathBuf::from(d).join("sangward");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config/sangward")
}

impl Settings {
    fn path() -> PathBuf {
        config_dir().join("settings.json")
    }

    /// Load settings; a missing or unreadable file yields defaults. Out-of-range
    /// values a previous version (or a hand-edited file) may have left are
    /// clamped back to something safe.
    pub fn load() -> Self {
        let mut s: Self = std::fs::read(Self::path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        s.sanitize();
        s
    }

    /// Replace zero (or otherwise unusable) timeouts with the defaults.
    fn sanitize(&mut self) {
        if self.clipboard_clear_secs == 0 {
            self.clipboard_clear_secs = crate::DEFAULT_CLEAR_SECS;
        }
        if self.auto_lock_secs == 0 {
            self.auto_lock_secs = DEFAULT_AUTO_LOCK_SECS;
        }
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

/// Human-readable whole-second duration for settings labels and toasts:
/// `30 seconds`, `5 minutes`, `1 hour`, `2 hours`.
pub fn format_duration(secs: u64) -> String {
    fn plural(n: u64, unit: &str) -> String {
        if n == 1 {
            format!("1 {unit}")
        } else {
            format!("{n} {unit}s")
        }
    }
    if secs >= 3600 && secs.is_multiple_of(3600) {
        plural(secs / 3600, "hour")
    } else if secs >= 60 && secs.is_multiple_of(60) {
        plural(secs / 60, "minute")
    } else {
        plural(secs, "second")
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
        assert_eq!(s.auto_lock_secs, DEFAULT_AUTO_LOCK_SECS);
    }

    #[test]
    fn sanitize_replaces_zero_timeouts() {
        let mut s = Settings {
            clipboard_clear_secs: 0,
            auto_lock_secs: 0,
            ..Settings::default()
        };
        s.sanitize();
        assert_eq!(s.clipboard_clear_secs, 30);
        assert_eq!(s.auto_lock_secs, DEFAULT_AUTO_LOCK_SECS);
    }

    #[test]
    fn format_duration_is_human_readable() {
        assert_eq!(format_duration(1), "1 second");
        assert_eq!(format_duration(30), "30 seconds");
        assert_eq!(format_duration(60), "1 minute");
        assert_eq!(format_duration(120), "2 minutes");
        assert_eq!(format_duration(900), "15 minutes");
        assert_eq!(format_duration(3600), "1 hour");
        assert_eq!(format_duration(7200), "2 hours");
        assert_eq!(format_duration(90), "90 seconds");
    }
}
