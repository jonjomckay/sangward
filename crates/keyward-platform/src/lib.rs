//! Platform abstractions shared by the agent and frontends.
//!
//! Every trait here is toolkit-agnostic: no GTK/Relm4 types appear in any
//! signature, so a Qt or Slint frontend can reuse the same implementations.

pub mod clipboard;
pub mod secret_store;
pub mod tray;

pub use clipboard::{Clipboard, ClipboardError, CopyToken};
pub use secret_store::{InMemorySecretStore, SecretStore, SecretStoreError, StoredCredentials};
pub use tray::{Tray, TrayCommand, TrayState};

#[cfg(target_os = "linux")]
pub use clipboard::ArboardClipboard;
#[cfg(target_os = "linux")]
pub use secret_store::Oo7SecretStore;
#[cfg(target_os = "linux")]
pub use tray::KsniTray;
