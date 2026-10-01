//! keyward-client: toolkit-agnostic frontend logic.
//!
//! Everything a frontend needs that isn't pixels lives here: the app state
//! machine, search filtering, clipboard auto-clear scheduling, settings, and
//! finding/spawning the agent. It depends only on `keyward-ipc`, so a Slint or
//! Qt frontend reuses all of it and only reimplements rendering.

pub mod clipboard;
pub mod settings;
pub mod spawn;

use keyward_ipc::{
    Client, ErrorKind, IpcError, ItemKind, ItemSummary, LockState, Request, Response, SecretField,
    Sensitive, ServerConfig, StatusInfo,
};

pub use clipboard::{AutoClear, DEFAULT_CLEAR_SECS};
pub use settings::Settings;

/// Frontend-visible application state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Agent not reachable yet.
    Connecting,
    LoggedOut,
    /// Login submitted; server asked for an authenticator code.
    AwaitingTotp,
    Locked,
    Unlocked,
    Syncing,
}

impl From<LockState> for AppState {
    fn from(s: LockState) -> Self {
        match s {
            LockState::LoggedOut => AppState::LoggedOut,
            LockState::Locked => AppState::Locked,
            LockState::Unlocked => AppState::Unlocked,
        }
    }
}

/// Outcome of a login attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    Success,
    NeedsTotp,
}

/// User-facing error with a stable category for the UI to branch on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiError {
    pub kind: Option<ErrorKind>,
    pub message: String,
}

impl std::fmt::Display for UiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UiError {}

impl From<IpcError> for UiError {
    fn from(e: IpcError) -> Self {
        let kind = e.kind();
        let message = match (&e, kind) {
            (IpcError::Io(_), _) => "cannot reach keyward-agent".to_owned(),
            (_, Some(ErrorKind::InvalidCredentials)) => "Invalid master password".to_owned(),
            (_, Some(ErrorKind::InvalidTwoFactor)) => "Invalid two-factor code".to_owned(),
            (_, Some(ErrorKind::Locked)) => "Vault is locked".to_owned(),
            (_, Some(ErrorKind::LoggedOut)) => "Not logged in".to_owned(),
            _ => e.to_string(),
        };
        UiError { kind, message }
    }
}

/// Thin async facade over the IPC client used by every frontend.
#[derive(Debug, Clone)]
pub struct Controller {
    client: Client,
}

impl Controller {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn status(&self) -> Result<StatusInfo, UiError> {
        Ok(self.client.status().await?)
    }

    pub async fn login(
        &self,
        server: ServerConfig,
        email: &str,
        password: Sensitive,
        totp: Option<Sensitive>,
    ) -> Result<LoginOutcome, UiError> {
        let req = Request::Login {
            server,
            email: email.to_owned(),
            password,
            totp,
        };
        match self.client.call(&req).await? {
            Response::Ok => Ok(LoginOutcome::Success),
            Response::TwoFactorRequired { .. } => Ok(LoginOutcome::NeedsTotp),
            other => Err(UiError {
                kind: None,
                message: format!("unexpected response {:?}", std::mem::discriminant(&other)),
            }),
        }
    }

    pub async fn unlock(&self, password: Sensitive) -> Result<(), UiError> {
        Ok(self.client.simple(&Request::Unlock { password }).await?)
    }
    pub async fn lock(&self) -> Result<(), UiError> {
        Ok(self.client.simple(&Request::Lock).await?)
    }
    pub async fn logout(&self) -> Result<(), UiError> {
        Ok(self.client.simple(&Request::Logout).await?)
    }
    pub async fn sync(&self) -> Result<(), UiError> {
        Ok(self.client.simple(&Request::Sync).await?)
    }
    pub async fn shutdown_agent(&self) -> Result<(), UiError> {
        Ok(self.client.simple(&Request::Shutdown).await?)
    }
    pub async fn set_auto_lock(&self, seconds: u64) -> Result<(), UiError> {
        Ok(self
            .client
            .simple(&Request::SetAutoLock { seconds })
            .await?)
    }
    pub async fn list(&self) -> Result<Vec<ItemSummary>, UiError> {
        Ok(self.client.list().await?)
    }
    pub async fn secret(&self, id: &str, field: SecretField) -> Result<Option<Sensitive>, UiError> {
        Ok(self.client.get_secret(id, field).await?)
    }
    pub async fn totp(&self, id: &str) -> Result<(Sensitive, u64), UiError> {
        Ok(self.client.totp(id).await?)
    }
}

/// What the user can copy from an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyTarget {
    Username,
    Password,
    Totp,
}

impl CopyTarget {
    pub fn label(self) -> &'static str {
        match self {
            CopyTarget::Username => "Username",
            CopyTarget::Password => "Password",
            CopyTarget::Totp => "TOTP code",
        }
    }
}

impl Controller {
    /// Resolve the value to place on the clipboard. Secrets are fetched per request.
    pub async fn copy_value(
        &self,
        item: &ItemSummary,
        target: CopyTarget,
    ) -> Result<Sensitive, UiError> {
        let missing = |what: &str| UiError {
            kind: Some(ErrorKind::NotFound),
            message: format!("item has no {what}"),
        };
        match target {
            CopyTarget::Username => item
                .username
                .clone()
                .map(Sensitive::new)
                .ok_or_else(|| missing("username")),
            CopyTarget::Password => self
                .secret(&item.id, SecretField::Password)
                .await?
                .ok_or_else(|| missing("password")),
            CopyTarget::Totp => Ok(self.totp(&item.id).await?.0),
        }
    }
}

/// Pure view-model for the vault list: items + query -> filtered view + selection.
#[derive(Debug, Default, Clone)]
pub struct VaultModel {
    items: Vec<ItemSummary>,
    query: String,
    filtered: Vec<usize>,
    selected: Option<String>,
    /// Bumped whenever the item set changes, so frontends with retained models
    /// (e.g. a GTK ListStore) know when to repopulate instead of diffing.
    generation: u64,
}

impl VaultModel {
    pub fn set_items(&mut self, items: Vec<ItemSummary>) {
        self.items = items;
        self.generation = self.generation.wrapping_add(1);
        self.refilter();
        if let Some(sel) = &self.selected
            && !self.items.iter().any(|i| &i.id == sel)
        {
            self.selected = None;
        }
    }

    pub fn clear(&mut self) {
        let generation = self.generation.wrapping_add(1);
        *self = Self {
            generation,
            ..Self::default()
        };
    }

    /// Changes whenever the item set changes (not on query/selection changes).
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn items(&self) -> &[ItemSummary] {
        &self.items
    }

    pub fn set_query(&mut self, q: &str) {
        self.query = q.to_owned();
        self.refilter();
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn visible(&self) -> impl Iterator<Item = &ItemSummary> {
        self.filtered.iter().map(|&i| &self.items[i])
    }

    pub fn visible_len(&self) -> usize {
        self.filtered.len()
    }

    pub fn all_len(&self) -> usize {
        self.items.len()
    }

    pub fn select(&mut self, id: Option<&str>) {
        self.selected = id
            .filter(|id| self.items.iter().any(|i| i.id == *id))
            .map(str::to_owned);
    }

    pub fn selected(&self) -> Option<&ItemSummary> {
        let id = self.selected.as_deref()?;
        self.items.iter().find(|i| i.id == id)
    }

    fn refilter(&mut self) {
        self.filtered = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, i)| matches(i, &self.query))
            .map(|(n, _)| n)
            .collect();
    }
}

/// Case-insensitive, whitespace-separated AND match over name, username and host.
pub fn matches(item: &ItemSummary, query: &str) -> bool {
    let hay = format!(
        "{} {} {}",
        item.name.to_lowercase(),
        item.username.as_deref().unwrap_or("").to_lowercase(),
        item.uri_host.as_deref().unwrap_or("").to_lowercase()
    );
    query
        .split_whitespace()
        .all(|term| hay.contains(&term.to_lowercase()))
}

pub fn kind_label(k: ItemKind) -> &'static str {
    match k {
        ItemKind::Login => "Login",
        ItemKind::SecureNote => "Secure note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, name: &str, user: Option<&str>, host: Option<&str>) -> ItemSummary {
        ItemSummary {
            id: id.into(),
            kind: ItemKind::Login,
            name: name.into(),
            username: user.map(Into::into),
            uri_host: host.map(Into::into),
            has_password: true,
            has_totp: false,
            has_notes: false,
            organization_id: None,
        }
    }

    #[test]
    fn search_filters_case_insensitively_across_fields() {
        let mut m = VaultModel::default();
        m.set_items(vec![
            item("1", "GitHub", Some("octo"), Some("github.com")),
            item(
                "2",
                "Bank Ünïcode 日本",
                Some("alice"),
                Some("bank.example"),
            ),
            item("3", "Email", None, None),
        ]);
        m.set_query("git");
        assert_eq!(
            m.visible().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            ["1"]
        );
        m.set_query("ALICE bank");
        assert_eq!(
            m.visible().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            ["2"]
        );
        m.set_query("ünï");
        assert_eq!(m.visible_len(), 1);
        m.set_query("日本");
        assert_eq!(m.visible_len(), 1);
        m.set_query("");
        assert_eq!(m.visible_len(), 3);
        m.set_query("nomatch");
        assert_eq!(m.visible_len(), 0);
    }

    #[test]
    fn generation_tracks_item_set_only() {
        let mut m = VaultModel::default();
        let g0 = m.generation();
        m.set_items(vec![item("1", "a", None, None)]);
        let g1 = m.generation();
        assert_ne!(g0, g1);
        m.set_query("a");
        m.select(Some("1"));
        assert_eq!(
            m.generation(),
            g1,
            "query/selection must not bump generation"
        );
        m.clear();
        assert_ne!(m.generation(), g1);
        assert_eq!(m.all_len(), 0);
    }

    /// 10k items: filtering must stay well under a frame so search can run per keystroke.
    #[test]
    fn filtering_large_vault_is_fast() {
        let items: Vec<_> = (0..10_000)
            .map(|i| {
                item(
                    &i.to_string(),
                    &format!("Site {i} ünïcode"),
                    Some(&format!("user{i}@example.test")),
                    Some("host.example.com"),
                )
            })
            .collect();
        let mut m = VaultModel::default();
        m.set_items(items);
        let t = std::time::Instant::now();
        for q in ["s", "si", "site", "site 4", "site 42", "site 424", ""] {
            m.set_query(q);
        }
        let per_query = t.elapsed() / 7;
        assert!(m.visible_len() == 10_000);
        // Generous for debug builds on slow CI; release is ~1 ms.
        assert!(
            per_query < std::time::Duration::from_millis(50),
            "filtering took {per_query:?} per query"
        );
    }

    #[test]
    fn selection_survives_refresh_only_if_item_exists() {
        let mut m = VaultModel::default();
        m.set_items(vec![item("1", "a", None, None), item("2", "b", None, None)]);
        m.select(Some("2"));
        assert_eq!(m.selected().unwrap().id, "2");
        m.set_items(vec![item("1", "a", None, None)]);
        assert!(m.selected().is_none());
        m.select(Some("missing"));
        assert!(m.selected().is_none());
    }

    #[test]
    fn ui_error_mapping() {
        let e: UiError = IpcError::Agent {
            kind: ErrorKind::InvalidCredentials,
            message: "x".into(),
        }
        .into();
        assert_eq!(e.message, "Invalid master password");
        assert_eq!(AppState::from(LockState::Locked), AppState::Locked);
    }
}
