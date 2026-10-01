//! System tray. Commands flow out over a plain `std::sync::mpsc` channel so
//! no toolkit types leak into this API.

use std::sync::mpsc::Sender;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    Open,
    Lock,
    Sync,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    LoggedOut,
    Locked,
    Unlocked,
}

pub trait Tray {
    /// Reflect the vault state (icon/tooltip, which items are enabled).
    fn set_state(&self, state: TrayState);
    /// Remove the tray icon.
    fn shutdown(&self);
}

/// StatusNotifierItem tray via `ksni` (KDE, most wlroots bars; GNOME needs the
/// AppIndicator extension).
#[cfg(target_os = "linux")]
pub struct KsniTray {
    handle: ksni::blocking::Handle<SniItem>,
}

#[cfg(target_os = "linux")]
struct SniItem {
    tx: Sender<TrayCommand>,
    state: TrayState,
}

#[cfg(target_os = "linux")]
impl SniItem {
    fn send(&self, c: TrayCommand) {
        // Receiver gone means the frontend is shutting down; nothing to do.
        let _ = self.tx.send(c);
    }
}

#[cfg(target_os = "linux")]
impl ksni::Tray for SniItem {
    fn id(&self) -> String {
        "keyward".into()
    }
    fn title(&self) -> String {
        "keyward".into()
    }
    fn icon_name(&self) -> String {
        match self.state {
            TrayState::Unlocked => "changes-allow-symbolic".into(),
            _ => "changes-prevent-symbolic".into(),
        }
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        let state = match self.state {
            TrayState::LoggedOut => "logged out",
            TrayState::Locked => "locked",
            TrayState::Unlocked => "unlocked",
        };
        ksni::ToolTip {
            title: format!("keyward ({state})"),
            ..Default::default()
        }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(TrayCommand::Open);
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;
        let unlocked = self.state == TrayState::Unlocked;
        vec![
            StandardItem {
                label: "Open".into(),
                activate: Box::new(|t: &mut Self| t.send(TrayCommand::Open)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Lock".into(),
                enabled: unlocked,
                activate: Box::new(|t: &mut Self| t.send(TrayCommand::Lock)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Sync".into(),
                enabled: unlocked,
                activate: Box::new(|t: &mut Self| t.send(TrayCommand::Sync)),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|t: &mut Self| t.send(TrayCommand::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

#[cfg(target_os = "linux")]
impl KsniTray {
    /// Register the tray icon. Fails if there's no session bus or no SNI watcher;
    /// callers should treat that as "no tray" rather than fatal.
    pub fn spawn(tx: Sender<TrayCommand>) -> Result<Self, String> {
        use ksni::blocking::TrayMethods;
        let handle = SniItem {
            tx,
            state: TrayState::LoggedOut,
        }
        .spawn()
        .map_err(|e| e.to_string())?;
        Ok(Self { handle })
    }
}

#[cfg(target_os = "linux")]
impl Tray for KsniTray {
    fn set_state(&self, state: TrayState) {
        self.handle.update(|t| t.state = state);
    }
    fn shutdown(&self) {
        self.handle.shutdown().wait();
    }
}
