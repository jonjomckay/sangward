//! keyward-gtk: Relm4 + GTK4 + libadwaita frontend binary.

use keyward_gtk::{APP_ID, App};
use relm4::RelmApp;
use relm4::adw;
use relm4::gtk::prelude::*;

fn main() {
    // Plain (non-ANSI) logs when not on a terminal or when NO_COLOR is set.
    use std::io::IsTerminal;
    let ansi = std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("KEYWARD_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(ansi)
        .with_target(false)
        .init();
    let app = adw::Application::builder().application_id(APP_ID).build();
    // Keep running while hidden to the tray.
    let _hold = app.hold();
    let relm = RelmApp::from_app(app);
    relm.run::<App>(());
}
