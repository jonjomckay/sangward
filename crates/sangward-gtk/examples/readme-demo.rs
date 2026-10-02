//! Drive the real GTK app against the seeded throwaway harness and script a
//! short sequence that the wrapper records as the README demo GIF.
//!
//! This is a maintainer tool, not part of the app or the test suite. Run it via
//! `just capture-readme`, which sets up Xvfb, a private D-Bus session, the
//! throwaway Vaultwarden and the agent. It logs in as the seeded PBKDF2 user
//! (all data in the harness is fake) and signals the recorder with a marker
//! file in `$SANGWARD_CAPTURE_DIR`.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use relm4::adw::prelude::*;
use relm4::prelude::*;
use relm4::{adw, gtk};
use sangward_gtk::{App, names};

const LONG: Duration = Duration::from_secs(60);

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} not set (run via `just capture-readme`)"))
}

fn out_dir() -> PathBuf {
    std::env::var("SANGWARD_CAPTURE_DIR")
        .unwrap_or_else(|_| "target/readme".to_string())
        .into()
}

/// Run the GLib main loop until `cond` holds or `timeout` elapses.
fn pump_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let ctx = gtk::glib::MainContext::default();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        while ctx.pending() {
            ctx.iteration(false);
        }
        if cond() {
            return true;
        }
        ctx.iteration(false);
        std::thread::sleep(Duration::from_millis(2));
    }
    cond()
}

/// Let the main loop settle for a while (animations, idle handlers).
fn pump_for(d: Duration) {
    pump_until(d, || false);
}

fn find(root: &impl IsA<gtk::Widget>, name: &str) -> Option<gtk::Widget> {
    let root = root.as_ref();
    if root.widget_name() == name {
        return Some(root.clone());
    }
    let mut child = root.first_child();
    while let Some(c) = child {
        if let Some(found) = find(&c, name) {
            return Some(found);
        }
        child = c.next_sibling();
    }
    None
}

/// The same in-process harness the UI tests use: launch the real `App` and
/// drive it by widget name.
struct Ui {
    window: adw::ApplicationWindow,
    _controller: relm4::Controller<App>,
}

impl Ui {
    fn launch() -> Self {
        let controller = App::builder().launch(()).detach();
        let window = controller.widget().clone();
        Ui {
            window,
            _controller: controller,
        }
    }

    fn get<T: IsA<gtk::Widget>>(&self, name: &str) -> T {
        find(&self.window, name)
            .unwrap_or_else(|| panic!("widget {name:?} not found"))
            .downcast::<T>()
            .unwrap_or_else(|w| panic!("widget {name:?} has type {}", w.type_().name()))
    }

    fn screen(&self) -> String {
        self.get::<gtk::Stack>(names::SCREENS)
            .visible_child_name()
            .map(|s| s.to_string())
            .unwrap_or_default()
    }

    fn wait_screen(&self, want: &str, timeout: Duration) {
        assert!(
            pump_until(timeout, || self.screen() == want),
            "expected screen {want:?}, still on {:?}",
            self.screen()
        );
    }

    fn type_into(&self, name: &str, text: &str) {
        self.get::<gtk::Editable>(name).set_text(text);
    }

    fn click(&self, name: &str) {
        self.get::<gtk::Button>(name).emit_clicked();
    }

    fn list_len(&self) -> usize {
        let list = self.get::<gtk::Widget>(names::LIST);
        if let Some(lv) = list.downcast_ref::<gtk::ListView>() {
            return lv.model().map(|m| m.n_items() as usize).unwrap_or(0);
        }
        let mut n = 0;
        let mut c = list.first_child();
        while let Some(w) = c {
            n += 1;
            c = w.next_sibling();
        }
        n
    }

    /// Select the row whose item name matches, regardless of vault order.
    fn select_named(&self, name: &str) {
        let list = self.get::<gtk::Widget>(names::LIST);
        let lv = list
            .downcast::<gtk::ListView>()
            .expect("vault list is a ListView");
        let sel = lv
            .model()
            .and_then(|m| m.downcast::<gtk::SingleSelection>().ok())
            .expect("SingleSelection model");
        for i in 0..sel.n_items() {
            let Some(obj) = sel.item(i).and_downcast::<gtk::glib::BoxedAnyObject>() else {
                continue;
            };
            if obj.borrow::<sangward_ipc::ItemSummary>().name == name {
                sel.set_selected(i);
                return;
            }
        }
        panic!("no vault item named {name:?}");
    }

    fn title(&self) -> String {
        self.get::<gtk::Label>(names::DETAIL_TITLE)
            .label()
            .to_string()
    }
}

fn main() {
    gtk::init().expect("gtk init (is DISPLAY set?)");
    adw::init().expect("adw init");

    let dir = out_dir();
    std::fs::create_dir_all(&dir).expect("create capture dir");

    let ui = Ui::launch();
    ui.wait_screen("login", Duration::from_secs(20));
    ui.type_into(names::SERVER, &env("SW_VW_URL"));
    ui.type_into(names::EMAIL, &env("SW_TEST_USER1_EMAIL"));
    ui.type_into(names::PASSWORD, &env("SW_TEST_USER1_PASSWORD"));
    ui.click(names::LOGIN);
    assert!(
        pump_until(LONG, || ui.screen() == "vault"),
        "never reached the vault"
    );
    assert!(pump_until(LONG, || ui.list_len() > 0), "vault is empty");

    // Signal the wrapper (it waits for this file), then animate for the GIF.
    std::fs::write(dir.join("ready"), b"").expect("write ready marker");

    // Apply search changes immediately. The default 150 ms `search-delay`
    // debounce is invisible when a human types fluently, but the demo pauses
    // between keystrokes, so it would let the unfiltered list flash back in.
    ui.get::<gtk::SearchEntry>(names::SEARCH)
        .set_property("search-delay", 0u32);
    demo(&ui);

    // Let the recorder catch the tail before the window goes away.
    pump_for(Duration::from_millis(700));
}

/// The recorded sequence: filter the list by typing, select the result, reveal
/// the password, then lock the vault.
fn demo(ui: &Ui) {
    ui.type_into(names::SEARCH, "");
    pump_for(Duration::from_millis(800));

    let mut query = String::new();
    for ch in "github".chars() {
        query.push(ch);
        ui.get::<gtk::SearchEntry>(names::SEARCH).set_text(&query);
        pump_for(Duration::from_millis(320));
    }
    assert!(
        pump_until(Duration::from_secs(5), || ui.list_len() == 1),
        "search did not narrow to one item"
    );

    ui.select_named("GitHub");
    assert!(
        pump_until(Duration::from_secs(5), || ui.title() == "GitHub"),
        "detail did not show GitHub"
    );
    pump_for(Duration::from_millis(1500));

    ui.click(names::REVEAL);
    pump_for(Duration::from_millis(1600));
    ui.click(names::REVEAL);
    pump_for(Duration::from_millis(700));

    ui.click(names::LOCK);
    let _ = pump_until(Duration::from_secs(5), || ui.screen() == "unlock");
    pump_for(Duration::from_millis(1200));
}
