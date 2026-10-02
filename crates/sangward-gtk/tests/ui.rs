//! In-process GTK UI tests.
//!
//! Pattern: launch the *real* `App` component inside this test process (under
//! Xvfb + a private D-Bus, see `scripts/gtk-ui-test.sh`), find widgets by their
//! stable names (`sangward_gtk::names`), drive them like a user would
//! (`set_text`, `emit_clicked`, row selection), and pump the GLib main loop
//! ourselves until a condition holds.
//!
//! Responsiveness: a 16 ms heartbeat timer runs on the main loop while each
//! scenario executes. The largest gap between heartbeats is the longest the UI
//! thread was blocked. Each scenario asserts it stays under
//! `SW_UI_MAX_STALL_MS`, which turns "the UI freezes with thousands of items"
//! into a failing test.
//!
//! `harness = false`: GTK must own the process's main thread, which libtest's
//! worker threads can't provide.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant};

use relm4::adw::prelude::*;
use relm4::prelude::*;
use relm4::{adw, gtk};
use sangward_gtk::{App, Msg, names};

// --------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------

struct Ui {
    window: adw::ApplicationWindow,
    controller: relm4::Controller<App>,
    stall: Rc<StallMeter>,
}

/// Records the largest gap between heartbeat ticks on the main loop.
struct StallMeter {
    last: Cell<Instant>,
    worst: Cell<Duration>,
}

impl StallMeter {
    fn start() -> Rc<Self> {
        let m = Rc::new(Self {
            last: Cell::new(Instant::now()),
            worst: Cell::new(Duration::ZERO),
        });
        let mm = m.clone();
        gtk::glib::timeout_add_local(Duration::from_millis(16), move || {
            let now = Instant::now();
            let gap = now - mm.last.replace(now);
            if gap > mm.worst.get() {
                mm.worst.set(gap);
            }
            gtk::glib::ControlFlow::Continue
        });
        m
    }
    /// Begin a new measurement window.
    fn reset(&self) {
        self.last.set(Instant::now());
        self.worst.set(Duration::ZERO);
    }
    fn worst(&self) -> Duration {
        self.worst.get()
    }
}

/// Run the main loop until `cond` is true or `timeout` elapses.
fn pump_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let ctx = gtk::glib::MainContext::default();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        // Non-blocking iteration, then a short sleep so we don't spin a core.
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

/// Whether `widget` is `ancestor` or inside it.
fn is_descendant_of(widget: &gtk::Widget, ancestor: &gtk::Widget) -> bool {
    if widget == ancestor {
        return true;
    }
    let mut p = widget.parent();
    while let Some(w) = p {
        if &w == ancestor {
            return true;
        }
        p = w.parent();
    }
    false
}

impl Ui {
    fn launch() -> Self {
        let controller = App::builder().launch(()).detach();
        let window = controller.widget().clone();
        let stall = StallMeter::start();
        Ui {
            window,
            controller,
            stall,
        }
    }

    /// Send a component message (e.g. the tray's Open command).
    fn send(&self, msg: Msg) {
        self.controller.sender().send(msg).unwrap();
    }

    /// Move focus away from `name`, as a user tabbing to another row would.
    fn focus_widget(&self, name: &str) {
        self.get::<gtk::Widget>(name).grab_focus();
        pump_for(Duration::from_millis(50));
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
        let ok = pump_until(timeout, || self.screen() == want);
        assert!(ok, "expected screen {want:?}, still on {:?}", self.screen());
    }

    fn type_into(&self, name: &str, text: &str) {
        self.get::<gtk::Editable>(name).set_text(text);
    }

    /// Whether keyboard focus is on the entry *inside* `name`. An
    /// `AdwEntryRow`/`AdwPasswordEntryRow` is a composite whose real focusable
    /// widget is an inner `GtkText`. Setting focus on the row alone leaves that
    /// entry unfocused (no cursor, typing goes nowhere), so this requires a
    /// strict descendant that actually has keyboard focus — not the row itself.
    fn has_keyboard_focus(&self, name: &str) -> bool {
        let want = self.get::<gtk::Widget>(name);
        let Some(focused) = gtk::prelude::RootExt::focus(&self.window) else {
            return false;
        };
        focused != want && focused.has_focus() && is_descendant_of(&focused, &want)
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

    /// Select the visible row at `pos`.
    fn select_row(&self, pos: u32) {
        let list = self.get::<gtk::Widget>(names::LIST);
        if let Some(lv) = list.downcast_ref::<gtk::ListView>() {
            let sel = lv
                .model()
                .and_then(|m| m.downcast::<gtk::SingleSelection>().ok())
                .expect("SingleSelection model");
            sel.set_selected(pos);
        } else if let Some(lb) = list.downcast_ref::<gtk::ListBox>() {
            lb.select_row(lb.row_at_index(pos as i32).as_ref());
        } else {
            panic!("unexpected list widget type {}", list.type_().name());
        }
    }

    /// Click a form's submit button and follow it to the vault, checking the
    /// in-between feedback: spinner + busy label on the button, inputs locked,
    /// and the vault appearing only once its list is populated (never an empty
    /// vault flashing first). Returns the busy labels seen, in order.
    fn submit_to_vault(&self, button: &str, inputs: &[&str], want_rows: usize) -> Vec<String> {
        let spinner = self.get::<gtk::Spinner>(&format!("{button}-spinner"));
        let label = self.get::<gtk::Label>(&format!("{button}-label"));
        let start_screen = self.screen();
        let idle = label.label().to_string();
        self.click(button);
        let mut seen: Vec<String> = Vec::new();
        let ok = pump_until(LONG, || {
            if self.screen() == "vault" {
                return true;
            }
            assert_eq!(
                self.screen(),
                start_screen,
                "left the form before the vault was ready"
            );
            if spinner.is_visible() {
                assert!(spinner.is_spinning(), "spinner visible but not spinning");
                assert!(
                    !self.get::<gtk::Button>(button).is_sensitive(),
                    "button clickable while busy"
                );
                for i in inputs {
                    assert!(
                        !self.get::<gtk::Widget>(i).is_sensitive(),
                        "{i} editable while busy"
                    );
                }
                let l = label.label().to_string();
                if seen.last() != Some(&l) {
                    seen.push(l);
                }
            }
            false
        });
        assert!(ok, "never reached the vault");
        assert_eq!(
            self.list_len(),
            want_rows,
            "vault shown before its items were loaded"
        );
        assert!(
            !seen.is_empty(),
            "no progress shown on {button} while working"
        );
        assert!(
            !spinner.is_visible() && label.label() == idle,
            "{button} not reset after success"
        );
        seen
    }

    /// Run a step and return the worst main-loop stall seen while it ran.
    fn measure(&self, step: impl FnOnce()) -> Duration {
        self.stall.reset();
        step();
        self.stall.worst()
    }
}

fn env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} not set (run via scripts/gtk-ui-test.sh)"))
}

/// Write a settings file so the next `App` launch looks like a returning user.
fn prefill_login(email: &str) {
    let dir = std::path::PathBuf::from(env("XDG_CONFIG_HOME")).join("sangward");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("settings.json"),
        format!(r#"{{"email":"{email}"}}"#),
    )
    .unwrap();
}

fn max_stall() -> Duration {
    Duration::from_millis(
        std::env::var("SW_UI_MAX_STALL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(150),
    )
}

thread_local! {
    static STALL_FAILURES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Record (not panic on) a stall-budget violation, so one run reports every phase.
fn assert_responsive(what: &str, stall: Duration) {
    let budget = max_stall();
    let verdict = if stall <= budget { "ok" } else { "FROZE" };
    println!(
        "    {verdict:5} {what}: worst main-loop stall {} ms (budget {} ms)",
        stall.as_millis(),
        budget.as_millis()
    );
    if stall > budget {
        STALL_FAILURES.with(|f| {
            f.borrow_mut()
                .push(format!("{what}: {} ms", stall.as_millis()))
        });
    }
}

// --------------------------------------------------------------------------
// Scenarios
// --------------------------------------------------------------------------

const LONG: Duration = Duration::from_secs(60);

/// Searchable text of large-vault login `i`, mirroring scripts/seed-large.sh.
fn large_hay(i: usize) -> String {
    const W: [&str; 16] = [
        "alpha",
        "bravo",
        "charlie",
        "delta",
        "echo",
        "foxtrot",
        "golf",
        "hotel",
        "india",
        "juliett",
        "kilo",
        "lima",
        "mike",
        "ünïcode",
        "日本",
        "🦀",
    ];
    format!(
        "site {i} {} {} user{i}@example.test host{}.example.com",
        W[i % 16],
        W[(i / 16) % 16],
        i % 500
    )
    .to_lowercase()
}

/// Login screen -> vault for a small account; search, select, reveal, copy, lock, unlock.
fn small_vault_flow() {
    let ui = Ui::launch();
    ui.wait_screen("login", Duration::from_secs(15));

    ui.type_into(names::SERVER, &env("SW_VW_URL"));
    ui.type_into(names::EMAIL, &env("SW_TEST_USER1_EMAIL"));
    ui.type_into(names::PASSWORD, "definitely-wrong");
    ui.click(names::LOGIN);
    let err = ui.get::<gtk::Label>(names::ERROR_LOGIN);
    assert!(
        pump_until(LONG, || err.is_visible()),
        "no error shown for wrong password"
    );
    assert!(
        err.label().contains("Invalid"),
        "unexpected error text {:?}",
        err.label()
    );
    assert_eq!(ui.screen(), "login");
    // After a failure the form is usable again, the typed password is kept
    // (selected, so typing replaces it) and the button is back to idle.
    let pw = ui.get::<gtk::Editable>(names::PASSWORD);
    assert_eq!(
        pw.text(),
        "definitely-wrong",
        "password cleared after a failed login"
    );
    assert!(pw.is_sensitive() && ui.get::<gtk::Button>(names::LOGIN).is_sensitive());

    ui.type_into(names::PASSWORD, &env("SW_TEST_USER1_PASSWORD"));
    let seen = ui.submit_to_vault(
        names::LOGIN,
        &[names::SERVER, names::EMAIL, names::PASSWORD],
        5,
    );
    println!("    login progress: {seen:?}");
    assert_eq!(seen.first().map(String::as_str), Some("Logging in…"));
    assert_eq!(
        ui.get::<gtk::Editable>(names::PASSWORD).text(),
        "",
        "password left in the login form"
    );

    ui.type_into(names::SEARCH, "github");
    assert!(
        pump_until(Duration::from_secs(5), || ui.list_len() == 1),
        "search: got {} rows",
        ui.list_len()
    );
    ui.select_row(0);
    let title = ui.get::<gtk::Label>(names::DETAIL_TITLE);
    assert!(
        pump_until(Duration::from_secs(5), || title.label() == "GitHub"),
        "detail shows {:?}",
        title.label()
    );
    let user_row = ui.get::<adw::ActionRow>(names::DETAIL_USERNAME);
    assert_eq!(user_row.subtitle().as_deref(), Some("octocat"));

    // Reveal fetches the secret from the agent on demand.
    let pw_row = ui.get::<adw::ActionRow>(names::DETAIL_PASSWORD);
    assert_eq!(pw_row.subtitle().as_deref(), Some("••••••••"));
    ui.click(names::REVEAL);
    assert!(
        pump_until(Duration::from_secs(5), || pw_row.subtitle().as_deref()
            == Some("gh-Pa55-wörd!")),
        "reveal failed"
    );
    ui.click(names::REVEAL);
    assert!(
        pump_until(Duration::from_secs(5), || pw_row.subtitle().as_deref()
            == Some("••••••••")),
        "hide failed"
    );

    // Copy goes through gdk::Clipboard; read it back from this process.
    ui.click(names::COPY_PASSWORD);
    let clip = gtk::gdk::Display::default().unwrap().clipboard();
    let got: Rc<RefCell<Option<String>>> = Rc::default();
    assert!(pump_until(Duration::from_secs(5), || {
        let g = got.clone();
        clip.read_text_async(None::<&gtk::gio::Cancellable>, move |r| {
            *g.borrow_mut() = r.ok().flatten().map(|s| s.to_string());
        });
        pump_for(Duration::from_millis(50));
        got.borrow().as_deref() == Some("gh-Pa55-wörd!")
    }));
    let formats = clip.formats();
    assert!(
        formats.contain_mime_type("x-kde-passwordManagerHint"),
        "password-manager hint missing: {formats}"
    );

    // Preferences: opening the dialog, changing both timeouts, and having them
    // persisted (and the auto-lock pushed to the running agent).
    ui.click(names::SETTINGS);
    assert!(
        pump_until(Duration::from_secs(5), || ui
            .window
            .visible_dialog()
            .is_some()),
        "preferences dialog did not open"
    );
    let dialog = ui.window.visible_dialog().expect("visible dialog");
    let combo = |name: &str| -> adw::ComboRow {
        find(&dialog, name)
            .unwrap_or_else(|| panic!("preferences row {name:?} not found"))
            .downcast::<adw::ComboRow>()
            .unwrap_or_else(|w| panic!("preferences row {name:?} is {}", w.type_().name()))
    };
    combo(names::CLIPBOARD_CLEAR).set_selected(0); // 10 seconds
    combo(names::AUTO_LOCK).set_selected(1); // 5 minutes
    let settings_path =
        std::path::PathBuf::from(env("XDG_CONFIG_HOME")).join("sangward/settings.json");
    assert!(
        pump_until(Duration::from_secs(5), || {
            std::fs::read_to_string(&settings_path).is_ok_and(|s| {
                s.contains("\"clipboard_clear_secs\": 10") && s.contains("\"auto_lock_secs\": 300")
            })
        }),
        "preferences not persisted: {:?}",
        std::fs::read_to_string(&settings_path)
    );
    // Poll the agent on a worker thread: the main thread owns the GTK loop.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let ctl = sangward_ipc::Client::new(sangward_ipc::default_socket_path());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for _ in 0..50 {
            let secs = rt.block_on(ctl.status()).ok().map(|s| s.auto_lock_seconds);
            if tx.send(secs).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    assert!(
        pump_until(Duration::from_secs(6), || {
            rx.try_recv().ok().flatten() == Some(300)
        }),
        "agent did not apply the new auto-lock timeout"
    );
    dialog.close();

    // Lock clears the list and the clipboard; unlock with password only.
    ui.click(names::LOCK);
    ui.wait_screen("unlock", Duration::from_secs(10));
    // The unlock field is focused on show so a returning user can type at once.
    assert!(
        pump_until(Duration::from_secs(3), || ui
            .has_keyboard_focus(names::UNLOCK_PASSWORD)),
        "unlock password field was not auto-focused"
    );
    assert_eq!(ui.list_len(), 0, "list not cleared on lock");
    assert!(
        pump_until(Duration::from_secs(2), || clip.content().is_none()),
        "clipboard not cleared on lock"
    );
    ui.type_into(names::UNLOCK_PASSWORD, "wrong");
    ui.click(names::UNLOCK);
    let uerr = ui.get::<gtk::Label>(names::ERROR_UNLOCK);
    assert!(
        pump_until(LONG, || uerr.is_visible()),
        "no unlock error shown"
    );
    assert_eq!(
        ui.get::<gtk::Editable>(names::UNLOCK_PASSWORD).text(),
        "wrong",
        "password cleared after failed unlock"
    );
    ui.type_into(names::UNLOCK_PASSWORD, &env("SW_TEST_USER1_PASSWORD"));
    let seen = ui.submit_to_vault(names::UNLOCK, &[names::UNLOCK_PASSWORD], 5);
    println!("    unlock progress: {seen:?}");
    assert_eq!(seen.first().map(String::as_str), Some("Unlocking…"));
    ui.window.close();
}

/// The vault with thousands of items must never freeze the main loop:
/// not while loading after unlock, not while searching, not while selecting.
fn large_vault_stays_responsive() {
    let n: usize = env("SW_LARGE_VAULT_ITEMS").parse().unwrap();
    let ui = Ui::launch();
    ui.wait_screen("login", Duration::from_secs(15));
    ui.type_into(names::SERVER, &env("SW_VW_URL"));
    ui.type_into(names::EMAIL, &env("SW_TEST_USER3_EMAIL"));
    ui.type_into(names::PASSWORD, &env("SW_TEST_USER3_PASSWORD"));

    let s = ui.measure(|| {
        let seen = ui.submit_to_vault(
            names::LOGIN,
            &[names::SERVER, names::EMAIL, names::PASSWORD],
            n,
        );
        println!("    login progress: {seen:?}");
        pump_for(Duration::from_millis(300));
    });
    assert_responsive(&format!("login + sync + render {n} items"), s);

    // Type a query one keystroke at a time, like a user.
    let s = ui.measure(|| {
        let search = ui.get::<gtk::SearchEntry>(names::SEARCH);
        let mut q = String::new();
        for ch in "site 42".chars() {
            q.push(ch);
            search.set_text(&q);
            pump_for(Duration::from_millis(40));
        }
        // Same AND-of-terms rule as sangward_client::matches over name, username and host,
        // using the generator in scripts/seed-large.sh (every 10th item is a note).
        let want = (0..n)
            .filter(|&i| {
                i % 10 != 9 && large_hay(i).contains("site") && large_hay(i).contains("42")
            })
            .count();
        assert!(
            pump_until(Duration::from_secs(10), || ui.list_len() == want),
            "search rows {} (want {want})",
            ui.list_len()
        );
    });
    assert_responsive("incremental search", s);

    let s = ui.measure(|| {
        ui.get::<gtk::SearchEntry>(names::SEARCH).set_text("");
        assert!(
            pump_until(Duration::from_secs(10), || ui.list_len() == n),
            "clearing search: {}",
            ui.list_len()
        );
        pump_for(Duration::from_millis(200));
    });
    assert_responsive("clear search (all items back)", s);

    let s = ui.measure(|| {
        ui.get::<gtk::SearchEntry>(names::SEARCH).set_text("4242");
        assert!(pump_until(Duration::from_secs(10), || ui.list_len() == 1));
        ui.select_row(0);
        let title = ui.get::<gtk::Label>(names::DETAIL_TITLE);
        assert!(
            pump_until(Duration::from_secs(5), || title.label()
                == "Site 4242 charlie juliett"),
            "detail {:?}",
            title.label()
        );
    });
    assert_responsive("search + select", s);

    // Lock and unlock: the agent decrypts thousands of names again.
    let s = ui.measure(|| {
        ui.click(names::LOCK);
        ui.wait_screen("unlock", Duration::from_secs(10));
        ui.type_into(names::UNLOCK_PASSWORD, &env("SW_TEST_USER3_PASSWORD"));
        let seen = ui.submit_to_vault(names::UNLOCK, &[names::UNLOCK_PASSWORD], n);
        println!("    unlock progress: {seen:?}");
        pump_for(Duration::from_millis(300));
    });
    assert_responsive("lock + unlock + reload", s);
    ui.window.close();
}

/// A returning user (saved email) lands on the login screen with the master
/// password field already focused, so they can type without reaching for the mouse.
fn returning_user_login_autofocus() {
    prefill_login(&env("SW_TEST_USER1_EMAIL"));
    let ui = Ui::launch();
    ui.wait_screen("login", Duration::from_secs(15));
    assert!(
        pump_until(Duration::from_secs(3), || ui
            .has_keyboard_focus(names::PASSWORD)),
        "master password field was not auto-focused for a returning user"
    );
    // Reopening (the tray's Open command) brings focus back to the field even
    // if the user had tabbed elsewhere before the window was hidden.
    ui.focus_widget(names::SERVER);
    assert!(!ui.has_keyboard_focus(names::PASSWORD));
    ui.send(Msg::ShowWindow);
    assert!(
        pump_until(Duration::from_secs(3), || ui
            .has_keyboard_focus(names::PASSWORD)),
        "master password field was not re-focused when the window reopened"
    );
    ui.window.close();
}

fn main() {
    // Each scenario gets a fresh agent: the wrapper script points SANGWARD_SOCKET
    // etc. at per-run temp dirs and stops the agent between scenarios.
    let only = std::env::args().nth(1).filter(|a| !a.starts_with('-'));
    gtk::init().expect("gtk init (is DISPLAY set?)");
    adw::init().expect("adw init");
    let scenarios: [(&str, fn()); 3] = [
        (
            "returning_user_login_autofocus",
            returning_user_login_autofocus,
        ),
        ("small_vault_flow", small_vault_flow),
        ("large_vault_stays_responsive", large_vault_stays_responsive),
    ];
    let mut ran = 0;
    for (name, f) in scenarios {
        if only.as_deref().is_some_and(|o| o != name) {
            continue;
        }
        println!("ui: {name}");
        f();
        // Drain pending work and tell the agent to forget this account.
        pump_for(Duration::from_millis(200));
        let sock = sangward_ipc::default_socket_path();
        let ctl = sangward_ipc::Client::new(sock);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = rt.block_on(ctl.simple(&sangward_ipc::Request::Logout));
        println!("ui: {name} ok");
        ran += 1;
    }
    assert!(ran > 0, "no scenario matched {only:?}");
    let failures = STALL_FAILURES.with(|f| f.borrow().clone());
    if !failures.is_empty() {
        eprintln!(
            "ui: UI thread exceeded the {} ms stall budget:",
            max_stall().as_millis()
        );
        for f in &failures {
            eprintln!("  - {f}");
        }
        std::process::exit(1);
    }
    println!("ui: {ran} scenario(s) passed");
}
