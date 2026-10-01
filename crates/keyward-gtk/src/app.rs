//! The keyward GTK application component (Relm4 + GTK4 + libadwaita).
//!
//! This is a thin rendering layer. App state, search, clipboard timing,
//! settings and agent spawning all come from `keyward-client`; vault access
//! goes over IPC to `keyward-agent`. A Slint/Qt frontend would replace only
//! this crate.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use keyward_client::spawn::{SpawnOptions, ensure_agent};
use keyward_client::{
    AppState, AutoClear, Controller, CopyTarget, LoginOutcome, Settings, UiError, VaultModel,
    kind_label,
};
use keyward_ipc::{ItemSummary, SecretField, Sensitive, ServerConfig, StatusInfo};
use keyward_platform::{Clipboard, CopyToken, KsniTray, Tray, TrayCommand, TrayState};
use relm4::adw::prelude::*;
use relm4::prelude::*;
use relm4::{abstractions::Toaster, adw, gtk, gtk::glib};

use crate::clipboard::GdkClipboard;

pub const APP_ID: &str = "dev.keyward.Keyward";

pub struct App {
    state: AppState,
    ctl: Option<Controller>,
    settings: Settings,
    vault: VaultModel,
    error: Option<String>,
    /// In-flight submit: which form screen stays visible, and the progress text
    /// its button shows. Covers the whole login/unlock -> items-loaded span, so
    /// the screen switches only once the vault is ready to show.
    busy: Option<Busy>,
    /// Items are being fetched (e.g. startup with an already-unlocked agent).
    items_loading: bool,
    /// One-shot: refocus and select the secret entry after a failed submit.
    refocus: bool,
    /// Revealed password for the selected item (cleared on selection change/lock).
    revealed: Option<Sensitive>,
    /// Pending login (kept for the TOTP step); password wiped after use.
    pending_login: Option<(ServerConfig, String, Sensitive)>,
    clipboard: Option<GdkClipboard>,
    auto_clear: AutoClear<CopyToken>,
    toaster: Toaster,
    tray: Option<KsniTray>,
    quitting: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Busy {
    screen: &'static str,
    text: &'static str,
}

/// UI messages. Secret payloads use `Sensitive` (redacted `Debug`): Relm4 logs
/// messages in its tracing spans.
#[derive(Debug)]
pub enum Msg {
    Login {
        server: String,
        email: String,
        password: Sensitive,
    },
    SubmitTotp(Sensitive),
    CancelTotp,
    Unlock(Sensitive),
    Lock,
    Sync,
    Logout,
    Search(String),
    Select(Option<String>),
    Copy(CopyTarget),
    ToggleReveal,
    ShowWindow,
    HideWindow,
    Quit,
    SetKeepAgent(bool),
    ClipboardTick,
    Tray(TrayCommand),
}

/// Results of async commands. Relm4 logs these via `Debug` in its spans, so the
/// impl below prints only the variant name, never payloads.
pub enum Cmd {
    Connected(Result<(Controller, StatusInfo), String>),
    LoginDone(Result<LoginOutcome, UiError>),
    UnlockDone(Result<(), UiError>),
    Items(Result<Vec<ItemSummary>, UiError>),
    SyncDone(Result<(), UiError>),
    Locked(Result<(), UiError>),
    LoggedOut(Result<(), UiError>),
    CopyValue(CopyTarget, Result<Sensitive, UiError>),
    Revealed(Result<Option<Sensitive>, UiError>),
    Status(Result<StatusInfo, UiError>),
    QuitReady,
}

impl std::fmt::Debug for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Cmd::Connected(_) => "Connected",
            Cmd::LoginDone(_) => "LoginDone",
            Cmd::UnlockDone(_) => "UnlockDone",
            Cmd::Items(_) => "Items",
            Cmd::SyncDone(_) => "SyncDone",
            Cmd::Locked(_) => "Locked",
            Cmd::LoggedOut(_) => "LoggedOut",
            Cmd::CopyValue(..) => "CopyValue",
            Cmd::Revealed(_) => "Revealed",
            Cmd::Status(_) => "Status",
            Cmd::QuitReady => "QuitReady",
        };
        f.write_str(name)
    }
}

/// Widgets the view updates after each message. Input widgets (entries, search)
/// push messages via signal handlers wired in `init` and need no handle here.
pub struct Widgets {
    stack: gtk::Stack,
    login_form: Form,
    login_error: gtk::Label,
    totp_form: Form,
    totp_error: gtk::Label,
    unlock_form: Form,
    unlock_error: gtk::Label,
    unlock_title: adw::StatusPage,
    // vault
    split: adw::NavigationSplitView,
    /// Backing store of the virtualized list (all items, unfiltered).
    store: gtk::gio::ListStore,
    /// Current search query, read by `filter`.
    query: std::rc::Rc<std::cell::RefCell<String>>,
    filter: gtk::CustomFilter,
    selection: gtk::SingleSelection,
    /// What the store/filter currently reflect, to skip redundant work.
    rendered_generation: u64,
    rendered_query: String,
    rendered_selected: Option<String>,
    empty_label: gtk::Label,
    search: gtk::SearchEntry,
    detail_title: gtk::Label,
    detail_kind: gtk::Label,
    detail_user: adw::ActionRow,
    detail_pw: adw::ActionRow,
    detail_host: adw::ActionRow,
    detail_totp: adw::ActionRow,
    detail_group: adw::PreferencesGroup,
    reveal_btn: gtk::Button,
    detail_stack: gtk::Stack,
    sync_spinner: gtk::Spinner,
}

impl App {
    fn ctl(&self) -> Option<Controller> {
        self.ctl.clone()
    }

    fn set_state(&mut self, s: AppState) {
        if self.state != s {
            tracing::info!(screen = screen_name(s), "screen changed");
        }
        self.state = s;
        if matches!(s, AppState::Locked | AppState::LoggedOut) {
            self.vault.clear();
            self.revealed = None;
            self.flush_clipboard();
        }
        if let Some(t) = &self.tray {
            t.set_state(match s {
                AppState::Unlocked | AppState::Syncing => TrayState::Unlocked,
                AppState::Locked => TrayState::Locked,
                _ => TrayState::LoggedOut,
            });
        }
    }

    fn flush_clipboard(&mut self) {
        if let (Some(tok), Some(cb)) = (self.auto_clear.flush(), self.clipboard.as_mut()) {
            let _ = cb.clear_if_owned(tok);
        }
    }

    fn toast(&self, text: &str) {
        self.toaster
            .add_toast(adw::Toast::builder().title(text).timeout(3).build());
    }

    /// The visible screen: an in-flight submit keeps its form on screen.
    fn screen(&self) -> &'static str {
        self.busy.map_or(screen_name(self.state), |b| b.screen)
    }

    fn fail(&mut self, e: UiError) {
        tracing::info!(kind = ?e.kind, "operation failed");
        if e.kind == Some(keyward_ipc::ErrorKind::Locked) {
            self.set_state(AppState::Locked);
        }
        self.error = Some(e.message);
    }
}

fn screen_name(s: AppState) -> &'static str {
    match s {
        AppState::Connecting => "connecting",
        AppState::LoggedOut => "login",
        AppState::AwaitingTotp => "totp",
        AppState::Locked => "unlock",
        AppState::Unlocked | AppState::Syncing => "vault",
    }
}

fn error_label() -> gtk::Label {
    let l = gtk::Label::new(None);
    l.add_css_class("error");
    l.set_wrap(true);
    l.set_visible(false);
    l
}

fn clamp(child: &impl IsA<gtk::Widget>) -> adw::Clamp {
    let c = adw::Clamp::builder().maximum_size(420).child(child).build();
    c.set_margin_top(24);
    c.set_margin_bottom(24);
    c.set_margin_start(12);
    c.set_margin_end(12);
    c
}

fn copy_button(icon: &str, tooltip: &str) -> gtk::Button {
    let b = gtk::Button::from_icon_name(icon);
    b.set_tooltip_text(Some(tooltip));
    b.set_valign(gtk::Align::Center);
    b.add_css_class("flat");
    // Accessible name for screen readers (icon-only button).
    b.update_property(&[gtk::accessible::Property::Label(tooltip)]);
    b
}

/// Stable widget names. They double as test hooks: `tests/ui.rs` finds widgets
/// by these names (`gtk::Widget::widget_name`), so renaming one is an API change.
pub mod names {
    pub const SERVER: &str = "login-server";
    pub const EMAIL: &str = "login-email";
    pub const PASSWORD: &str = "login-password";
    pub const LOGIN: &str = "login-submit";
    pub const TOTP: &str = "totp-code";
    pub const TOTP_SUBMIT: &str = "totp-submit";
    pub const UNLOCK_PASSWORD: &str = "unlock-password";
    pub const UNLOCK: &str = "unlock-submit";
    pub const SEARCH: &str = "vault-search";
    pub const LIST: &str = "vault-list";
    pub const LOCK: &str = "vault-lock";
    pub const SYNC: &str = "vault-sync";
    pub const DETAIL_TITLE: &str = "detail-title";
    pub const DETAIL_USERNAME: &str = "detail-username";
    pub const DETAIL_PASSWORD: &str = "detail-password";
    pub const COPY_USERNAME: &str = "copy-username";
    pub const COPY_PASSWORD: &str = "copy-password";
    pub const COPY_TOTP: &str = "copy-totp";
    pub const REVEAL: &str = "reveal-password";
    pub const SCREENS: &str = "screens";
    pub const ERROR_LOGIN: &str = "error-login";
    pub const ERROR_UNLOCK: &str = "error-unlock";
}

/// A submit form (login / TOTP / unlock) whose button shows progress in place.
struct Form {
    button: gtk::Button,
    spinner: gtk::Spinner,
    label: gtk::Label,
    idle: &'static str,
    /// Disabled while busy so a second submit can't start.
    inputs: Vec<gtk::Widget>,
    /// Kept on failure (selected, refocused) and cleared once the form is left.
    secret: gtk::Editable,
}

impl Form {
    fn new(
        idle: &'static str,
        name: &str,
        inputs: Vec<gtk::Widget>,
        secret: gtk::Editable,
    ) -> Self {
        let spinner = gtk::Spinner::builder().visible(false).build();
        spinner.set_widget_name(&format!("{name}-spinner"));
        let label = gtk::Label::new(Some(idle));
        label.set_widget_name(&format!("{name}-label"));
        let content = gtk::Box::builder()
            .spacing(8)
            .halign(gtk::Align::Center)
            .build();
        content.append(&spinner);
        content.append(&label);
        let button = gtk::Button::builder()
            .child(&content)
            .css_classes(["suggested-action", "pill"])
            .halign(gtk::Align::Center)
            // Fixed width so the button doesn't jump when the label changes.
            .width_request(200)
            .build();
        button.set_widget_name(name);
        Self {
            button,
            spinner,
            label,
            idle,
            inputs,
            secret,
        }
    }

    /// `busy`: progress text to show, or `None` when idle. `active`: this form's screen is shown.
    fn render(&self, busy: Option<&str>, active: bool, focus_secret: bool) {
        let on = active && busy.is_some();
        self.label.set_label(if on {
            busy.unwrap_or(self.idle)
        } else {
            self.idle
        });
        self.spinner.set_visible(on);
        self.spinner.set_spinning(on);
        self.button.set_sensitive(!on);
        self.button
            .update_state(&[gtk::accessible::State::Busy(on)]);
        for w in &self.inputs {
            w.set_sensitive(!on);
        }
        if !active && !self.secret.text().is_empty() {
            self.secret.set_text("");
        }
        if active && focus_secret {
            self.secret.grab_focus();
            self.secret.select_region(0, -1);
        }
    }
}

fn named<W: IsA<gtk::Widget>>(w: W, name: &str) -> W {
    w.set_widget_name(name);
    w
}

impl Component for App {
    type Init = ();
    type Input = Msg;
    type Output = ();
    type CommandOutput = Cmd;
    type Root = adw::ApplicationWindow;
    type Widgets = Widgets;

    fn init_root() -> Self::Root {
        adw::ApplicationWindow::builder()
            .title("keyward")
            .default_width(900)
            .default_height(600)
            .build()
    }

    fn init(_: (), window: Self::Root, sender: ComponentSender<Self>) -> ComponentParts<Self> {
        let settings = Settings::load();
        let toaster = Toaster::default();

        // ---- Login page ----
        let server = adw::EntryRow::builder()
            .title("Server URL")
            .text(&settings.server_url)
            .build();
        server.set_widget_name(names::SERVER);
        let email = adw::EntryRow::builder()
            .title("Email")
            .text(&settings.email)
            .build();
        email.set_widget_name(names::EMAIL);
        let password = adw::PasswordEntryRow::builder()
            .title("Master password")
            .build();
        password.set_widget_name(names::PASSWORD);
        let login_group = adw::PreferencesGroup::new();
        login_group.add(&server);
        login_group.add(&email);
        login_group.add(&password);
        let login_form = Form::new(
            "Log in",
            names::LOGIN,
            vec![
                server.clone().upcast(),
                email.clone().upcast(),
                password.clone().upcast(),
            ],
            password.clone().upcast(),
        );
        let login_btn = login_form.button.clone();
        let login_error = named(error_label(), names::ERROR_LOGIN);
        let login_box = gtk::Box::new(gtk::Orientation::Vertical, 18);
        let login_status = adw::StatusPage::builder()
            .icon_name("dialog-password-symbolic")
            .title("keyward")
            .description("Log in to your self-hosted Bitwarden-compatible server")
            .build();
        login_box.append(&login_status);
        login_box.append(&login_group);
        login_box.append(&login_error);
        login_box.append(&login_btn);
        {
            let s = sender.clone();
            let entries = (server.clone(), email.clone(), password.clone());
            let submit = move || {
                let (server, email, password) = &entries;
                s.input(Msg::Login {
                    server: server.text().to_string(),
                    email: email.text().to_string(),
                    password: Sensitive::new(password.text().to_string()),
                });
            };
            let submit2 = submit.clone();
            login_btn.connect_clicked(move |_| submit());
            password.connect_entry_activated(move |_| submit2());
        }

        // ---- TOTP page ----
        let totp = adw::EntryRow::builder()
            .title("Authenticator code")
            .input_purpose(gtk::InputPurpose::Digits)
            .build();
        totp.set_widget_name(names::TOTP);
        let totp_group = adw::PreferencesGroup::new();
        totp_group.add(&totp);
        let totp_error = error_label();
        let totp_cancel = gtk::Button::builder()
            .label("Back")
            .css_classes(["flat"])
            .halign(gtk::Align::Center)
            .build();
        let totp_form = Form::new(
            "Verify",
            names::TOTP_SUBMIT,
            vec![totp.clone().upcast(), totp_cancel.clone().upcast()],
            totp.clone().upcast(),
        );
        let totp_btn = totp_form.button.clone();
        let totp_box = gtk::Box::new(gtk::Orientation::Vertical, 18);
        totp_box.append(
            &adw::StatusPage::builder()
                .icon_name("security-high-symbolic")
                .title("Two-step login")
                .description("Enter the code from your authenticator app")
                .build(),
        );
        totp_box.append(&totp_group);
        totp_box.append(&totp_error);
        totp_box.append(&totp_btn);
        totp_box.append(&totp_cancel);
        {
            let s = sender.clone();
            let t = totp.clone();
            let submit = move || {
                s.input(Msg::SubmitTotp(Sensitive::new(t.text().trim())));
            };
            let submit2 = submit.clone();
            totp_btn.connect_clicked(move |_| submit());
            totp.connect_entry_activated(move |_| submit2());
            let s = sender.clone();
            totp_cancel.connect_clicked(move |_| s.input(Msg::CancelTotp));
        }

        // ---- Unlock page ----
        let unlock_pw = adw::PasswordEntryRow::builder()
            .title("Master password")
            .build();
        unlock_pw.set_widget_name(names::UNLOCK_PASSWORD);
        let unlock_group = adw::PreferencesGroup::new();
        unlock_group.add(&unlock_pw);
        let unlock_error = named(error_label(), names::ERROR_UNLOCK);
        let logout_btn = gtk::Button::builder()
            .label("Log out")
            .css_classes(["flat"])
            .halign(gtk::Align::Center)
            .build();
        let unlock_form = Form::new(
            "Unlock",
            names::UNLOCK,
            vec![unlock_pw.clone().upcast(), logout_btn.clone().upcast()],
            unlock_pw.clone().upcast(),
        );
        let unlock_btn = unlock_form.button.clone();
        let unlock_title = adw::StatusPage::builder()
            .icon_name("changes-prevent-symbolic")
            .title("Vault locked")
            .build();
        let unlock_box = gtk::Box::new(gtk::Orientation::Vertical, 18);
        unlock_box.append(&unlock_title);
        unlock_box.append(&unlock_group);
        unlock_box.append(&unlock_error);
        unlock_box.append(&unlock_btn);
        unlock_box.append(&logout_btn);
        {
            let s = sender.clone();
            let p = unlock_pw.clone();
            let submit = move || {
                s.input(Msg::Unlock(Sensitive::new(p.text().to_string())));
            };
            let submit2 = submit.clone();
            unlock_btn.connect_clicked(move |_| submit());
            unlock_pw.connect_entry_activated(move |_| submit2());
            let s = sender.clone();
            logout_btn.connect_clicked(move |_| s.input(Msg::Logout));
        }

        // ---- Vault page: AdwNavigationSplitView ----
        let search = gtk::SearchEntry::builder()
            .placeholder_text("Search vault")
            .hexpand(true)
            .build();
        search.set_widget_name(names::SEARCH);
        search.update_property(&[gtk::accessible::Property::Label("Search vault")]);
        {
            let s = sender.clone();
            search.connect_search_changed(move |e| s.input(Msg::Search(e.text().to_string())));
        }
        // Virtualized list: GTK only creates widgets for rows on screen and
        // recycles them while scrolling, so the cost is independent of vault size.
        // The store holds `ItemSummary` values; filtering reuses
        // `keyward_client::matches` via a CustomFilter driven by the query cell.
        let store = gtk::gio::ListStore::new::<glib::BoxedAnyObject>();
        let query = std::rc::Rc::new(std::cell::RefCell::new(String::new()));
        let filter = {
            let q = query.clone();
            gtk::CustomFilter::new(move |obj| {
                let q = q.borrow();
                q.is_empty()
                    || obj
                        .downcast_ref::<glib::BoxedAnyObject>()
                        .is_some_and(|b| keyward_client::matches(&b.borrow::<ItemSummary>(), &q))
            })
        };
        let filtered = gtk::FilterListModel::new(Some(store.clone()), Some(filter.clone()));
        let selection = gtk::SingleSelection::new(Some(filtered.clone()));
        selection.set_autoselect(false);
        selection.set_can_unselect(true);
        let factory = gtk::SignalListItemFactory::new();
        factory.connect_setup(|_, obj| {
            let li = obj.downcast_ref::<gtk::ListItem>().expect("ListItem");
            let title = gtk::Label::builder()
                .xalign(0.0)
                .ellipsize(gtk::pango::EllipsizeMode::End)
                .build();
            let subtitle = gtk::Label::builder()
                .xalign(0.0)
                .ellipsize(gtk::pango::EllipsizeMode::End)
                .css_classes(["dim-label", "caption"])
                .build();
            let b = gtk::Box::builder()
                .orientation(gtk::Orientation::Vertical)
                .spacing(2)
                .margin_top(6)
                .margin_bottom(6)
                .margin_start(6)
                .margin_end(6)
                .build();
            b.append(&title);
            b.append(&subtitle);
            li.set_child(Some(&b));
        });
        factory.connect_bind(|_, obj| {
            let li = obj.downcast_ref::<gtk::ListItem>().expect("ListItem");
            let (Some(item), Some(child)) = (li.item(), li.child()) else {
                return;
            };
            let Ok(item) = item.downcast::<glib::BoxedAnyObject>() else {
                return;
            };
            let s = item.borrow::<ItemSummary>();
            let title = child
                .first_child()
                .and_downcast::<gtk::Label>()
                .expect("title label");
            let subtitle = title
                .next_sibling()
                .and_downcast::<gtk::Label>()
                .expect("subtitle label");
            // Plain text (not markup), so no escaping is needed.
            title.set_text(&s.name);
            subtitle.set_text(
                s.username
                    .as_deref()
                    .or(s.uri_host.as_deref())
                    .unwrap_or(kind_label(s.kind)),
            );
            child.update_property(&[gtk::accessible::Property::Label(&s.name)]);
        });
        let list = gtk::ListView::builder()
            .model(&selection)
            .factory(&factory)
            .css_classes(["navigation-sidebar"])
            .build();
        list.set_widget_name(names::LIST);
        {
            let s = sender.clone();
            selection.connect_selected_notify(move |sel| {
                let id = sel
                    .selected_item()
                    .and_downcast::<glib::BoxedAnyObject>()
                    .map(|b| b.borrow::<ItemSummary>().id.clone());
                s.input(Msg::Select(id));
            });
        }
        let empty_label = gtk::Label::builder()
            .label("No items")
            .css_classes(["dim-label"])
            .margin_top(24)
            .valign(gtk::Align::Start)
            .build();
        // The ListView must be the ScrolledWindow's direct child to stay virtualized.
        let scroller = gtk::ScrolledWindow::builder()
            .child(&list)
            .vexpand(true)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .build();
        let list_box = gtk::Overlay::new();
        list_box.set_child(Some(&scroller));
        list_box.add_overlay(&empty_label);
        empty_label.set_can_target(false);

        let sync_btn = gtk::Button::from_icon_name("view-refresh-symbolic");
        sync_btn.set_widget_name(names::SYNC);
        sync_btn.set_tooltip_text(Some("Sync"));
        sync_btn.update_property(&[gtk::accessible::Property::Label("Sync")]);
        let lock_btn = gtk::Button::from_icon_name("changes-prevent-symbolic");
        lock_btn.set_widget_name(names::LOCK);
        lock_btn.set_tooltip_text(Some("Lock"));
        lock_btn.update_property(&[gtk::accessible::Property::Label("Lock")]);
        let sync_spinner = gtk::Spinner::new();
        let keep_agent = gtk::CheckButton::with_label("Keep agent running after quit");
        keep_agent.set_active(settings.keep_agent_running);
        {
            let s = sender.clone();
            keep_agent.connect_toggled(move |c| s.input(Msg::SetKeepAgent(c.is_active())));
            let s = sender.clone();
            sync_btn.connect_clicked(move |_| s.input(Msg::Sync));
            let s = sender.clone();
            lock_btn.connect_clicked(move |_| s.input(Msg::Lock));
        }
        let menu_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
        menu_box.set_margin_top(6);
        menu_box.set_margin_bottom(6);
        menu_box.set_margin_start(6);
        menu_box.set_margin_end(6);
        menu_box.append(&keep_agent);
        let quit_btn = gtk::Button::with_label("Quit");
        {
            let s = sender.clone();
            quit_btn.connect_clicked(move |_| s.input(Msg::Quit));
        }
        menu_box.append(&quit_btn);
        let menu_btn = gtk::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .popover(&gtk::Popover::builder().child(&menu_box).build())
            .tooltip_text("Menu")
            .build();

        let side_header = adw::HeaderBar::new();
        side_header.pack_start(&lock_btn);
        side_header.pack_end(&menu_btn);
        side_header.pack_end(&sync_btn);
        side_header.pack_end(&sync_spinner);
        let side_tv = adw::ToolbarView::new();
        side_tv.add_top_bar(&side_header);
        let search_bar = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        search_bar.set_margin_start(6);
        search_bar.set_margin_end(6);
        search_bar.set_margin_bottom(6);
        search_bar.append(&search);
        side_tv.add_top_bar(&search_bar);
        side_tv.set_content(Some(&list_box));
        let sidebar = adw::NavigationPage::builder()
            .title("Vault")
            .child(&side_tv)
            .build();

        // Detail pane
        let detail_title = gtk::Label::builder()
            .css_classes(["title-1"])
            .wrap(true)
            .xalign(0.0)
            .build();
        detail_title.set_widget_name(names::DETAIL_TITLE);
        let detail_kind = gtk::Label::builder()
            .css_classes(["dim-label"])
            .xalign(0.0)
            .build();
        let detail_user = adw::ActionRow::builder()
            .title("Username")
            .subtitle_selectable(true)
            .build();
        detail_user.set_widget_name(names::DETAIL_USERNAME);
        let detail_pw = adw::ActionRow::builder()
            .title("Password")
            .subtitle("••••••••")
            .build();
        detail_pw.set_widget_name(names::DETAIL_PASSWORD);
        let detail_host = adw::ActionRow::builder()
            .title("Website")
            .subtitle_selectable(true)
            .build();
        let detail_totp = adw::ActionRow::builder()
            .title("One-time code")
            .subtitle("Copy to view")
            .build();
        let copy_user = copy_button("edit-copy-symbolic", "Copy username");
        copy_user.set_widget_name(names::COPY_USERNAME);
        let copy_pw = copy_button("edit-copy-symbolic", "Copy password");
        copy_pw.set_widget_name(names::COPY_PASSWORD);
        let reveal_btn = copy_button("view-reveal-symbolic", "Reveal password");
        reveal_btn.set_widget_name(names::REVEAL);
        let copy_totp = copy_button("edit-copy-symbolic", "Copy one-time code");
        copy_totp.set_widget_name(names::COPY_TOTP);
        detail_user.add_suffix(&copy_user);
        detail_pw.add_suffix(&reveal_btn);
        detail_pw.add_suffix(&copy_pw);
        detail_totp.add_suffix(&copy_totp);
        {
            let s = sender.clone();
            copy_user.connect_clicked(move |_| s.input(Msg::Copy(CopyTarget::Username)));
            let s = sender.clone();
            copy_pw.connect_clicked(move |_| s.input(Msg::Copy(CopyTarget::Password)));
            let s = sender.clone();
            copy_totp.connect_clicked(move |_| s.input(Msg::Copy(CopyTarget::Totp)));
            let s = sender.clone();
            reveal_btn.connect_clicked(move |_| s.input(Msg::ToggleReveal));
        }
        let detail_group = adw::PreferencesGroup::new();
        detail_group.add(&detail_user);
        detail_group.add(&detail_pw);
        detail_group.add(&detail_totp);
        detail_group.add(&detail_host);
        let detail_box = gtk::Box::new(gtk::Orientation::Vertical, 12);
        detail_box.append(&detail_title);
        detail_box.append(&detail_kind);
        detail_box.append(&detail_group);
        let detail_stack = gtk::Stack::new();
        detail_stack.add_named(
            &adw::StatusPage::builder()
                .icon_name("dialog-password-symbolic")
                .title("Select an item")
                .build(),
            Some("empty"),
        );
        detail_stack.add_named(
            &gtk::ScrolledWindow::builder()
                .child(&clamp(&detail_box))
                .build(),
            Some("item"),
        );
        let content_tv = adw::ToolbarView::new();
        content_tv.add_top_bar(&adw::HeaderBar::new());
        content_tv.set_content(Some(&detail_stack));
        let content = adw::NavigationPage::builder()
            .title("Item")
            .child(&content_tv)
            .build();
        let split = adw::NavigationSplitView::builder()
            .sidebar(&sidebar)
            .content(&content)
            .build();

        // ---- Top-level stack ----
        let stack = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::Crossfade)
            .build();
        stack.set_widget_name(names::SCREENS);
        stack.add_named(
            &adw::StatusPage::builder()
                .title("Connecting to agent…")
                .child(
                    &gtk::Spinner::builder()
                        .spinning(true)
                        .width_request(32)
                        .height_request(32)
                        .halign(gtk::Align::Center)
                        .build(),
                )
                .build(),
            Some("connecting"),
        );
        let wrap_page = |w: &gtk::Box| {
            let tv = adw::ToolbarView::new();
            tv.add_top_bar(&adw::HeaderBar::new());
            tv.set_content(Some(
                &gtk::ScrolledWindow::builder().child(&clamp(w)).build(),
            ));
            tv
        };
        stack.add_named(&wrap_page(&login_box), Some("login"));
        stack.add_named(&wrap_page(&totp_box), Some("totp"));
        stack.add_named(&wrap_page(&unlock_box), Some("unlock"));
        stack.add_named(&split, Some("vault"));
        let overlay = toaster.overlay_widget();
        overlay.set_child(Some(&stack));
        window.set_content(Some(overlay));

        // Closing hides to tray (if we have one); Quit lives in the tray/menu.
        {
            let s = sender.clone();
            window.connect_close_request(move |_| {
                s.input(Msg::HideWindow);
                relm4::gtk::glib::Propagation::Stop
            });
        }

        // Tray: ksni runs its own thread; commands arrive over a std channel.
        let (tx, rx) = mpsc::channel::<TrayCommand>();
        let tray = match KsniTray::spawn(tx) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::warn!("tray unavailable ({e}); closing the window will quit");
                None
            }
        };
        {
            let s = sender.input_sender().clone();
            std::thread::spawn(move || {
                while let Ok(cmd) = rx.recv() {
                    if s.send(Msg::Tray(cmd)).is_err() {
                        break;
                    }
                }
            });
        }

        // Clipboard auto-clear ticker.
        {
            // `send` instead of `input`: once the component is shut down (quit,
            // window destroyed) the send fails, and we stop the timer instead of
            // panicking inside a GLib callback (which aborts the process).
            let s = sender.input_sender().clone();
            relm4::gtk::glib::timeout_add_seconds_local(1, move || {
                if s.send(Msg::ClipboardTick).is_ok() {
                    relm4::gtk::glib::ControlFlow::Continue
                } else {
                    relm4::gtk::glib::ControlFlow::Break
                }
            });
        }

        // Connect to (or spawn) the agent.
        sender.oneshot_command(async move {
            let socket = keyward_ipc::default_socket_path();
            let opts = SpawnOptions {
                extra_args: agent_args_from_env(),
                ..Default::default()
            };
            let r = match ensure_agent(&socket, &opts).await {
                Ok(client) => {
                    let ctl = Controller::new(client);
                    ctl.status().await.map(|s| (ctl, s)).map_err(|e| e.message)
                }
                Err(e) => Err(e.to_string()),
            };
            Cmd::Connected(r)
        });

        let model = App {
            state: AppState::Connecting,
            ctl: None,
            auto_clear: AutoClear::new(Duration::from_secs(settings.clipboard_clear_secs)),
            settings,
            vault: VaultModel::default(),
            error: None,
            busy: None,
            items_loading: false,
            refocus: false,
            revealed: None,
            pending_login: None,
            clipboard: GdkClipboard::default_display(),
            toaster,
            tray,
            quitting: false,
        };
        let widgets = Widgets {
            stack,
            login_form,
            login_error,
            totp_form,
            totp_error,
            unlock_form,
            unlock_error,
            unlock_title,
            split,
            store,
            query,
            filter,
            selection,
            rendered_generation: u64::MAX,
            rendered_query: String::new(),
            rendered_selected: None,
            empty_label,
            search,
            detail_title,
            detail_kind,
            detail_user,
            detail_pw,
            detail_host,
            detail_totp,
            detail_group,
            reveal_btn,
            detail_stack,
            sync_spinner,
        };
        window.present();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Msg, sender: ComponentSender<Self>, root: &Self::Root) {
        self.error = None;
        self.refocus = false;
        let Some(ctl) = self.ctl() else {
            if let Msg::Quit | Msg::Tray(TrayCommand::Quit) = msg
                && let Some(a) = root.application()
            {
                a.quit();
            }
            return;
        };
        match msg {
            Msg::Login { .. } | Msg::SubmitTotp(_) | Msg::Unlock(_) if self.busy.is_some() => {}
            Msg::Login {
                server,
                email,
                password,
            } => {
                if server.trim().is_empty() || email.trim().is_empty() || password.is_empty() {
                    self.error = Some("Server URL, email and password are required".into());
                    return;
                }
                self.settings.server_url = server.trim().to_owned();
                self.settings.email = email.trim().to_owned();
                let _ = self.settings.save();
                let cfg = ServerConfig {
                    base_url: self.settings.server_url.clone(),
                    identity_url: self.settings.identity_url.clone(),
                    api_url: self.settings.api_url.clone(),
                    insecure_allow_http: false,
                };
                let pw = password;
                self.pending_login = Some((cfg.clone(), self.settings.email.clone(), pw.clone()));
                self.busy = Some(Busy {
                    screen: "login",
                    text: "Logging in…",
                });
                let email = self.settings.email.clone();
                sender.oneshot_command(async move {
                    Cmd::LoginDone(ctl.login(cfg, &email, pw, None).await)
                });
            }
            Msg::SubmitTotp(code) => {
                let Some((cfg, email, pw)) = self.pending_login.clone() else {
                    return;
                };
                if code.is_empty() {
                    return;
                }
                self.busy = Some(Busy {
                    screen: "totp",
                    text: "Verifying…",
                });
                sender.oneshot_command(async move {
                    Cmd::LoginDone(ctl.login(cfg, &email, pw, Some(code)).await)
                });
            }
            Msg::CancelTotp => {
                self.pending_login = None;
                self.set_state(AppState::LoggedOut);
            }
            Msg::Unlock(pw) => {
                if pw.is_empty() {
                    return;
                }
                self.busy = Some(Busy {
                    screen: "unlock",
                    text: "Unlocking…",
                });
                sender.oneshot_command(async move { Cmd::UnlockDone(ctl.unlock(pw).await) });
            }
            Msg::Lock | Msg::Tray(TrayCommand::Lock) => {
                sender.oneshot_command(async move { Cmd::Locked(ctl.lock().await) });
            }
            Msg::Sync | Msg::Tray(TrayCommand::Sync) => {
                if self.state != AppState::Unlocked {
                    return;
                }
                self.set_state(AppState::Syncing);
                sender.oneshot_command(async move { Cmd::SyncDone(ctl.sync().await) });
            }
            Msg::Logout => {
                sender.oneshot_command(async move { Cmd::LoggedOut(ctl.logout().await) });
            }
            Msg::Search(q) => self.vault.set_query(&q),
            Msg::Select(id) => {
                self.revealed = None;
                self.vault.select(id.as_deref());
            }
            Msg::Copy(target) => {
                let Some(item) = self.vault.selected().cloned() else {
                    return;
                };
                sender.oneshot_command(async move {
                    let v = ctl.copy_value(&item, target).await;
                    Cmd::CopyValue(target, v)
                });
            }
            Msg::ToggleReveal => {
                if self.revealed.take().is_some() {
                    return;
                }
                let Some(item) = self.vault.selected().cloned() else {
                    return;
                };
                sender.oneshot_command(async move {
                    Cmd::Revealed(ctl.secret(&item.id, SecretField::Password).await)
                });
            }
            Msg::ShowWindow | Msg::Tray(TrayCommand::Open) => {
                root.set_visible(true);
                root.present();
                // Refresh state: the agent may have auto-locked while hidden.
                sender.oneshot_command(async move { Cmd::Status(ctl.status().await) });
            }
            Msg::HideWindow => {
                if self.tray.is_some() {
                    root.set_visible(false);
                    self.revealed = None;
                } else {
                    sender.input(Msg::Quit);
                }
            }
            Msg::Quit | Msg::Tray(TrayCommand::Quit) => {
                if self.quitting {
                    return;
                }
                self.quitting = true;
                self.flush_clipboard();
                let keep = self.settings.keep_agent_running;
                sender.oneshot_command(async move {
                    // Default: lock and stop the agent. Opt-in: leave it running (still locked if it was).
                    if !keep {
                        let _ = ctl.shutdown_agent().await;
                    }
                    Cmd::QuitReady
                });
            }
            Msg::SetKeepAgent(v) => {
                self.settings.keep_agent_running = v;
                let _ = self.settings.save();
            }
            Msg::ClipboardTick => {
                if let Some(tok) = self.auto_clear.due(Instant::now())
                    && let Some(cb) = self.clipboard.as_mut()
                {
                    match cb.clear_if_owned(tok) {
                        Ok(true) => tracing::debug!("clipboard cleared"),
                        Ok(false) => tracing::debug!("clipboard changed elsewhere; left untouched"),
                        Err(e) => tracing::warn!("clipboard clear failed: {e}"),
                    }
                }
            }
        }
    }

    fn update_cmd(&mut self, msg: Cmd, sender: ComponentSender<Self>, root: &Self::Root) {
        self.refocus = false;
        match msg {
            Cmd::Connected(Ok((ctl, status))) => {
                self.ctl = Some(ctl);
                self.apply_status(&status, &sender);
            }
            Cmd::Connected(Err(e)) => {
                tracing::error!("cannot reach agent: {e}");
                self.error = Some(e);
                self.set_state(AppState::Connecting);
            }
            Cmd::Status(Ok(s)) => self.apply_status(&s, &sender),
            Cmd::Status(Err(e)) => self.fail(e),
            Cmd::LoginDone(Ok(LoginOutcome::Success)) | Cmd::UnlockDone(Ok(())) => {
                self.pending_login = None;
                // Stay on the submitting screen with its spinner until the item
                // list has arrived, then switch straight to a populated vault.
                if let Some(b) = &mut self.busy {
                    b.text = "Opening vault…";
                }
                self.set_state(AppState::Unlocked);
                self.load_items(&sender);
            }
            Cmd::LoginDone(Ok(LoginOutcome::NeedsTotp)) => {
                self.busy = None;
                self.set_state(AppState::AwaitingTotp);
            }
            Cmd::LoginDone(Err(e)) => {
                self.busy = None;
                self.refocus = true;
                if self.state != AppState::AwaitingTotp {
                    self.pending_login = None;
                }
                self.fail(e);
            }
            Cmd::UnlockDone(Err(e)) => {
                self.busy = None;
                self.refocus = true;
                self.fail(e);
            }
            Cmd::Items(r) => {
                self.busy = None;
                self.items_loading = false;
                match r {
                    // Ignore a late reply that raced with lock/logout.
                    Ok(items) if matches!(self.state, AppState::Unlocked | AppState::Syncing) => {
                        self.vault.set_items(items)
                    }
                    Ok(_) => {}
                    Err(e) => self.fail(e),
                }
            }
            Cmd::SyncDone(r) => {
                self.set_state(AppState::Unlocked);
                match r {
                    Ok(()) => {
                        self.toast("Vault synced");
                        self.load_items(&sender);
                    }
                    Err(e) => self.fail(e),
                }
            }
            Cmd::Locked(r) => {
                self.busy = None;
                if let Err(e) = r {
                    self.fail(e);
                }
                self.set_state(AppState::Locked);
            }
            Cmd::LoggedOut(r) => {
                self.busy = None;
                if let Err(e) = r {
                    self.fail(e);
                }
                self.set_state(AppState::LoggedOut);
            }
            Cmd::CopyValue(target, Ok(value)) => match self
                .clipboard
                .as_mut()
                .map(|c| c.set_secret(value.expose()))
            {
                Some(Ok(tok)) => {
                    let after = self.auto_clear.after();
                    self.auto_clear.copied(tok, Instant::now());
                    self.toast(&keyward_client::clipboard::copied_message(
                        target.label(),
                        after,
                    ));
                }
                Some(Err(e)) => self.error = Some(e.to_string()),
                None => self.error = Some("No clipboard available".into()),
            },
            Cmd::CopyValue(_, Err(e)) => self.fail(e),
            Cmd::Revealed(Ok(v)) => self.revealed = v,
            Cmd::Revealed(Err(e)) => self.fail(e),
            Cmd::QuitReady => {
                if let Some(t) = self.tray.take() {
                    t.shutdown();
                }
                if let Some(app) = root.application() {
                    app.quit();
                }
            }
        }
        if let Some(e) = &self.error {
            self.toast(e);
        }
    }

    fn update_view(&self, w: &mut Widgets, _sender: ComponentSender<Self>) {
        let screen = self.screen();
        w.stack.set_visible_child_name(screen);
        let busy = self.busy.map(|b| b.text);
        let refocus = self.refocus;
        w.login_form.render(busy, screen == "login", refocus);
        w.totp_form.render(busy, screen == "totp", refocus);
        w.unlock_form.render(busy, screen == "unlock", refocus);
        let show_err = |l: &gtk::Label, on: bool| {
            l.set_visible(on && self.error.is_some());
            l.set_label(self.error.as_deref().unwrap_or(""));
        };
        show_err(&w.login_error, self.state == AppState::LoggedOut);
        show_err(&w.totp_error, self.state == AppState::AwaitingTotp);
        show_err(&w.unlock_error, self.state == AppState::Locked);
        w.sync_spinner.set_spinning(self.state == AppState::Syncing);
        w.sync_spinner.set_visible(self.state == AppState::Syncing);
        w.unlock_title.set_description(
            self.settings
                .email
                .is_empty()
                .then_some("")
                .or(Some(&self.settings.email)),
        );

        // Repopulate the store only when the item set changed (one splice, one
        // items-changed signal); otherwise re-run the filter only when the query
        // changed. Neither creates row widgets: the ListView binds visible rows lazily.
        if self.vault.generation() != w.rendered_generation {
            w.rendered_generation = self.vault.generation();
            let objs: Vec<glib::BoxedAnyObject> = self
                .vault
                .items()
                .iter()
                .cloned()
                .map(glib::BoxedAnyObject::new)
                .collect();
            w.store.splice(0, w.store.n_items(), &objs);
            w.rendered_query = String::new();
            *w.query.borrow_mut() = String::new();
        }
        if self.vault.query() != w.rendered_query {
            let narrowing = self.vault.query().starts_with(w.rendered_query.as_str());
            w.rendered_query = self.vault.query().to_owned();
            *w.query.borrow_mut() = w.rendered_query.clone();
            // MoreStrict lets GTK only re-test currently visible items when narrowing.
            w.filter.changed(if narrowing {
                gtk::FilterChange::MoreStrict
            } else {
                gtk::FilterChange::Different
            });
        }
        // Keep the list selection in sync with the model (e.g. cleared on lock).
        if self.vault.selected().is_none() && w.selection.selected() != gtk::INVALID_LIST_POSITION {
            w.selection.set_selected(gtk::INVALID_LIST_POSITION);
        }
        // The model drops the query on lock/logout; don't leave stale text behind.
        if matches!(self.state, AppState::Locked | AppState::LoggedOut)
            && !w.search.text().is_empty()
        {
            w.search.set_text("");
        }
        let loading = self.items_loading && self.vault.all_len() == 0;
        w.empty_label.set_label(if loading {
            "Opening vault…"
        } else {
            "No items"
        });
        w.empty_label.set_visible(
            (loading || self.vault.visible_len() == 0)
                && matches!(self.state, AppState::Unlocked | AppState::Syncing),
        );

        match self.vault.selected() {
            None => w.detail_stack.set_visible_child_name("empty"),
            Some(item) => {
                w.detail_stack.set_visible_child_name("item");
                w.detail_title.set_label(&item.name);
                w.detail_kind.set_label(kind_label(item.kind));
                w.detail_user.set_visible(item.username.is_some());
                w.detail_user
                    .set_subtitle(&glib_escape(item.username.as_deref().unwrap_or("")));
                w.detail_pw.set_visible(item.has_password);
                let pw_text = match &self.revealed {
                    Some(p) => glib_escape(p.expose()),
                    None => "••••••••".to_owned(),
                };
                w.detail_pw.set_subtitle(&pw_text);
                w.detail_pw.set_subtitle_selectable(self.revealed.is_some());
                w.reveal_btn.set_icon_name(if self.revealed.is_some() {
                    "view-conceal-symbolic"
                } else {
                    "view-reveal-symbolic"
                });
                w.reveal_btn
                    .set_tooltip_text(Some(if self.revealed.is_some() {
                        "Hide password"
                    } else {
                        "Reveal password"
                    }));
                w.detail_totp.set_visible(item.has_totp);
                w.detail_host.set_visible(item.uri_host.is_some());
                w.detail_host
                    .set_subtitle(&glib_escape(item.uri_host.as_deref().unwrap_or("")));
                w.detail_group.set_visible(
                    item.username.is_some()
                        || item.has_password
                        || item.has_totp
                        || item.uri_host.is_some(),
                );
                // Only navigate on a *new* selection, so periodic updates (clipboard
                // tick) don't override the Back button in the collapsed layout.
                if w.rendered_selected.as_deref() != Some(item.id.as_str()) {
                    w.split.set_show_content(true);
                }
            }
        }
        w.rendered_selected = self.vault.selected().map(|i| i.id.clone());
    }
}

impl App {
    fn apply_status(&mut self, s: &StatusInfo, sender: &ComponentSender<Self>) {
        let st = AppState::from(s.state);
        let was = self.state;
        if let Some(e) = &s.email {
            self.settings.email = e.clone();
        }
        if st == AppState::LoggedOut && was == AppState::AwaitingTotp {
            return;
        }
        self.set_state(st);
        if st == AppState::Unlocked && was != AppState::Unlocked {
            self.load_items(sender);
        }
    }

    fn load_items(&mut self, sender: &ComponentSender<Self>) {
        if let Some(ctl) = self.ctl() {
            self.items_loading = true;
            sender.oneshot_command(async move { Cmd::Items(ctl.list().await) });
        }
    }
}

/// Rows render markup; escape user content.
fn glib_escape(s: &str) -> String {
    relm4::gtk::glib::markup_escape_text(s).to_string()
}

/// `KEYWARD_GTK_AGENT_ARGS` (space-separated) lets the harness start the agent
/// with e.g. the in-memory secret store.
fn agent_args_from_env() -> Vec<String> {
    std::env::var("KEYWARD_GTK_AGENT_ARGS")
        .map(|s| s.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}
