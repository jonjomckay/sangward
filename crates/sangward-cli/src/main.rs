//! `sangward`: command-line frontend. Talks only to sangward-agent over IPC.
//!
//! Passwords are read from a TTY prompt, from `--password-stdin`, or from an
//! environment variable named by `--password-env` (never from argv).

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use sangward_client::spawn::{SpawnOptions, ensure_agent};
use sangward_client::{
    Controller, CopyTarget, LoginOutcome, Settings, UiError, VaultModel, kind_label,
};
use sangward_ipc::{ErrorKind, ItemSummary, LockState, SecretField, Sensitive, ServerConfig};

#[derive(Parser)]
#[command(
    name = "sangward",
    version,
    about = "sangward: a native client for Bitwarden-compatible servers"
)]
struct Cli {
    /// Agent socket (default: $XDG_RUNTIME_DIR/sangward/agent.sock).
    #[arg(long, global = true, env = "SANGWARD_SOCKET")]
    socket: Option<PathBuf>,
    /// Don't auto-start sangward-agent.
    #[arg(long, global = true)]
    no_spawn: bool,
    /// Extra argument for an auto-started agent (repeatable), e.g. `--agent-arg=--secret-store=memory`.
    #[arg(long = "agent-arg", global = true, allow_hyphen_values = true)]
    agent_args: Vec<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct PasswordSource {
    /// Read the master password from this environment variable.
    #[arg(long)]
    password_env: Option<String>,
    /// Read the master password from the first line of stdin.
    #[arg(long, conflicts_with = "password_env")]
    password_stdin: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Log in to a self-hosted server.
    Login {
        /// Server base URL, e.g. https://vault.example.com
        #[arg(long)]
        server: String,
        #[arg(long)]
        email: String,
        /// Override the identity URL (default {server}/identity).
        #[arg(long)]
        identity_url: Option<String>,
        /// Override the API URL (default {server}/api).
        #[arg(long)]
        api_url: Option<String>,
        /// Permit plain http:// to non-loopback hosts. Dangerous.
        #[arg(long)]
        insecure_allow_http: bool,
        /// Authenticator code (otherwise prompted if the server asks for one).
        #[arg(long)]
        totp: Option<String>,
        /// Read the authenticator code from this environment variable.
        #[arg(long, conflicts_with = "totp")]
        totp_env: Option<String>,
        #[command(flatten)]
        password: PasswordSource,
    },
    /// Unlock the vault with the master password.
    Unlock {
        #[command(flatten)]
        password: PasswordSource,
    },
    Lock,
    /// Log out and forget the cached account.
    Logout,
    Status {
        #[arg(long)]
        json: bool,
    },
    Sync,
    /// List items (optionally filtered).
    List {
        /// Search terms (name, username, host).
        query: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Print one field of an item (by id or exact name).
    Get {
        item: String,
        #[arg(long, value_enum, default_value = "password")]
        field: GetField,
        /// Print the whole item as JSON (decrypts password, notes and TOTP seed).
        #[arg(long)]
        json: bool,
    },
    /// Copy a field to the clipboard and clear it after a delay.
    Copy {
        item: String,
        #[arg(long, value_enum, default_value = "password")]
        field: CopyField,
        #[arg(long, default_value_t = sangward_client::DEFAULT_CLEAR_SECS)]
        clear_after: u64,
    },
    /// Set the agent's inactivity auto-lock timeout.
    AutoLock {
        seconds: u64,
    },
    /// Lock and stop the agent.
    StopAgent,
}

#[derive(Copy, Clone, ValueEnum)]
enum GetField {
    Username,
    Password,
    Notes,
    Totp,
    TotpSeed,
    Uri,
    Name,
}

#[derive(Copy, Clone, ValueEnum)]
enum CopyField {
    Username,
    Password,
    Totp,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SANGWARD_LOG")
                .unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match run(Cli::parse()).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("sangward: {e:#}");
            let code = e
                .downcast_ref::<UiError>()
                .and_then(|u| u.kind)
                .map(exit_code)
                .unwrap_or(1);
            std::process::exit(code);
        }
    }
}

/// Stable exit codes so scripts (and the e2e harness) can branch on them.
fn exit_code(k: ErrorKind) -> i32 {
    match k {
        ErrorKind::Locked => 3,
        ErrorKind::LoggedOut => 4,
        ErrorKind::InvalidCredentials => 5,
        ErrorKind::InvalidTwoFactor => 6,
        ErrorKind::NotFound => 7,
        ErrorKind::Network => 8,
        ErrorKind::Policy => 9,
        _ => 1,
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let socket = cli
        .socket
        .clone()
        .unwrap_or_else(sangward_ipc::default_socket_path);
    let no_spawn = cli.no_spawn || matches!(cli.cmd, Cmd::StopAgent);
    let opts = SpawnOptions {
        no_spawn,
        extra_args: cli.agent_args.clone(),
        ..Default::default()
    };
    let client = match ensure_agent(&socket, &opts).await {
        Ok(c) => c,
        Err(e) if matches!(cli.cmd, Cmd::StopAgent) => {
            eprintln!("{e}");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let ctl = Controller::new(client);

    match cli.cmd {
        Cmd::Login {
            server,
            email,
            identity_url,
            api_url,
            insecure_allow_http,
            totp,
            totp_env,
            password,
        } => {
            let pw = read_password(&password, "Master password: ")?;
            let server = ServerConfig {
                base_url: server,
                identity_url,
                api_url,
                insecure_allow_http,
            };
            let mut code = match (totp, totp_env) {
                (Some(t), _) => Some(Sensitive::new(t)),
                (None, Some(var)) => Some(Sensitive::new(
                    std::env::var(&var).with_context(|| format!("{var} is not set"))?,
                )),
                _ => None,
            };
            loop {
                match ctl
                    .login(server.clone(), &email, pw.clone(), code.take())
                    .await?
                {
                    LoginOutcome::Success => {
                        eprintln!("Logged in and synced.");
                        return Ok(());
                    }
                    LoginOutcome::NeedsTotp => {
                        if !std::io::stdin().is_terminal() {
                            bail!(UiError {
                                kind: Some(ErrorKind::InvalidTwoFactor),
                                message: "two-factor code required (use --totp/--totp-env)".into()
                            });
                        }
                        let c = prompt_line("Authenticator code: ")?;
                        code = Some(Sensitive::new(c));
                    }
                }
            }
        }
        Cmd::Unlock { password } => {
            let pw = read_password(&password, "Master password: ")?;
            ctl.unlock(pw).await?;
            eprintln!("Unlocked.");
        }
        Cmd::Lock => {
            ctl.lock().await?;
            eprintln!("Locked.");
        }
        Cmd::Logout => {
            ctl.logout().await?;
            eprintln!("Logged out.");
        }
        Cmd::Status { json } => {
            let s = ctl.status().await?;
            if json {
                println!("{}", serde_json::to_string(&s)?);
            } else {
                let state = match s.state {
                    LockState::LoggedOut => "logged out",
                    LockState::Locked => "locked",
                    LockState::Unlocked => "unlocked",
                };
                println!("state: {state}");
                if let Some(e) = s.email {
                    println!("email: {e}");
                }
                if let Some(srv) = s.server {
                    println!("server: {srv}");
                }
                println!("auto-lock: {}s", s.auto_lock_seconds);
            }
        }
        Cmd::Sync => {
            ctl.sync().await?;
            eprintln!("Synced.");
        }
        Cmd::List { query, json } => {
            let mut m = VaultModel::default();
            m.set_items(ctl.list().await?);
            m.set_query(&query.join(" "));
            if json {
                let v: Vec<&ItemSummary> = m.visible().collect();
                println!("{}", serde_json::to_string(&v)?);
            } else {
                for i in m.visible() {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        i.id,
                        kind_label(i.kind),
                        i.name,
                        i.username.as_deref().unwrap_or(""),
                        i.uri_host.as_deref().unwrap_or("")
                    );
                }
            }
        }
        Cmd::Get { item, field, json } => {
            let it = find_item(&ctl, &item).await?;
            if json {
                let pw = ctl.secret(&it.id, SecretField::Password).await?;
                let notes = ctl.secret(&it.id, SecretField::Notes).await?;
                let seed = ctl.secret(&it.id, SecretField::TotpSeed).await?;
                let out = serde_json::json!({
                    "id": it.id, "kind": it.kind, "name": it.name, "username": it.username, "uri_host": it.uri_host,
                    "password": pw.as_ref().map(Sensitive::expose),
                    "notes": notes.as_ref().map(Sensitive::expose),
                    "totp": seed.as_ref().map(Sensitive::expose),
                });
                println!("{}", serde_json::to_string(&out)?);
                return Ok(());
            }
            let value: Option<String> = match field {
                GetField::Name => Some(it.name.clone()),
                GetField::Username => it.username.clone(),
                GetField::Uri => it.uri_host.clone(),
                GetField::Password => ctl
                    .secret(&it.id, SecretField::Password)
                    .await?
                    .map(|s| s.expose().to_owned()),
                GetField::Notes => ctl
                    .secret(&it.id, SecretField::Notes)
                    .await?
                    .map(|s| s.expose().to_owned()),
                GetField::TotpSeed => ctl
                    .secret(&it.id, SecretField::TotpSeed)
                    .await?
                    .map(|s| s.expose().to_owned()),
                GetField::Totp => Some(ctl.totp(&it.id).await?.0.expose().to_owned()),
            };
            let value = value.ok_or_else(|| UiError {
                kind: Some(ErrorKind::NotFound),
                message: "field is empty".into(),
            })?;
            let mut out = std::io::stdout().lock();
            out.write_all(value.as_bytes())?;
            out.write_all(b"\n")?;
            sangward_ipc::wipe(value.into_bytes());
        }
        Cmd::Copy {
            item,
            field,
            clear_after,
        } => {
            let it = find_item(&ctl, &item).await?;
            let target = match field {
                CopyField::Username => CopyTarget::Username,
                CopyField::Password => CopyTarget::Password,
                CopyField::Totp => CopyTarget::Totp,
            };
            let value = ctl.copy_value(&it, target).await?;
            let mut cb = sangward_platform::ArboardClipboard::new().map_err(|e| anyhow!(e))?;
            let after = Duration::from_secs(clear_after);
            eprintln!(
                "{}",
                sangward_client::clipboard::copied_message(target.label(), after)
            );
            // Linux clipboards are owned by a live process: serve it until the deadline, then clear if still ours.
            let value_s = value.expose().to_owned();
            let cleared = tokio::task::spawn_blocking(move || {
                let r = cb.copy_and_hold(&value_s, Instant::now() + after);
                sangward_ipc::wipe(value_s.into_bytes());
                r
            })
            .await?
            .map_err(|e| anyhow!(e))?;
            eprintln!(
                "{}",
                if cleared {
                    "Clipboard cleared."
                } else {
                    "Clipboard changed elsewhere; left untouched."
                }
            );
        }
        Cmd::AutoLock { seconds } => {
            ctl.set_auto_lock(seconds).await?;
            // Keep the shared setting in step so the GUI does not push an old
            // value back to the agent on its next launch.
            let mut settings = Settings::load();
            settings.auto_lock_secs = seconds;
            if let Err(e) = settings.save() {
                eprintln!("sangward: could not save settings: {e}");
            }
            eprintln!("Auto-lock set to {seconds}s.");
        }
        Cmd::StopAgent => {
            ctl.shutdown_agent().await?;
            eprintln!("Agent stopped.");
        }
    }
    Ok(())
}

async fn find_item(ctl: &Controller, key: &str) -> anyhow::Result<ItemSummary> {
    let items = ctl.list().await?;
    if let Some(i) = items.iter().find(|i| i.id == key) {
        return Ok(i.clone());
    }
    let by_name: Vec<_> = items.iter().filter(|i| i.name == key).collect();
    match by_name.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(UiError {
            kind: Some(ErrorKind::NotFound),
            message: format!("no item with id or name {key:?}"),
        }
        .into()),
        _ => Err(anyhow!("several items are named {key:?}; use the id")),
    }
}

fn read_password(src: &PasswordSource, prompt: &str) -> anyhow::Result<Sensitive> {
    let pw = if let Some(var) = &src.password_env {
        std::env::var(var).with_context(|| format!("{var} is not set"))?
    } else if src.password_stdin || !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\n', '\r']).to_owned();
        sangward_ipc::wipe(line.into_bytes());
        trimmed
    } else {
        rpassword::prompt_password(prompt)?
    };
    if pw.is_empty() {
        bail!("empty password");
    }
    Ok(Sensitive::new(pw))
}

fn prompt_line(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    Ok(s.trim().to_owned())
}
