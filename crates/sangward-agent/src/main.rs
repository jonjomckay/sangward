//! sangward-agent: holds key material and serves the IPC socket.
//!
//! Designed to be started either on demand by a frontend (which detaches it)
//! or by a systemd user unit (`--socket` / `SANGWARD_SOCKET` set explicitly,
//! logs to stderr -> journal).

mod hardening;
mod state;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, ValueEnum};
use sangward_core::cache::{Cache, default_data_dir};
use sangward_ipc::{ErrorKind, Request, Response, read_frame, write_frame};
use sangward_platform::{InMemorySecretStore, Oo7SecretStore, SecretStore};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::state::Agent;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SecretStoreKind {
    /// Freedesktop Secret Service via oo7 (GNOME Keyring, KWallet, KeePassXC).
    SecretService,
    /// Process memory only; for tests. Refresh tokens die with the agent.
    Memory,
}

#[derive(Parser, Debug)]
#[command(
    name = "sangward-agent",
    version,
    about = "sangward agent: holds vault keys and serves frontends over a Unix socket"
)]
struct Args {
    /// Socket path (default: $XDG_RUNTIME_DIR/sangward/agent.sock).
    #[arg(long, env = "SANGWARD_SOCKET")]
    socket: Option<PathBuf>,
    /// Data directory for the encrypted cache (default: $XDG_DATA_HOME/sangward).
    #[arg(long, env = "SANGWARD_DATA_DIR")]
    data_dir: Option<PathBuf>,
    /// Lock after this many seconds without activity.
    #[arg(long, env = "SANGWARD_AUTO_LOCK_SECS", default_value_t = 900)]
    auto_lock_secs: u64,
    #[arg(
        long,
        value_enum,
        env = "SANGWARD_SECRET_STORE",
        default_value = "secret-service"
    )]
    secret_store: SecretStoreKind,
}

#[tokio::main]
async fn main() {
    init_logging();
    hardening::harden_process();
    if let Err(e) = run(Args::parse()).await {
        tracing::error!("{e:#}");
        std::process::exit(1);
    }
}

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("SANGWARD_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

async fn run(args: Args) -> anyhow::Result<()> {
    if args.auto_lock_secs == 0 {
        bail!("--auto-lock-secs must be > 0");
    }
    let socket = args
        .socket
        .unwrap_or_else(sangward_ipc::default_socket_path);
    let data_dir = args.data_dir.unwrap_or_else(default_data_dir);
    let secrets: Arc<dyn SecretStore> = match args.secret_store {
        SecretStoreKind::SecretService => Arc::new(Oo7SecretStore::new()),
        SecretStoreKind::Memory => Arc::new(InMemorySecretStore::new()),
    };

    let listener = bind(&socket).await?;
    tracing::info!(socket = %socket.display(), dumpable = hardening::is_dumpable(), store = ?args.secret_store, auto_lock_secs = args.auto_lock_secs, "agent listening");

    let agent = Arc::new(Mutex::new(Agent::new(
        Cache::new(&data_dir),
        secrets,
        Duration::from_secs(args.auto_lock_secs),
    )));
    let our_uid = hardening::current_uid();
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);

    // Auto-lock ticker.
    {
        let agent = agent.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(500));
            loop {
                iv.tick().await;
                agent.lock().await.tick();
            }
        });
    }

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(s) => s,
                    Err(e) => { tracing::warn!(error = %e, "accept failed"); continue; }
                };
                let agent = agent.clone();
                let stop_tx = stop_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve(stream, our_uid, agent, stop_tx).await {
                        tracing::debug!(error = %e, "connection ended with error");
                    }
                });
            }
            _ = stop_rx.changed() => break,
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
        }
    }
    agent.lock().await.lock();
    let _ = std::fs::remove_file(&socket);
    tracing::info!("agent stopped");
    Ok(())
}

/// Bind the socket, refusing to steal it from a live agent.
async fn bind(socket: &std::path::Path) -> anyhow::Result<UnixListener> {
    let dir = socket
        .parent()
        .context("socket path has no parent directory")?;
    hardening::prepare_socket_dir(dir).with_context(|| format!("preparing {}", dir.display()))?;
    if socket.exists() {
        if UnixStream::connect(socket).await.is_ok() {
            bail!("another agent is already listening on {}", socket.display());
        }
        std::fs::remove_file(socket)
            .with_context(|| format!("removing stale socket {}", socket.display()))?;
    }
    let listener =
        UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serve one connection. `our_uid` is the UID peers must match; it is a
/// parameter (not read inside) so tests can exercise the rejection path over a
/// real socket without needing a second user account.
async fn serve(
    mut stream: UnixStream,
    our_uid: u32,
    agent: Arc<Mutex<Agent>>,
    stop: tokio::sync::watch::Sender<bool>,
) -> Result<(), sangward_ipc::IpcError> {
    // SO_PEERCRED: reject any peer that is not our own UID.
    let cred = stream.peer_cred()?;
    if !hardening::peer_allowed(cred.uid(), our_uid) {
        tracing::warn!(peer_uid = cred.uid(), peer_pid = ?cred.pid(), "rejected connection from foreign uid");
        let _ = write_frame(
            &mut stream,
            &Response::error(ErrorKind::Policy, "permission denied"),
        )
        .await;
        return Ok(());
    }
    while let Some(req) = read_frame::<_, Request>(&mut stream).await? {
        let shutdown = matches!(req, Request::Shutdown);
        let resp = agent.lock().await.handle(req).await;
        write_frame(&mut stream, &resp).await?;
        if shutdown {
            let _ = stop.send(true);
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sangward_ipc::{Client, LockState};

    async fn agent_on_socket(
        dir: &std::path::Path,
        required_uid: u32,
    ) -> (PathBuf, tokio::task::JoinHandle<()>) {
        let socket = dir.join("run/agent.sock");
        let listener = bind(&socket).await.unwrap();
        let agent = Arc::new(Mutex::new(Agent::new(
            Cache::new(dir.join("data")),
            Arc::new(InMemorySecretStore::new()),
            Duration::from_secs(900),
        )));
        let (tx, _rx) = tokio::sync::watch::channel(false);
        let h = tokio::spawn(async move {
            loop {
                let (s, _) = listener.accept().await.unwrap();
                let _ = serve(s, required_uid, agent.clone(), tx.clone()).await;
            }
        });
        (socket, h)
    }

    /// Real socket, real SO_PEERCRED: the agent requires a UID we are not, so it must refuse.
    #[tokio::test]
    async fn foreign_uid_is_rejected_over_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let foreign = hardening::current_uid().wrapping_add(1);
        let (socket, h) = agent_on_socket(tmp.path(), foreign).await;
        let err = Client::new(&socket).status().await.unwrap_err();
        assert_eq!(err.kind(), Some(ErrorKind::Policy), "{err}");
        h.abort();
    }

    #[tokio::test]
    async fn own_uid_is_served_and_socket_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let (socket, h) = agent_on_socket(tmp.path(), hardening::current_uid()).await;
        let st = Client::new(&socket).status().await.unwrap();
        assert_eq!(st.state, LockState::LoggedOut);
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(socket.parent().unwrap()), 0o700);
        assert_eq!(mode(&socket), 0o600);
        // A second agent must refuse to steal a live socket.
        assert!(bind(&socket).await.is_err());
        h.abort();
    }
}
