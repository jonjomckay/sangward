//! Locate and auto-spawn `keyward-agent`.
//!
//! Frontends call [`ensure_agent`] before talking to the agent. If the socket
//! is absent (or stale) we start `keyward-agent` detached and wait for it. A
//! systemd user unit can replace this: if the socket is already served, we
//! never spawn anything.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use keyward_ipc::Client;

#[derive(Debug, Clone)]
pub struct SpawnOptions {
    /// Explicit agent binary; default: `KEYWARD_AGENT_BIN`, then next to the
    /// current executable, then `$PATH`.
    pub agent_bin: Option<PathBuf>,
    /// Extra args passed to the agent (e.g. `--secret-store memory`).
    pub extra_args: Vec<String>,
    /// Never spawn; just fail if the agent isn't running.
    pub no_spawn: bool,
    pub timeout: Duration,
}

impl Default for SpawnOptions {
    fn default() -> Self {
        Self {
            agent_bin: None,
            extra_args: Vec::new(),
            no_spawn: false,
            timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug)]
pub enum SpawnError {
    NotRunning(PathBuf),
    Spawn(std::io::Error, PathBuf),
    Timeout(PathBuf),
}

impl std::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnError::NotRunning(p) => write!(
                f,
                "keyward-agent is not running (no socket at {})",
                p.display()
            ),
            SpawnError::Spawn(e, bin) => write!(f, "could not start {}: {e}", bin.display()),
            SpawnError::Timeout(p) => write!(f, "keyward-agent did not come up on {}", p.display()),
        }
    }
}

impl std::error::Error for SpawnError {}

fn agent_binary(opts: &SpawnOptions) -> PathBuf {
    if let Some(b) = &opts.agent_bin {
        return b.clone();
    }
    if let Some(b) = std::env::var_os("KEYWARD_AGENT_BIN") {
        return PathBuf::from(b);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("keyward-agent");
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from("keyward-agent")
}

async fn alive(client: &Client) -> bool {
    client.ping().await.is_ok()
}

/// Ensure an agent serves `socket`, spawning one if needed.
pub async fn ensure_agent(socket: &Path, opts: &SpawnOptions) -> Result<Client, SpawnError> {
    let client = Client::new(socket);
    if alive(&client).await {
        return Ok(client);
    }
    if opts.no_spawn {
        return Err(SpawnError::NotRunning(socket.to_owned()));
    }
    let bin = agent_binary(opts);
    tracing::debug!(bin = %bin.display(), "spawning agent");
    let mut cmd = Command::new(&bin);
    cmd.arg("--socket")
        .arg(socket)
        .args(&opts.extra_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    // Keep agent logs if the caller redirected them (KEYWARD_AGENT_LOG), else discard.
    match std::env::var_os("KEYWARD_AGENT_LOG") {
        Some(path) => {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| SpawnError::Spawn(e, bin.clone()))?;
            cmd.stderr(f);
        }
        None => {
            cmd.stderr(Stdio::null());
        }
    }
    // Own process group: the agent survives the frontend's terminal/Ctrl-C.
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
    let mut child = cmd.spawn().map_err(|e| SpawnError::Spawn(e, bin.clone()))?;

    let start = Instant::now();
    while start.elapsed() < opts.timeout {
        if alive(&client).await {
            // Reap in the background so it never becomes a zombie of ours.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok(client);
        }
        if let Ok(Some(status)) = child.try_wait() {
            // Another agent may have won a race; accept it if it answers.
            if alive(&client).await {
                return Ok(client);
            }
            return Err(SpawnError::Spawn(
                std::io::Error::other(format!("agent exited with {status}")),
                bin,
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(SpawnError::Timeout(socket.to_owned()))
}
