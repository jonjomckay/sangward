# Developing Sangward

This file is for working on Sangward itself. The user guide is in
[README.md](README.md), design decisions are in [DECISIONS.md](DECISIONS.md),
and security notes are in [SECURITY.md](SECURITY.md).

## Dev environment

All tools come from devenv (`devenv.nix`): Rust, GTK/libadwaita, Vaultwarden,
the official `bw` CLI, Xvfb and `just`. Don't install them any other way.

```sh
cargo build
./target/debug/sangward-gtk          # GUI (auto-starts the agent)
just check                           # the whole unattended test pipeline
```

## Architecture

```
            ┌──────────────┐   ┌──────────────┐   ┌ ─ ─ ─ ─ ─ ─ ─ ┐
 frontends  │ sangward-gtk │   │ sangward-cli │     future Slint/Qt
            │ Relm4 + adw  │   │ (`sangward`) │   └ ─ ─ ─ ─ ─ ─ ─ ┘
            └──┬────────┬──┘   └──┬────────┬──┘           │
               │        │         │        │              │
               ▼        ▼         ▼        ▼              ▼
     ┌─────────────────────┐   ┌───────────────────────────────┐
     │  sangward-client    │   │  sangward-platform            │
     │  state machine,     │   │  traits: SecretStore, Tray,   │
     │  search, auto-clear,│   │  Clipboard; Linux impls: oo7, │
     │  settings, spawn    │   │  ksni, arboard (+ in-memory)  │
     └─────────┬───────────┘   └───────────────▲───────────────┘
               ▼                               │
     ┌─────────────────────┐                   │
     │  sangward-ipc       │  length-prefixed JSON over a Unix socket
     │  protocol + client  │  $XDG_RUNTIME_DIR/sangward/agent.sock
     └─────────┬───────────┘                   │
 ════════════ process boundary ════════════════│═══════════════════════
               ▼                               │
     ┌─────────────────────┐                   │
     │  sangward-agent     │───────────────────┘ (SecretStore only)
     │  holds keys, serves │
     │  IPC, auto-lock     │
     └─────────┬───────────┘
               ▼
     ┌─────────────────────┐
     │  sangward-core      │  API client (reqwest+rustls), KDF/crypto,
     │                     │  sync models, encrypted cache
     └─────────────────────┘
```

Dependency rules (checked with `cargo tree`; frontends cannot reach `sangward-core`):

| Crate | Kind | Depends on |
|---|---|---|
| `sangward-core` | lib | no UI or IPC crates |
| `sangward-ipc` | lib | serde, serde_json, tokio |
| `sangward-client` | lib | sangward-ipc |
| `sangward-platform` | lib | toolkit-agnostic (oo7, ksni, arboard) |
| `sangward-agent` | bin | core, ipc, platform |
| `sangward-cli` | bin | ipc, client, platform |
| `sangward-gtk` | bin | ipc, client, platform, relm4 |

Frontends never touch crypto, HTTP or the cache. Everything goes through the
agent. The CLI is a full frontend, and the e2e suite drives the agent only
through it.

## Security model

[SECURITY.md](SECURITY.md) lists the limitations.

- **Agent process**: `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` at startup.
  Socket directory 0700, socket 0600. Every connection's `SO_PEERCRED` UID must
  equal the agent's UID, or it is refused.
- **Keys**: the user key and org keys live in `secrecy::SecretBox`, are
  `mlock`ed when the kernel allows it, and are zeroized on lock, on auto-lock
  (default 15 min of inactivity; status polling doesn't count) and on exit.
- **Vault stays encrypted** in memory and on disk. `List` decrypts only name,
  username and URI host. Passwords, notes and TOTP seeds are decrypted one
  field at a time on `GetSecret`/`GenerateTotp`.
- **Master password**: sent from the frontend to the agent once per unlock and
  never persisted. Unlock verifies it locally (the MAC on the protected user
  key), then refreshes the access token silently with the stored refresh token.
- **Keychain** (Secret Service via oo7) holds only the refresh token and device
  identifier, keyed by server URL + email.
- **Cache** `$XDG_DATA_HOME/sangward/vault.json` (0600, directory 0700): the
  protected user key, encrypted private key, KDF params and raw sync response.
  It is useless without the master password.
- **TLS**: rustls with the system trust store (rustls-platform-verifier). Plain
  `http://` is refused except for `localhost`/`127.0.0.1`/`::1`, or with
  `--insecure-allow-http`.
- **Clipboard**: owned by the frontend. Entries carry
  `x-kde-passwordManagerHint: secret`, and after 30 s the clipboard is cleared
  only if it still holds our value.
- **Logging**: `tracing`; secret-bearing types have redacted `Debug`. The e2e
  run greps every captured log for every test password, note, TOTP seed and
  token.

## Runtime knobs

| Variable / flag | Effect |
|---|---|
| `SANGWARD_SOCKET` / `--socket` | Agent socket path. |
| `SANGWARD_AGENT_BIN` | Agent binary to spawn (default: next to the frontend, then `$PATH`). |
| `SANGWARD_DATA_DIR` | Cache directory (default `$XDG_DATA_HOME/sangward`). |
| `SANGWARD_SECRET_STORE` / `--secret-store` | `secret-service` (default) or `memory` (tests). |
| `SANGWARD_AUTO_LOCK_SECS` | Agent auto-lock timeout (default 900). |
| `SANGWARD_LOG` | `tracing` filter (agent default `info`, frontends `warn`). |
| `SANGWARD_AGENT_LOG` | File for a spawned agent's output (default: discarded). |
| `SANGWARD_GTK_AGENT_ARGS` | Extra args for an agent spawned by the GUI. |
| `SSL_CERT_FILE` | Extra CA for the agent (private CAs, the test harness). |

### Running the agent under systemd instead of auto-spawn

Frontends spawn `sangward-agent` only if nothing answers on the socket, so a
user unit can replace auto-spawn:

```ini
# ~/.config/systemd/user/sangward-agent.service
[Service]
ExecStart=%h/.local/bin/sangward-agent --socket %t/sangward/agent.sock
```

## Testing

| Recipe | What it does |
|---|---|
| `just harness-up` / `harness-down` | Throwaway Vaultwarden (`vaultwarden` binary from devenv, TLS with a throwaway CA, fresh `mktemp -d` data dir). PID in `target/vaultwarden.pid`. |
| `just seed` | Registers a PBKDF2 user and an Argon2id user with **Sangward's crypto** (`sangward-testkit register`, feature `test-support`). Then the **official `bw` CLI** logs in and creates the items (logins, TOTP, notes, unicode, one org-owned item). Enables TOTP 2FA on the Argon2id user, and imports a 5000-item vault for a third user (`scripts/seed-large.sh`). Writes `target/fixtures.json` and bw-encrypted vectors. |
| `just test` | Unit and integration tests, including decrypting the bw-encrypted vectors. |
| `just capture-vectors` | Copies freshly captured vectors from `target/vectors` into `crates/sangward-core/tests/vectors/`, used by plain `cargo test`. |
| `just e2e` | Agent with the in-memory SecretStore and temp XDG dirs, driven by `sangward`: 2FA login, sync/list/get vs fixtures, lock/unlock, wrong password, auto-lock, peer-UID check, large-vault responsiveness, log-leak grep. |
| `just gtk-smoke` | `sangward-gtk` under `xvfb-run` with a private D-Bus; it must reach the login screen. |
| `just gtk-ui [scenario]` | In-process UI tests (`crates/sangward-gtk/tests/ui.rs`): launches the real `App`, finds widgets by `sangward_gtk::names`, drives them, and pumps the GLib loop. Checks login/unlock progress feedback, and a 16 ms heartbeat measures the longest main-loop stall, which must stay under `SW_UI_MAX_STALL_MS` on the 5000-item vault. |
| `just check` | All of the above plus `clippy -D warnings` and `fmt --check`; always runs harness-down. |

The cross-validation runs both ways: our client decrypts data encrypted by the
official client, and the official client logs into accounts registered with
our crypto.

Harness settings (ports, test users, budgets) are the `SW_*` variables in
`devenv.nix`. The test passwords and admin token there are throwaway values
for the local harness only.

## Adding another frontend

1. Create `crates/sangward-<toolkit>` that depends on `sangward-ipc`,
   `sangward-client` and `sangward-platform`, and **not** `sangward-core`.
2. Call `sangward_client::spawn::ensure_agent` to connect (spawning the agent if
   needed) and wrap the result in a `sangward_client::Controller`.
3. Drive the UI from `AppState`, `VaultModel` (items, search, selection) and
   `Controller` (login/unlock/lock/sync/list/secret/totp/copy_value).
4. Implement `sangward_platform::Clipboard` for your toolkit's clipboard (see
   `sangward-gtk/src/clipboard.rs`), or use `ArboardClipboard`. Schedule clears
   with `sangward_client::AutoClear`.
5. Use `sangward_platform::KsniTray` and react to `TrayCommand`s from its
   channel.

`sangward-gtk/src/app.rs` is the reference. It's mostly widget construction,
with no crypto, HTTP or search logic.
