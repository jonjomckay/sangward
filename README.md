# keyward

A native desktop client for **self-hosted Bitwarden-compatible servers**
(Vaultwarden and official self-hosted Bitwarden), written in Rust. Linux first.
keyward is an independent project, not affiliated with Bitwarden Inc.; it is
compatible with Bitwarden/Vaultwarden servers.

MVP features: email + master password login (plus authenticator-app 2FA),
lock/unlock, sync, a read-only view of Login items and Secure Notes with
search, copy username/password/TOTP with clipboard auto-clear, tray icon, and
the refresh token kept in the OS keychain.

## Quick start

All tools come from devenv (`devenv.nix`); inside the dev shell:

```sh
cargo build --release
./target/release/keyward-gtk                  # GUI (auto-starts the agent)
./target/release/keyward login --server https://vault.example.com --email you@example.com
./target/release/keyward list github
./target/release/keyward copy GitHub --field totp
```

`just check` runs the whole unattended test pipeline against a throwaway Vaultwarden.

## Architecture

```
            ┌──────────────┐   ┌──────────────┐   ┌ ─ ─ ─ ─ ─ ─ ─ ┐
 frontends  │ keyward-gtk  │   │ keyward-cli  │     future Slint/Qt
            │ Relm4 + adw  │   │ (`keyward`)  │   └ ─ ─ ─ ─ ─ ─ ─ ┘
            └──┬────────┬──┘   └──┬────────┬──┘           │
               │        │         │        │              │
               ▼        ▼         ▼        ▼              ▼
     ┌─────────────────────┐   ┌───────────────────────────────┐
     │  keyward-client     │   │  keyward-platform             │
     │  state machine,     │   │  traits: SecretStore, Tray,   │
     │  search, auto-clear,│   │  Clipboard; Linux impls: oo7, │
     │  settings, spawn    │   │  ksni, arboard (+ in-memory)  │
     └─────────┬───────────┘   └───────────────▲───────────────┘
               ▼                               │
     ┌─────────────────────┐                   │
     │  keyward-ipc        │  length-prefixed JSON over a Unix socket
     │  protocol + client  │  $XDG_RUNTIME_DIR/keyward/agent.sock
     └─────────┬───────────┘                   │
 ════════════ process boundary ════════════════│═══════════════════════
               ▼                               │
     ┌─────────────────────┐                   │
     │  keyward-agent      │───────────────────┘ (SecretStore only)
     │  holds keys, serves │
     │  IPC, auto-lock     │
     └─────────┬───────────┘
               ▼
     ┌─────────────────────┐
     │  keyward-core       │  API client (reqwest+rustls), KDF/crypto,
     │                     │  sync models, encrypted cache
     └─────────────────────┘
```

Dependency rules (checked with `cargo tree`; frontends cannot reach `keyward-core`):

| Crate | Kind | Depends on |
|---|---|---|
| `keyward-core` | lib | no UI or IPC crates |
| `keyward-ipc` | lib | serde, serde_json, tokio |
| `keyward-client` | lib | keyward-ipc |
| `keyward-platform` | lib | toolkit-agnostic (oo7, ksni, arboard) |
| `keyward-agent` | bin | core, ipc, platform |
| `keyward-cli` | bin | ipc, client, platform |
| `keyward-gtk` | bin | ipc, client, platform, relm4 |

Frontends never touch crypto, HTTP or the cache. Everything goes through the
agent. The CLI is a full frontend, and the e2e suite drives the agent only
through it.

## Security model (summary)

See [SECURITY.md](SECURITY.md) for the limitations.

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
- **Cache** `$XDG_DATA_HOME/keyward/vault.json` (0600, directory 0700): the
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

## Using it with a real self-hosted server

```sh
keyward login --server https://vault.example.com --email you@example.com
# split deployments:
keyward login --server https://vault.example.com \
  --identity-url https://id.example.com --api-url https://api.example.com --email you@example.com
keyward status
keyward unlock          # after lock / auto-lock / restart: master password only
keyward lock
keyward auto-lock 600   # seconds
keyward stop-agent
```

- The server must be reachable over HTTPS with a certificate your system
  trusts. For a private CA, install it into the system store, or set
  `SSL_CERT_FILE` for the agent.
- A Secret Service provider (GNOME Keyring, KWallet's Secret Service bridge,
  or KeePassXC) must be running for the refresh token to persist across agent
  restarts. Without one, unlock still works from the cache, but syncing after
  an agent restart needs a fresh `keyward login`.
- **Tray**: keyward uses StatusNotifierItem. KDE and most wlroots bars support
  it natively. **GNOME needs the AppIndicator/KStatusNotifierItem extension.**
  Without a tray, closing the window quits the app.
- **Quit behaviour**: by default, Quit (tray or menu) locks and stops the
  agent. Tick "Keep agent running after quit" in the menu to leave it running.
  It still auto-locks.

### Running the agent under systemd instead of auto-spawn

Frontends spawn `keyward-agent` only if nothing answers on the socket, so a user unit can replace auto-spawn:

```ini
# ~/.config/systemd/user/keyward-agent.service
[Service]
ExecStart=%h/.local/bin/keyward-agent --socket %t/keyward/agent.sock
```

## Testing

| Recipe | What it does |
|---|---|
| `just harness-up` / `harness-down` | Throwaway Vaultwarden (`vaultwarden` binary from devenv, TLS with a throwaway CA, fresh `mktemp -d` data dir). PID in `target/vaultwarden.pid`. |
| `just seed` | Registers a PBKDF2 user and an Argon2id user with **keyward's crypto** (`keyward-testkit register`, feature `test-support`). Then the **official `bw` CLI** logs in and creates the items (logins, TOTP, notes, unicode, one org-owned item). Enables TOTP 2FA on the Argon2id user. Writes `target/fixtures.json` and bw-encrypted vectors. |
| `just test` | Unit and integration tests, including decrypting the bw-encrypted vectors. |
| `just e2e` | Agent with the in-memory SecretStore and temp XDG dirs, driven by `keyward`: 2FA login, sync/list/get vs fixtures, lock/unlock, wrong password, auto-lock, peer-UID check, log-leak grep. |
| `just gtk-smoke` | `keyward-gtk` under `xvfb-run` with a private D-Bus; it must reach the login screen. |
| `just gtk-ui [scenario]` | In-process UI tests (`crates/keyward-gtk/tests/ui.rs`): launches the real `App`, finds widgets by `keyward_gtk::names`, drives them, and pumps the GLib loop. A 16 ms heartbeat measures the longest main-loop stall, which must stay under `KW_UI_MAX_STALL_MS` on a 5000-item vault (`scripts/seed-large.sh`). |
| `just check` | All of the above plus `clippy -D warnings` and `fmt --check`; always runs harness-down. |

The cross-validation runs both ways: our client decrypts data encrypted by the
official client, and the official client logs into accounts registered with
our crypto.

## Adding another frontend

1. Create `crates/keyward-<toolkit>` that depends on `keyward-ipc`,
   `keyward-client` and `keyward-platform`, and **not** `keyward-core`.
2. Call `keyward_client::spawn::ensure_agent` to connect (spawning the agent if
   needed) and wrap the result in a `keyward_client::Controller`.
3. Drive the UI from `AppState`, `VaultModel` (items, search, selection) and
   `Controller` (login/unlock/lock/sync/list/secret/totp/copy_value).
4. Implement `keyward_platform::Clipboard` for your toolkit's clipboard (see
   `keyward-gtk/src/clipboard.rs`), or use `ArboardClipboard`. Schedule clears
   with `keyward_client::AutoClear`.
5. Use `keyward_platform::KsniTray` and react to `TrayCommand`s from its
   channel.

`keyward-gtk/src/main.rs` is the reference: about 1,000 lines, almost all
widget construction, with no crypto, HTTP or search logic.
