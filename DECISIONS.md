# Decisions

Judgement calls made while building the MVP, roughly in order of impact.

## Test harness

- **Vaultwarden runs with TLS.** The official Bitwarden CLI (2026.8) refuses
  any non-`https://` server (`InsecureUrlNotAllowedError`; plain http is
  allowed only in dev builds). `harness-up` therefore generates a throwaway CA
  and a localhost cert with `openssl` (declared in `devenv.nix`) and starts
  Vaultwarden with `ROCKET_TLS`. `SW_VW_URL` is `https://localhost:8087`. Our
  client trusts the CA via `SSL_CERT_FILE` (honoured by
  rustls-platform-verifier on Linux) and bw via `NODE_EXTRA_CA_CERTS`. Plain
  http to loopback is still covered by unit tests.
- **`sangward-testkit` binary** in `sangward-core`, behind
  `required-features = ["test-support"]`. It wraps the test-only `register`,
  `enable-totp`, `create-org`, `dump-sync` and `totp` helpers so the shell
  scripts can call them. It is never built into normal binaries. Passwords
  reach it through env-var names, never argv.
- **Vectors.** `seed` captures bw-encrypted data plus the expected plaintext
  into `target/vectors/`. `just test` uses those fresh captures, and
  committed copies in `crates/sangward-core/tests/vectors/` keep plain
  `cargo test` meaningful without a server. `just capture-vectors` refreshes
  them. The vectors contain only throwaway harness credentials.
- **Per-cipher keys.** bw 2026.8 against Vaultwarden 1.37 does not emit
  per-cipher `key` fields, so bw-generated data can't exercise that path. A
  test re-wraps a bw-created cipher under a fresh cipher key using our
  primitives. This is the only round-trip test, and it covers a code path the
  cross-validation cannot reach.
- **Org-owned items**: `create-org` builds an organization with our crypto
  (org key RSA-OAEP-SHA1-wrapped to the owner's public key). bw then creates an
  item in it, and our agent decrypts it.
- **Peer-UID check.** A second real UID needs root, so the agent test binds a
  real socket and runs `serve` with a required UID one higher than ours.
  Real `SO_PEERCRED` then rejects the connection. The e2e step runs that test
  and also asserts that our own connections were never rejected.
- **TOTP step reuse.** Vaultwarden rejects a code whose 30 s step was already
  used. e2e retries on the next step.
- **gtk-smoke** uses a minimal private `dbus-daemon` config written to the
  temp dir, because Nix's dbus has no `/etc/dbus-1/session.conf` on non-NixOS
  hosts and the host's session config would activate portals. `GDK_BACKEND=x11`
  under `xvfb-run`; success means the process stays alive until the timeout
  and logs `screen changed screen="login"`.
- **GTK UI tests** run in-process (`harness = false`, because GTK needs the main
  thread) against a real agent and Vaultwarden, not a fake IPC server. That
  way the timings include real decryption. The stall meter is a 16 ms
  `timeout_add_local` heartbeat, and the worst gap must stay under
  `SW_UI_MAX_STALL_MS` (150 ms, release build under Xvfb). AT-SPI (dogtail)
  and NixOS VM tests were considered. AT-SPI adds Python and a11y-bus
  flakiness. A VM test would be the right tool for tray, Secret Service and
  real clipboard managers, but it needs KVM and is too slow for `just check`.
- **Large vault**: 5000 items generated as a Bitwarden JSON export and loaded
  with `bw import` (~18 s), so they're encrypted by the official client.
- **Vault list** is a virtualized `gtk::ListView` over a `gio::ListStore`.
  Filtering goes through a `CustomFilter` calling `sangward_client::matches`.
  The store is repopulated only when `VaultModel::generation()` changes.
  The old `ListBox` built one `AdwActionRow` per item on every update, which
  froze the UI for 1.6 s with 5000 items.
- **Submit feedback**: the login, TOTP and unlock buttons show a spinner with
  a label ("Logging in…", "Unlocking…", then "Opening vault…"), and the form's
  inputs are disabled meanwhile. The form stays on screen until the item list
  has arrived, so the vault never flashes up empty. I chose an in-button
  spinner over a separate loading screen because it keeps the user's context
  and the wait is usually under a second. On failure the password is kept,
  selected and refocused.
- PBKDF2 test users use 100 000 iterations (Vaultwarden's minimum) and
  Argon2id uses m=64 MiB, t=3, p=4, to keep the harness fast.

## Protocol / crypto

- Server JSON keys are normalized (first letter lower-cased, recursively)
  before deserializing, so PascalCase (older official servers) and camelCase
  (Vaultwarden) share one set of structs. Unknown fields and cipher types are
  ignored, and an undecryptable item is skipped with a warning instead of
  failing the list.
- `Bitwarden-Client-Name: desktop`, `Bitwarden-Client-Version: 2025.6.0`,
  `deviceType=8`, `Auth-Email` header on the password grant (the official
  server wants it).
- Only the TOTP 2FA provider (0) is supported. Login to an account offering
  no TOTP fails with a clear message.
- Legacy EncString type 0 (no MAC) is rejected.
- RSA types 3/5 use OAEP-SHA256 and 4/6 use OAEP-SHA1. The legacy MAC on
  types 5/6 is ignored, matching other clients.
- Steam TOTP is supported via `steam://<secret>` and otpauth URIs with
  `issuer=Steam`/`algorithm=STEAM` (totp-rs `steam` feature).

## Agent / IPC

- One request per connection by default; the server also accepts several
  frames per connection. JSON with a 4-byte big-endian length prefix and a
  16 MiB cap.
- `sangward-ipc::Sensitive` is a dependency-free secret string (redacted
  `Debug`, volatile wipe on drop), so the IPC crate stays serde + tokio only.
- One account per agent. Logging in again replaces the cached account.
- The keychain entry is a single Secret Service item per (server, email)
  holding JSON `{device_id, refresh_token}`.
- Exit codes: Locked=3, LoggedOut=4, InvalidCredentials=5,
  InvalidTwoFactor=6, NotFound=7, Network=8, Policy=9.
- `Status`/`Ping` don't reset the inactivity timer, so GUI polling can't keep
  the vault unlocked forever.
- After an agent restart with the in-memory store, unlock still works from the
  cache, but sync reports "log in again". With the Secret Service store, the
  refresh token survives restarts.

## Frontends

- The GTK clipboard clear checks provider identity (`gdk::Clipboard::content()
  == our provider && is_local()`) instead of reading the clipboard back.
- The CLI copies with `arboard` (`exclude_from_history` adds the KDE hint) and
  serves the clipboard until the clear deadline, because a Linux clipboard
  dies with its owner process.
- Whether the agent keeps running after the GUI quits is a setting
  (`keep_agent_running`, default false = lock and stop), stored in
  `$XDG_CONFIG_HOME/sangward/settings.json` by `sangward-client::Settings`, so
  every frontend shares it.
- Without a tray (no StatusNotifierWatcher), closing the window quits instead
  of hiding, so the app can't become unreachable.
- Relm4 traces component messages with `Debug`. The GTK `Cmd` enum therefore
  prints only variant names, and secret-bearing `Msg` payloads use
  `Sensitive`.

## Libraries and docs

Context7 had current docs for: devenv, relm4, gtk4-rs (only README-level for
`gdk::Clipboard`), libadwaita, reqwest, tokio, totp-rs, argon2, secrecy,
zeroize, rustls, serde, tracing, just, Vaultwarden, Bitwarden CLI.

**Not in Context7** (so I read the pinned crate sources in `~/.cargo/registry`
or the upstream repo instead):

- **oo7 0.5.0**: `Keyring::{new, search_items, create_item, delete}`.
- **ksni 0.3.6**: the `blocking` API also needs the `tokio` feature.
- **rsa 0.9.10**: no Context7 entry; used docs.rs-equivalent sources.
- **arboard 3.6.1**: `SetExtLinux::{exclude_from_history, wait_until}`.
- **rbw**: no Context7 entry. Request shapes follow Vaultwarden 1.37.3's
  source (`src/api/identity.rs`, `src/api/core/accounts.rs`,
  `two_factor/authenticator.rs`).
- **gdk4 0.11.5**: `ContentProvider::{for_bytes, new_union}` and
  `Clipboard::{content, is_local, set_content}`, read from source.

Versions are pinned exactly (`=x.y.z`) in the workspace `Cargo.toml`. The
RustCrypto crates stay on the stable 0.8/0.10/0.12 line (`aes`, `cbc`, `sha2`,
`hmac`, `hkdf`, `pbkdf2`, `rsa` 0.9, `rand` 0.8) because `rsa` 0.10 is still a
release candidate and mixing trait generations doesn't compile.
