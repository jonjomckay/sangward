# Security notes and known limitations

Sangward is an MVP. The design is in DEVELOPMENT.md ("Security model"). This file
lists what it does **not** protect against.

## Memory

- **Same-UID processes.** The agent sets `PR_SET_DUMPABLE=0`, which blocks
  ptrace and `/proc/<pid>/mem` for non-root same-UID processes and disables
  core dumps. Anything running as root, or as your user with
  `CAP_SYS_PTRACE`, can still read agent memory. If something re-enables
  dumpable (a `setuid`/`execve` transition, or a debugger attached before the
  `prctl`), ptrace protection is gone.
  A malicious process running as your UID can also simply connect to the
  socket: `SO_PEERCRED` only distinguishes UIDs, not programs. This is the
  same trust model as ssh-agent and gpg-agent.
- **mlock is best-effort.** Under a low `RLIMIT_MEMLOCK`, key pages can be
  swapped out. Use encrypted swap, or raise the limit.
- **Zeroization is best-effort.** Keys are zeroized on lock and drop. Decrypted
  field values pass through `String`s in serde/IPC buffers; the frame buffers
  we own are wiped, but copies made inside serde_json, reqwest, rustls or GTK
  (entry buffers, labels showing a revealed password) are outside our control.
- **Frontends hold plaintext briefly.** Passwords typed into the GUI live in
  GTK entry buffers until cleared. A revealed password stays in a GTK label
  until you hide it, select another item, or lock.
- The **master key** exists only during login/unlock and is dropped
  (zeroized) right after the user key is decrypted.

## Clipboard

- On Linux, any process in your session can read the clipboard while the
  secret is on it.
- `x-kde-passwordManagerHint: secret` is honoured by Klipper and some other
  managers; others may still record the entry.
- Auto-clear happens only while the owning process runs. The GUI clears on
  quit and lock. `sangward copy` stays in the foreground until the timer fires;
  if you kill it, the clipboard owner dies too, which on most compositors
  clears the selection anyway.
- The "still ours" check compares provider identity (GTK) or contents
  (arboard). If you copy the same value again from elsewhere, the clear still
  happens.

## Storage and network

- The cache holds server-side-encrypted data (EncStrings), so offline brute
  force of the master password is possible from it, just as with every
  Bitwarden client cache. Strong KDF settings (Argon2id) and a strong master
  password are the defence.
- The refresh token in the Secret Service is protected only as well as your
  keyring (usually unlocked at login).
- `--insecure-allow-http` sends the master password *hash* and tokens in
  cleartext. Only use it on trusted networks.
- Only the authenticator-app (TOTP) 2FA provider is supported. Accounts that
  require only other providers can't log in.
- The test harness uses a throwaway CA under `target/harness/tls/`. It is
  trusted only by harness processes (via `SSL_CERT_FILE` and
  `NODE_EXTRA_CA_CERTS`) and never installed system-wide.

## Not implemented

- No cipher-integrity verification beyond EncString MACs. A malicious server
  can still drop or reorder items.
- No per-item reprompt; Bitwarden's "master password reprompt" flag is ignored.
- Legacy unauthenticated EncString type 0 is rejected rather than decrypted.
