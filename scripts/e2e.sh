#!/usr/bin/env bash
# End-to-end test: keyward-agent (in-memory SecretStore, temp XDG dirs) driven
# entirely through the keyward CLI against the seeded Vaultwarden.
set -euo pipefail

: "${KW_FIXTURES:?run inside the devenv shell}" "${KW_CA_CERT:?}"
[[ -f "$KW_FIXTURES" ]] || { echo "e2e: $KW_FIXTURES missing; run 'just seed'" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cargo build -q -p keyward-agent -p keyward-cli
cargo build -q -p keyward-core --features test-support --bin keyward-testkit
BIN="$ROOT/target/debug"
KW="$BIN/keyward"
TK="$BIN/keyward-testkit"

export SSL_CERT_FILE="$KW_CA_CERT"
export KEYWARD_AGENT_BIN="$BIN/keyward-agent"
export KEYWARD_LOG=debug

tmp="$(mktemp -d -t keyward-e2e.XXXXXX)"
export XDG_RUNTIME_DIR="$tmp/run" XDG_DATA_HOME="$tmp/data" XDG_CONFIG_HOME="$tmp/config"
mkdir -p "$XDG_RUNTIME_DIR" && chmod 700 "$XDG_RUNTIME_DIR"
LOGS="$ROOT/target/e2e-logs"
rm -rf -- "$LOGS" && mkdir -p "$LOGS"
export KEYWARD_AGENT_LOG="$LOGS/agent-autospawn.log"   # stderr of auto-spawned agents
CLI_LOG="$LOGS/cli.log"

pids=()
cleanup() {
  "$KW" --no-spawn stop-agent >/dev/null 2>&1 || true
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  rm -rf -- "$tmp"
}
trap cleanup EXIT

pass=0
ok() { pass=$((pass + 1)); echo "  ok - $*"; }
fail() { echo "  FAIL - $*" >&2; exit 1; }

# kw <args...>: run the CLI, stderr appended to the CLI log, stdout returned.
kw() { "$KW" "$@" 2>>"$CLI_LOG"; }
# expect_exit <code> <args...>
expect_exit() {
  local want="$1"; shift
  set +e; "$KW" "$@" >/dev/null 2>>"$CLI_LOG"; local got=$?; set -e
  [[ "$got" == "$want" ]] || fail "keyward $* exited $got, expected $want"
}

fx() { jq -r "$1" "$KW_FIXTURES"; }
SERVER="$(fx .server)"

# Compare `list --json` and `get --json` against the fixtures for user index $1.
verify_user_items() {
  local u="$1" list
  list="$(kw list --json)"
  local want_n got_n
  want_n="$(fx ".users[$u].items | length")"
  got_n="$(jq length <<<"$list")"
  [[ "$want_n" == "$got_n" ]] || fail "user$u: list has $got_n items, expected $want_n"
  local i n
  n="$want_n"
  for ((i = 0; i < n; i++)); do
    local exp name id got
    exp="$(fx ".users[$u].items[$i]")"
    name="$(jq -r .name <<<"$exp")"
    id="$(jq -r --arg n "$name" '.[] | select(.name == $n) | .id' <<<"$list")"
    [[ -n "$id" ]] || fail "user$u: item '$name' missing from list"
    got="$(kw get "$id" --json)"
    for f in username password notes totp uri_host; do
      [[ "$(jq -c ".$f" <<<"$got")" == "$(jq -c ".$f" <<<"$exp")" ]] \
        || fail "user$u: '$name' field $f mismatch"
    done
    [[ "$(jq -r .kind <<<"$got")" == "$( [[ $(jq -r .kind <<<"$exp") == note ]] && echo secure_note || echo login)" ]] \
      || fail "user$u: '$name' kind mismatch"
    # TOTP code from the agent must equal one computed independently from the seed.
    local seed
    seed="$(jq -r .totp <<<"$exp")"
    if [[ "$seed" != null ]]; then
      local a b
      for _ in 1 2 3; do
        a="$(kw get "$id" --field totp)"; b="$("$TK" totp "$seed")"
        [[ "$a" == "$b" ]] && break
        sleep 1   # straddled a 30s boundary
      done
      [[ "$a" == "$b" ]] || fail "user$u: '$name' TOTP code mismatch"
    fi
  done
  ok "user$u: $n items (incl. unicode, notes, TOTP$( [[ $(fx ".users[$u].org_id") != null ]] && echo ', org-owned')) match fixtures"
}

echo "e2e: user1 (PBKDF2, no 2FA) via auto-spawned agent"
U1_EMAIL="$(fx '.users[0].email')"
U1_PWVAR="$(fx '.users[0].password_env')"
# First CLI call spawns the agent; in-memory secret store, never the real keychain.
kw --agent-arg=--secret-store=memory status >/dev/null
[[ -S "$XDG_RUNTIME_DIR/keyward/agent.sock" ]] || fail "agent socket not created"
ok "agent auto-spawned"
[[ "$(stat -c %a "$XDG_RUNTIME_DIR/keyward")" == 700 ]] || fail "socket dir is not 0700"
[[ "$(stat -c %a "$XDG_RUNTIME_DIR/keyward/agent.sock")" == 600 ]] || fail "socket is not 0600"
ok "socket dir 0700, socket 0600"
[[ "$(kw status --json | jq -r .state)" == logged_out ]] || fail "expected logged_out"

expect_exit 9 login --server "http://vault.example.com" --email "$U1_EMAIL" --password-env "$U1_PWVAR"
ok "plain http to a non-loopback host refused"

KW_BAD=wrong-password expect_exit 5 login --server "$SERVER" --email "$U1_EMAIL" --password-env KW_BAD
ok "login with wrong password -> clean InvalidCredentials error"

kw login --server "$SERVER" --email "$U1_EMAIL" --password-env "$U1_PWVAR"
[[ "$(kw status --json | jq -r .state)" == unlocked ]] || fail "expected unlocked after login"
ok "login + sync"
kw sync
verify_user_items 0

kw list GitHub | grep -q $'\tGitHub\t' || fail "search 'GitHub' found nothing"
[[ "$(kw list --json nomatch-xyz | jq length)" == 0 ]] || fail "search should be empty"
[[ "$(kw list --json 日本 | jq length)" == 1 ]] || fail "unicode search failed"
ok "list search filters (incl. unicode)"

kw lock
[[ "$(kw status --json | jq -r .state)" == locked ]] || fail "expected locked"
expect_exit 3 get GitHub
expect_exit 3 list
ok "lock -> get/list fail with Locked"

KW_BAD=wrong-password expect_exit 5 unlock --password-env KW_BAD
grep -q "Invalid master password" "$CLI_LOG" || fail "wrong-password message missing"
ok "unlock with wrong password -> clean error"

kw unlock --password-env "$U1_PWVAR"
[[ "$(kw get GitHub --field username)" == octocat ]] || fail "get after unlock"
# Sync needs an access token: after unlock it is obtained with the stored refresh token.
kw sync
ok "unlock with password only, then sync via refresh token"

echo "e2e: agent restart keeps the cached account (unlock works offline from cache)"
kw stop-agent
sleep 0.3
kw --agent-arg=--secret-store=memory status --json | jq -e '.state == "locked"' >/dev/null || fail "expected locked after restart"
kw unlock --password-env "$U1_PWVAR"
verify_user_items 0
ok "restart -> locked -> unlock from encrypted cache"
expect_exit 4 sync   # in-memory refresh token died with the old agent: clean LoggedOut
ok "sync without stored refresh token -> clean 'log in again' error"
kw logout
[[ "$(kw status --json | jq -r .state)" == logged_out ]] || fail "expected logged_out after logout"
[[ ! -e "$XDG_DATA_HOME/keyward/vault.json" ]] || fail "cache not removed on logout"
ok "logout clears cache"

echo "e2e: user2 (Argon2id + TOTP 2FA)"
U2_EMAIL="$(fx '.users[1].email')"
U2_PWVAR="$(fx '.users[1].password_env')"
U2_TOTP="$(fx '.users[1].totp_secret')"
expect_exit 6 login --server "$SERVER" --email "$U2_EMAIL" --password-env "$U2_PWVAR"
ok "2FA account without code -> TwoFactorRequired"
expect_exit 6 login --server "$SERVER" --email "$U2_EMAIL" --password-env "$U2_PWVAR" --totp 000000
ok "wrong TOTP code rejected"
logged_in=no
for _ in 1 2 3; do
  # Vaultwarden rejects a code from an already-used 30s step; retry on the next step.
  if KW_CODE="$("$TK" totp "$U2_TOTP")" kw login --server "$SERVER" --email "$U2_EMAIL" --password-env "$U2_PWVAR" --totp-env KW_CODE; then
    logged_in=yes; break
  fi
  sleep $((31 - $(date +%s) % 30))
done
[[ "$logged_in" == yes ]] || fail "2FA login failed"
ok "login with computed TOTP code"
verify_user_items 1
kw lock && kw unlock --password-env "$U2_PWVAR" && kw sync
ok "Argon2id lock/unlock/refresh"
kw stop-agent

echo "e2e: large vault ($(fx .large.items) items imported by bw)"
LV_SOCK="$tmp/run/keyward-large.sock"
"$BIN/keyward-agent" --socket "$LV_SOCK" --secret-store memory 2>"$LOGS/agent-large.log" &
pids+=($!)
for _ in $(seq 1 50); do [[ -S "$LV_SOCK" ]] && break; sleep 0.1; done
lv() { kw --socket "$LV_SOCK" --no-spawn "$@"; }
LV_PWVAR="$(fx .large.password_env)"
lv login --server "$SERVER" --email "$(fx .large.email)" --password-env "$LV_PWVAR"
[[ "$(lv list --json | jq length)" == "$(fx .large.items)" ]] || fail "large vault: wrong item count"
[[ "$(lv get "$(fx .large.sample.name)" --field password)" == "$(fx .large.sample.password)" ]] \
  || fail "large vault: sample password mismatch"
ok "large vault: all items listed, sample decrypts to the bw-imported value"
# Status must stay fast while the agent decrypts thousands of summaries.
lists=()
for _ in 1 2 3; do lv list --json >/dev/null & lists+=($!); done
s=$(date +%s%N); lv status >/dev/null; ms=$(( ($(date +%s%N) - s) / 1000000 ))
wait "${lists[@]}"
(( ms < 1000 )) || fail "status took ${ms} ms while list was running"
ok "large vault: status answered in ${ms} ms during concurrent lists"
lv stop-agent

echo "e2e: inactivity auto-lock"
AL_SOCK="$tmp/run/keyward-autolock.sock"
"$BIN/keyward-agent" --socket "$AL_SOCK" --secret-store memory --auto-lock-secs 2 2>"$LOGS/agent-autolock.log" &
pids+=($!)
for _ in $(seq 1 50); do [[ -S "$AL_SOCK" ]] && break; sleep 0.1; done
kw --socket "$AL_SOCK" --no-spawn login --server "$SERVER" --email "$U1_EMAIL" --password-env "$U1_PWVAR"
kw --socket "$AL_SOCK" --no-spawn get GitHub --field username >/dev/null
# Status polling must not count as activity.
for _ in 1 2 3 4 5 6; do kw --socket "$AL_SOCK" --no-spawn status >/dev/null; sleep 0.5; done
[[ "$(kw --socket "$AL_SOCK" --no-spawn status --json | jq -r .state)" == locked ]] || fail "agent did not auto-lock"
expect_exit 3 --socket "$AL_SOCK" --no-spawn get GitHub
grep -q "auto-locking after inactivity" "$LOGS/agent-autolock.log" || fail "auto-lock not logged"
ok "auto-lock after 2s inactivity (status polling is not activity)"
kw --socket "$AL_SOCK" --no-spawn stop-agent

echo "e2e: peer-credential check"
# A second real UID needs root, so the agent's socket test runs serve() over a
# real Unix socket with SO_PEERCRED while requiring a UID we are not.
out="$(cargo test -q -p keyward-agent foreign_uid_is_rejected_over_socket 2>&1)" || { echo "$out" >&2; fail "peer-cred socket test failed"; }
grep -q "1 passed" <<<"$out" || fail "peer-cred socket test did not run"
if grep -q "rejected connection from foreign uid" "$LOGS"/*.log; then fail "own-uid connection was rejected"; fi
ok "SO_PEERCRED: foreign UID rejected over a real socket; our own UID always accepted"

echo "e2e: log leak check"
cat "$LOGS"/agent-*.log >"$LOGS/all.log"; cat "$CLI_LOG" >>"$LOGS/all.log"
grep -q "sync complete" "$LOGS/all.log" || fail "logs look empty; leak check would be vacuous"
mapfile -t secrets < <(jq -r '.users[] | .password, .totp_secret, (.items[] | .password, .notes, .totp) | select(. != null)' "$KW_FIXTURES")
for s in "${secrets[@]}"; do
  # Check each line of multi-line notes too.
  while IFS= read -r line; do
    [[ ${#line} -ge 6 ]] || continue
    if grep -qF -- "$line" "$LOGS/all.log"; then fail "secret value leaked into logs ($(wc -l <"$LOGS/all.log") lines in $LOGS/all.log)"; fi
  done <<<"$s"
done
grep -qiE 'refresh_token"?\s*[:=]\s*"?[A-Za-z0-9]' "$LOGS/all.log" && fail "refresh token leaked into logs"
grep -qiE 'Bearer [A-Za-z0-9]' "$LOGS/all.log" && fail "access token leaked into logs"
ok "no passwords, notes, TOTP seeds or tokens in $(wc -l <"$LOGS/all.log") log lines"

echo "e2e: all $pass checks passed"
