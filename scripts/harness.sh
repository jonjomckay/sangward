#!/usr/bin/env bash
# Start/stop a throwaway Vaultwarden for the test harness.
# All configuration comes from devenv.nix (KW_* variables).
set -euo pipefail

: "${KW_VW_ADDRESS:?run inside the devenv shell}"
: "${KW_VW_PORT:?}" "${KW_VW_URL:?}" "${KW_VW_ADMIN_TOKEN:?}" "${KW_HARNESS_DIR:?}" "${KW_VW_PID_FILE:?}"

: "${KW_CA_CERT:?}" "${KW_VW_ALIVE_URL:?}"

datadir_file="$KW_HARNESS_DIR/vaultwarden.datadir"
log_file="$KW_HARNESS_DIR/vaultwarden.log"
tls_dir="$(dirname "$KW_CA_CERT")"

# Throwaway CA + localhost cert. The CA is trusted only by harness processes
# (SSL_CERT_FILE for our rustls client, NODE_EXTRA_CA_CERTS for bw); never installed system-wide.
make_tls() {
  [[ -f "$tls_dir/server.pem" && -f "$KW_CA_CERT" ]] && return 0
  mkdir -p "$tls_dir"
  chmod 700 "$tls_dir"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=keyward harness CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
    -keyout "$tls_dir/ca.key" -out "$KW_CA_CERT" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
    -keyout "$tls_dir/server.key" -out "$tls_dir/server.csr" 2>/dev/null
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' >"$tls_dir/ext.cnf"
  openssl x509 -req -in "$tls_dir/server.csr" -CA "$KW_CA_CERT" -CAkey "$tls_dir/ca.key" -CAcreateserial \
    -days 30 -extfile "$tls_dir/ext.cnf" -out "$tls_dir/server.pem" 2>/dev/null
  rm -f "$tls_dir/server.csr" "$tls_dir/ext.cnf"
}

alive() {
  curl -fsS --cacert "$KW_CA_CERT" "$KW_VW_ALIVE_URL" >/dev/null 2>&1
}

# True if the pid file names a live process that really is vaultwarden
# (guards against PID reuse after a reboot leaves a stale pid file behind).
ours_running() {
  [[ -f "$KW_VW_PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$KW_VW_PID_FILE")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  [[ "$(ps -o comm= -p "$pid" 2>/dev/null)" == vaultwarden* ]]
}

up() {
  mkdir -p "$KW_HARNESS_DIR" "$(dirname "$KW_VW_PID_FILE")"
  if ours_running; then
    echo "harness: vaultwarden already running (pid $(cat "$KW_VW_PID_FILE"))"
    return 0
  fi
  # Stale state from a previous run (e.g. after a reboot wiped /tmp).
  rm -f "$KW_VW_PID_FILE" "$datadir_file"
  if curl -fsSk "$KW_VW_ALIVE_URL" >/dev/null 2>&1; then
    echo "harness: something is already listening on $KW_VW_URL; refusing to continue" >&2
    exit 1
  fi
  make_tls
  local data
  data="$(mktemp -d -t keyward-vw.XXXXXX)"
  echo "$data" >"$datadir_file"

  ROCKET_ADDRESS="$KW_VW_ADDRESS" \
  ROCKET_PORT="$KW_VW_PORT" \
  WEB_VAULT_ENABLED=false \
  SIGNUPS_ALLOWED=true \
  SIGNUPS_VERIFY=false \
  ADMIN_TOKEN="$KW_VW_ADMIN_TOKEN" \
  ROCKET_TLS="{certs=\"$tls_dir/server.pem\",key=\"$tls_dir/server.key\"}" \
  DATA_FOLDER="$data" \
  DOMAIN="$KW_VW_URL" \
  LOG_LEVEL=warn \
  ORG_CREATION_USERS=all \
  LOGIN_RATELIMIT_MAX_BURST=1000 \
  LOGIN_RATELIMIT_SECONDS=1 \
  ADMIN_RATELIMIT_MAX_BURST=1000 \
  nohup vaultwarden >"$log_file" 2>&1 &
  echo $! >"$KW_VW_PID_FILE"

  for _ in $(seq 1 100); do
    if alive; then
      echo "harness: vaultwarden up at $KW_VW_URL (pid $(cat "$KW_VW_PID_FILE"), data $data)"
      return 0
    fi
    if ! kill -0 "$(cat "$KW_VW_PID_FILE")" 2>/dev/null; then
      echo "harness: vaultwarden exited early; log follows" >&2
      cat "$log_file" >&2
      exit 1
    fi
    sleep 0.2
  done
  echo "harness: timed out waiting for $KW_VW_URL/alive" >&2
  exit 1
}

down() {
  # Only signal the pid if it is still our vaultwarden; never a reused pid.
  if ours_running; then
    local pid
    pid="$(cat "$KW_VW_PID_FILE")"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    if ours_running; then kill -9 "$pid" 2>/dev/null || true; fi
  fi
  rm -f "$KW_VW_PID_FILE"
  if [[ -f "$datadir_file" ]]; then
    local data
    data="$(cat "$datadir_file")"
    # Only ever delete the mktemp directory we created ourselves.
    if [[ "$data" == "${TMPDIR:-/tmp}"/keyward-vw.* && -d "$data" ]]; then
      rm -rf -- "$data"
    fi
    rm -f "$datadir_file"
  fi
  echo "harness: vaultwarden stopped"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
