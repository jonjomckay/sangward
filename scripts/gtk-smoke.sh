#!/usr/bin/env bash
# Headless GTK smoke test: launch keyward-gtk under Xvfb with a private D-Bus
# session and throwaway XDG dirs; it must reach the login screen without panicking.
set -euo pipefail

: "${KW_VW_URL:?run inside the devenv shell}" "${KW_CA_CERT:?}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cargo build -q -p keyward-gtk -p keyward-agent
BIN="$ROOT/target/debug"

tmp="$(mktemp -d -t keyward-gtk.XXXXXX)"
trap 'rm -rf -- "$tmp"' EXIT
export XDG_RUNTIME_DIR="$tmp/run" XDG_DATA_HOME="$tmp/data" XDG_CONFIG_HOME="$tmp/config" HOME="$tmp/home"
mkdir -p "$XDG_RUNTIME_DIR" "$HOME" "$XDG_CONFIG_HOME/keyward" && chmod 700 "$XDG_RUNTIME_DIR"
# Prefill the login form with the seeded server (exercises Settings loading too).
printf '{"server_url":"%s","email":"smoke@example.test"}\n' "$KW_VW_URL" >"$XDG_CONFIG_HOME/keyward/settings.json"

export SSL_CERT_FILE="$KW_CA_CERT"
export KEYWARD_AGENT_BIN="$BIN/keyward-agent"
export KEYWARD_GTK_AGENT_ARGS="--secret-store memory"
export KEYWARD_AGENT_LOG="$tmp/agent.log"
export KEYWARD_LOG=info GDK_BACKEND=x11 GSK_RENDERER=cairo NO_AT_BRIDGE=1 RUST_BACKTRACE=1
log="$ROOT/target/gtk-smoke.log"

set +e
# Minimal private session bus: no service activation, so nothing from the host
# (portals, a11y, keyrings) gets started. Nix's dbus has no /etc config on
# non-NixOS hosts, so we write our own.
cat >"$tmp/session.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir=$tmp/run</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
EOF
export GTK_USE_PORTAL=0 GDK_DEBUG=no-portals NO_COLOR=1
dbus-run-session --config-file="$tmp/session.conf" -- xvfb-run -a -s "-screen 0 1280x800x24" \
  timeout --signal=TERM --kill-after=5 8 "$BIN/keyward-gtk" >"$log" 2>&1
rc=$?
set -e
# Stop the agent the GUI auto-spawned (the GUI was killed by timeout, so it couldn't).
"$BIN/keyward" --no-spawn stop-agent >/dev/null 2>&1 || true

if grep -qE "panicked at|SIGSEGV|Segmentation fault" "$log"; then
  echo "gtk-smoke: keyward-gtk panicked/crashed:" >&2; cat "$log" >&2; exit 1
fi
# 124 = killed by timeout, i.e. it was still running happily.
if [[ $rc -ne 124 ]]; then
  echo "gtk-smoke: keyward-gtk exited early with $rc:" >&2; cat "$log" >&2; exit 1
fi
if ! grep -qE 'screen changed screen="?login' "$log"; then
  echo "gtk-smoke: never reached the login screen:" >&2; cat "$log" >&2; exit 1
fi
echo "gtk-smoke: keyward-gtk started headless and reached the login screen (log: $log)"
