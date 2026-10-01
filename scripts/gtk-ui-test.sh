#!/usr/bin/env bash
# Run the in-process GTK UI tests (crates/sangward-gtk/tests/ui.rs) headless:
# Xvfb + a private D-Bus session + throwaway XDG dirs + in-memory keychain.
# Usage: scripts/gtk-ui-test.sh [scenario]
set -euo pipefail

: "${SW_VW_URL:?run inside the devenv shell}" "${SW_CA_CERT:?}" "${SW_FIXTURES:?}"
jq -e .large "$SW_FIXTURES" >/dev/null 2>&1 || { echo "gtk-ui-test: run 'just seed' (incl. seed-large) first" >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Release build: the stall budget is about the app, not unoptimised debug code.
cargo build -q --release -p sangward-agent
cargo test -q --release -p sangward-gtk --test ui --no-run
UI_BIN="$(cargo test -q --release -p sangward-gtk --test ui --no-run --message-format=json 2>/dev/null \
  | jq -r 'select(.reason=="compiler-artifact" and .target.name=="ui" and .executable!=null) | .executable' | tail -1)"
[[ -x "$UI_BIN" ]] || { echo "gtk-ui-test: could not locate ui test binary" >&2; exit 1; }

tmp="$(mktemp -d -t sangward-gtk-ui.XXXXXX)"
cleanup() {
  "$ROOT/target/debug/sangward" --no-spawn stop-agent >/dev/null 2>&1 || true
  rm -rf -- "$tmp"
}
trap cleanup EXIT
export XDG_RUNTIME_DIR="$tmp/run" XDG_DATA_HOME="$tmp/data" XDG_CONFIG_HOME="$tmp/config" HOME="$tmp/home"
mkdir -p "$XDG_RUNTIME_DIR" "$HOME" && chmod 700 "$XDG_RUNTIME_DIR"

export SSL_CERT_FILE="$SW_CA_CERT"
export SANGWARD_AGENT_BIN="$ROOT/target/release/sangward-agent"
export SANGWARD_GTK_AGENT_ARGS="--secret-store memory"
export SANGWARD_AGENT_LOG="$ROOT/target/gtk-ui-agent.log"
export SANGWARD_LOG=info NO_COLOR=1 GDK_BACKEND=x11 GSK_RENDERER=cairo GTK_A11Y=none GDK_DEBUG=no-portals RUST_BACKTRACE=1
rm -f "$SANGWARD_AGENT_LOG"

cat >"$tmp/session.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir=$tmp/run</listen>
  <auth>EXTERNAL</auth>
  <policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy>
</busconfig>
EOF

dbus-run-session --config-file="$tmp/session.conf" -- \
  xvfb-run -a -s "-screen 0 1280x800x24" "$UI_BIN" "$@" 2>"$ROOT/target/gtk-ui.log"
echo "gtk-ui-test: passed (stderr in target/gtk-ui.log, agent log in target/gtk-ui-agent.log)"
