#!/usr/bin/env bash
# Capture the README assets from the real app, running headless against the
# seeded throwaway Vaultwarden (all data is fake). Maintainer tool.
#
# Prerequisites, inside the devenv shell:
#   just harness-up && scripts/seed.sh
#
# Writes docs/demo.gif. The example itself
# (crates/sangward-gtk/examples/readme-demo.rs) drives the app; this script
# provides Xvfb, a private D-Bus session, the agent and the recorder.
set -euo pipefail

: "${SW_VW_URL:?run inside the devenv shell}" "${SW_CA_CERT:?}"
: "${SW_TEST_USER1_EMAIL:?}" "${SW_TEST_USER1_PASSWORD:?}" "${SW_FIXTURES:?}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

for tool in ffmpeg jq; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "capture-readme: '$tool' not found in PATH" >&2
    exit 1
  }
done
if [[ ! -f "$SW_FIXTURES" ]] || ! jq -e '.users[0].items' "$SW_FIXTURES" >/dev/null 2>&1; then
  echo "capture-readme: harness not seeded; run 'just harness-up && scripts/seed.sh'" >&2
  exit 1
fi

OUT="$ROOT/docs"
FRAMES="$ROOT/target/readme"
# HiDPI: render at 2x so PNGs stay crisp on high-density screens. The logical
# window is 900x600, so the X root is 1800x1200.
SCALE="${SW_CAPTURE_SCALE:-2}"
WIDTH=$((900 * SCALE))
HEIGHT=$((600 * SCALE))
GIF_WIDTH="${SW_CAPTURE_GIF_WIDTH:-800}"
rm -rf -- "$FRAMES"
mkdir -p "$FRAMES" "$OUT"

cargo build -q -p sangward-gtk --example readme-demo
EXAMPLE="$ROOT/target/debug/examples/readme-demo"

tmp="$(mktemp -d -t sangward-capture.XXXXXX)"
cleanup() {
  "$ROOT/target/debug/sangward" --no-spawn stop-agent >/dev/null 2>&1 || true
  rm -rf -- "$tmp"
}
trap cleanup EXIT

export XDG_RUNTIME_DIR="$tmp/run" XDG_DATA_HOME="$tmp/data" XDG_CONFIG_HOME="$tmp/config" HOME="$tmp/home"
mkdir -p "$XDG_RUNTIME_DIR" "$HOME" && chmod 700 "$XDG_RUNTIME_DIR"
export SSL_CERT_FILE="$SW_CA_CERT"
export SANGWARD_AGENT_BIN="$ROOT/target/debug/sangward-agent"
export SANGWARD_GTK_AGENT_ARGS="--secret-store memory"
export SANGWARD_AGENT_LOG="$ROOT/target/capture-agent.log"
export SANGWARD_CAPTURE_DIR="$FRAMES"
export SANGWARD_LOG=info NO_COLOR=1 GDK_BACKEND=x11 GSK_RENDERER=cairo
export GTK_A11Y=none GDK_DEBUG=no-portals GTK_USE_PORTAL=0
export LANG=C.UTF-8 LC_ALL=C.UTF-8 GDK_SCALE="$SCALE"
export EXAMPLE OUT FRAMES WIDTH HEIGHT GIF_WIDTH ROOT

# Minimal private session bus: no service activation, so nothing from the host
# (portals, a11y, keyrings) gets started.
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

# Runs inside dbus-run-session + xvfb-run: start the app, wait until it has
# logged in and is ready, then record the screen while it animates.
cat >"$tmp/run.sh" <<'INNER'
#!/usr/bin/env bash
set -euo pipefail

"$EXAMPLE" >"$ROOT/target/readme-demo.log" 2>&1 &
app=$!

for _ in $(seq 1 400); do
  [[ -f "$FRAMES/ready" ]] && break
  kill -0 "$app" 2>/dev/null || break
  sleep 0.05
done
if [[ ! -f "$FRAMES/ready" ]]; then
  echo "capture-readme: app never became ready; log follows" >&2
  cat "$ROOT/target/readme-demo.log" >&2
  kill "$app" 2>/dev/null || true
  exit 1
fi

ffmpeg -hide_banner -loglevel error -f x11grab -draw_mouse 0 -framerate 12 -video_size "${WIDTH}x${HEIGHT}" \
  -i "$DISPLAY" -t 30 -y "$FRAMES/demo.mp4" &
rec=$!

wait "$app"
kill -INT "$rec" 2>/dev/null || true
wait "$rec" 2>/dev/null || true
INNER
chmod +x "$tmp/run.sh"

echo "capture-readme: recording at ${WIDTH}x${HEIGHT} (app log: target/readme-demo.log)"
set +e
dbus-run-session --config-file="$tmp/session.conf" -- \
  xvfb-run -a -s "-screen 0 ${WIDTH}x${HEIGHT}x24" bash "$tmp/run.sh"
rc=$?
set -e
[[ $rc -eq 0 ]] || { echo "capture-readme: capture run failed (rc=$rc)" >&2; exit "$rc"; }

# Screen recording -> looping GIF with a shared palette.
ffmpeg -hide_banner -loglevel error -i "$FRAMES/demo.mp4" \
  -vf "fps=12,scale=${GIF_WIDTH}:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128:stats_mode=diff[p];[s1][p]paletteuse=dither=bayer:bayer_scale=3" \
  -loop 0 -y "$OUT/demo.gif"

echo "capture-readme: wrote $OUT/demo.gif"
ls -lh "$OUT"/demo.gif
