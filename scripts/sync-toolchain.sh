#!/usr/bin/env bash
# Keep rust-toolchain.toml's `channel` in step with the MSRV declared as
# `[workspace.package] rust-version` in Cargo.toml.
#
# Cargo and rustup have no way to share one value: Cargo only knows its own
# `rust-version` and rustup only reads rust-toolchain.toml (Cargo's proposed
# `package.rust-version = "toolchain"` is unimplemented). Cargo.toml is the
# single source of truth; this script mirrors it into the toolchain file.
#
#   scripts/sync-toolchain.sh          rewrite the channel line
#   scripts/sync-toolchain.sh --check  fail if it is out of date (used by CI)
#
# Only `channel` is touched; `profile` and `components` are hand-maintained.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cargo_toml="$root/Cargo.toml"
toolchain="$root/rust-toolchain.toml"

check=0
if [[ "${1:-}" == "--check" ]]; then check=1; fi

# A bare version from the [workspace.package] table, e.g. 1.93 or 1.93.0.
msrv="$(sed -n '/^\[workspace.package\]/,/^\[/p' "$cargo_toml" \
  | sed -n 's/^rust-version = "\([0-9.]*\)"/\1/p' | head -n1)"
if [[ -z "$msrv" ]]; then
  echo "sync-toolchain: no [workspace.package] rust-version in $cargo_toml" >&2
  exit 1
fi

# Pin the exact release: 1.93 -> 1.93.0.
channel="$msrv"
while [[ "$channel" != *.*.* ]]; do channel="$channel.0"; done

current="$(sed -n 's/^channel = "\(.*\)"/\1/p' "$toolchain")"

if [[ "$current" == "$channel" ]]; then
  echo "sync-toolchain: up to date ($channel)"
  exit 0
fi

if (( check )); then
  echo "sync-toolchain: rust-toolchain.toml channel '$current' does not match" >&2
  echo "  Cargo.toml rust-version '$msrv' (expected channel '$channel')" >&2
  echo "run 'just sync-toolchain' and commit the result" >&2
  exit 1
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
sed "s/^channel = \".*\"/channel = \"$channel\"/" "$toolchain" >"$tmp"
mv "$tmp" "$toolchain"
trap - EXIT
echo "sync-toolchain: channel -> $channel"
