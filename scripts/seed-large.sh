#!/usr/bin/env bash
# Seed a *large* vault (default 5000 items) for the performance tests.
#
# Items are generated as a Bitwarden JSON export and imported with the
# official `bw import`, so they are encrypted by Bitwarden's client, not ours.
# A third user (PBKDF2) holds them; its details are appended to $SW_FIXTURES.
set -euo pipefail

: "${SW_VW_URL:?run inside the devenv shell}" "${SW_CA_CERT:?}" "${SW_FIXTURES:?}"
: "${SW_TEST_USER3_EMAIL:?}" "${SW_TEST_USER3_PASSWORD:?}" "${SW_LARGE_VAULT_ITEMS:?}"
[[ -f "$SW_FIXTURES" ]] || { echo "seed-large: run 'just seed' first" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cargo build -q -p sangward-core --features test-support --bin sangward-testkit
TK="$ROOT/target/debug/sangward-testkit"
export SSL_CERT_FILE="$SW_CA_CERT" NODE_EXTRA_CA_CERTS="$SW_CA_CERT" BW_NOINTERACTION=true NODE_NO_WARNINGS=1

work="$(mktemp -d -t sangward-seed-large.XXXXXX)"
trap 'rm -rf -- "$work"' EXIT
n="$SW_LARGE_VAULT_ITEMS"
export SW_SEED_PW="$SW_TEST_USER3_PASSWORD"

echo "seed-large: registering $SW_TEST_USER3_EMAIL and importing $n items via bw"
"$TK" register --email "$SW_TEST_USER3_EMAIL" --password-env SW_SEED_PW --kdf pbkdf2

# Deterministic, varied items: every 10th is a secure note, every 7th has TOTP,
# names mix ASCII and unicode so search has something to chew on.
jq -n --argjson n "$n" '
  def word($i): ["alpha","bravo","charlie","delta","echo","foxtrot","golf","hotel","india","juliett","kilo","lima","mike","ünïcode","日本","🦀"][$i % 16];
  {encrypted: false, folders: [], items: [range(0; $n) as $i |
    if ($i % 10) == 9 then
      {type: 2, name: "Note \($i) \(word($i))", notes: "note body \($i)", secureNote: {type: 0}, favorite: false, reprompt: 0}
    else
      {type: 1, name: "Site \($i) \(word($i)) \(word($i / 16 | floor))", notes: null, favorite: false, reprompt: 0,
       login: {username: "user\($i)@example.test", password: "pw-\($i)-\(word($i))",
               totp: (if ($i % 7) == 0 then "JBSWY3DPEHPK3PXP" else null end),
               uris: [{match: null, uri: "https://host\($i % 500).example.com/login"}]}}
    end]}' >"$work/export.json"

export BITWARDENCLI_APPDATA_DIR="$work/bw"
mkdir -p "$BITWARDENCLI_APPDATA_DIR"
bw config server "$SW_VW_URL" >/dev/null
BW_SESSION="$(bw login "$SW_TEST_USER3_EMAIL" --passwordenv SW_SEED_PW --raw)"
export BW_SESSION
bw import bitwardenjson "$work/export.json" >/dev/null
count="$(bw list items | jq length)"
bw logout >/dev/null 2>&1 || true
[[ "$count" == "$n" ]] || { echo "seed-large: bw reports $count items, expected $n" >&2; exit 1; }

tmp="$(mktemp)"
jq --arg email "$SW_TEST_USER3_EMAIL" --argjson n "$n" \
  '.large = {email: $email, password_env: "SW_TEST_USER3_PASSWORD", items: $n,
             sample: {name: "Site 4242 charlie juliett", username: "user4242@example.test", password: "pw-4242-charlie"}}' \
  "$SW_FIXTURES" >"$tmp" && mv "$tmp" "$SW_FIXTURES" && chmod 600 "$SW_FIXTURES"
echo "seed-large: imported $count items"
