#!/usr/bin/env bash
# Seed the harness Vaultwarden.
#
#  1. Register users with *keyward's* crypto (keyward-testkit register).
#  2. Log in with the *official* Bitwarden CLI and create items with it.
#  3. Optionally create an organization (org-owned item) and enable TOTP 2FA.
#  4. Write expected plaintexts to $KW_FIXTURES and capture encrypted
#     test vectors (bw-encrypted data + expected plaintext) to target/vectors/.
#
# bw always runs with a throwaway BITWARDENCLI_APPDATA_DIR.
set -euo pipefail

: "${KW_VW_URL:?run inside the devenv shell}"
: "${KW_CA_CERT:?}" "${KW_FIXTURES:?}"
: "${KW_TEST_USER1_EMAIL:?}" "${KW_TEST_USER1_PASSWORD:?}" "${KW_TEST_USER2_EMAIL:?}" "${KW_TEST_USER2_PASSWORD:?}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cargo build -q -p keyward-core --features test-support --bin keyward-testkit
TK="$ROOT/target/debug/keyward-testkit"

export SSL_CERT_FILE="$KW_CA_CERT"        # our rustls client trusts the harness CA
export NODE_EXTRA_CA_CERTS="$KW_CA_CERT"  # so does bw (node)
export BW_NOINTERACTION=true NODE_NO_WARNINGS=1

work="$(mktemp -d -t keyward-seed.XXXXXX)"
trap 'rm -rf -- "$work"' EXIT
vectors_dir="$ROOT/target/vectors"
rm -rf -- "$vectors_dir"
mkdir -p "$vectors_dir" "$(dirname "$KW_FIXTURES")"

# Item specs. `org: true` items are created inside the user's organization.
cat >"$work/items1.json" <<'EOF'
[
  {"kind":"login","name":"GitHub","username":"octocat","password":"gh-Pa55-wörd!","uri":"https://github.com/login","uri_host":"github.com","totp":"JBSWY3DPEHPK3PXP","notes":null,"org":false},
  {"kind":"login","name":"Bänk Ünïcode 日本 🔐","username":"alice@example.test","password":"p@ss wörd ✓ 🔑","uri":"https://Bank.Example.com/auth?token=abc","uri_host":"bank.example.com","totp":null,"notes":"line one\nline two — ünïcode","org":false},
  {"kind":"login","name":"No URI login","username":"nouri","password":"no-uri-password-123","uri":null,"uri_host":null,"totp":null,"notes":null,"org":false},
  {"kind":"note","name":"Server notes ✎","username":null,"password":null,"uri":null,"uri_host":null,"totp":null,"notes":"Root password is in the safe.\nZweite Zeile: äöü — 中文","org":false},
  {"kind":"login","name":"Org Shared Login","username":"shared-user","password":"org-Secret-Ω-42","uri":"https://intranet.example.test/","uri_host":"intranet.example.test","totp":"otpauth://totp/Org:shared?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Org","notes":null,"org":true}
]
EOF
cat >"$work/items2.json" <<'EOF'
[
  {"kind":"login","name":"Argon Login","username":"argon-user","password":"argon-Pässwörd-ß","uri":"https://argon.example.org","uri_host":"argon.example.org","totp":"otpauth://totp/Argon:argon-user?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=Argon&digits=6&period=30","notes":null,"org":false},
  {"kind":"login","name":"Ünïcödé Ñame 🦀","username":"ünï","password":"🦀🦀🦀-rust","uri":"androidapp://com.example.app","uri_host":"com.example.app","totp":null,"notes":null,"org":false},
  {"kind":"note","name":"Argon note","username":null,"password":null,"uri":null,"uri_host":null,"totp":null,"notes":"Argon2id secure note body","org":false}
]
EOF

# Create one item from a spec object (stdin-free; spec passed as $1).
create_item() {
  local spec="$1" org_id="$2" coll_id="$3" login item
  if [[ "$(jq -r .kind <<<"$spec")" == "login" ]]; then
    login="$(jq --argjson s "$spec" '
      .username = $s.username | .password = $s.password | .totp = $s.totp
      | .uris = (if $s.uri == null then [] else [{match: null, uri: $s.uri}] end)' "$work/tpl-login.json")"
    item="$(jq --argjson s "$spec" --argjson l "$login" '.type = 1 | .login = $l | .secureNote = null' "$work/tpl-item.json")"
  else
    item="$(jq '.type = 2 | .login = null | .secureNote = {type: 0}' "$work/tpl-item.json")"
  fi
  item="$(jq --argjson s "$spec" --arg org "$org_id" --arg coll "$coll_id" '
    .name = $s.name | .notes = $s.notes
    | if $s.org then .organizationId = $org | .collectionIds = [$coll] else .organizationId = null | .collectionIds = [] end' <<<"$item")"
  bw encode <<<"$item" | bw create item >/dev/null
}

# seed_user <n> <email> <password-var> <kdf> <enable-totp: yes|no> <org: yes|no>
seed_user() {
  local n="$1" email="$2" pwvar="$3" kdf="$4" want_totp="$5" want_org="$6"
  export KW_SEED_PW="${!pwvar}"
  echo "seed: user$n ($kdf) $email"
  "$TK" register --email "$email" --password-env KW_SEED_PW --kdf "$kdf"

  export BITWARDENCLI_APPDATA_DIR="$work/bw$n"
  mkdir -p "$BITWARDENCLI_APPDATA_DIR"
  bw config server "$KW_VW_URL" >/dev/null
  BW_SESSION="$(bw login "$email" --passwordenv KW_SEED_PW --raw)"
  export BW_SESSION
  bw get template item >"$work/tpl-item.json"
  bw get template item.login >"$work/tpl-login.json"

  local org_id="" coll_id=""
  if [[ "$want_org" == yes ]]; then
    local out
    out="$("$TK" create-org --email "$email" --password-env KW_SEED_PW --name "keyward test org")"
    org_id="$(jq -r .org_id <<<"$out")"
    coll_id="$(jq -r .collection_id <<<"$out")"
    bw sync >/dev/null
  fi

  local spec
  while IFS= read -r spec; do
    create_item "$spec" "$org_id" "$coll_id"
  done < <(jq -c '.[]' "$work/items$n.json")
  bw logout >/dev/null 2>&1 || true
  unset BW_SESSION

  # Capture bw-encrypted data before enabling 2FA (so the dump login needs no TOTP).
  "$TK" dump-sync --email "$email" --password-env KW_SEED_PW >"$work/dump$n.json"
  jq -n --slurpfile d "$work/dump$n.json" --slurpfile e "$work/items$n.json" --arg pw "$KW_SEED_PW" '
    {email: $d[0].email, password: $pw, kdf: $d[0].kdf, protected_key: $d[0].protected_key,
     sync: $d[0].sync, expected: $e[0]}' >"$vectors_dir/user$n-$kdf.json"

  local secret=""
  if [[ "$want_totp" == yes ]]; then
    secret="$("$TK" enable-totp --email "$email" --password-env KW_SEED_PW)"
    echo "seed: enabled TOTP 2FA for $email"
  fi
  jq -n --arg email "$email" --arg pwvar "$pwvar" --arg pw "$KW_SEED_PW" --arg kdf "$kdf" --arg secret "$secret" \
    --slurpfile items "$work/items$n.json" --argjson org "$( [[ -n $org_id ]] && jq -n --arg o "$org_id" '$o' || echo null)" '
    {email: $email, password_env: $pwvar, password: $pw, kdf: $kdf,
     totp_secret: (if $secret == "" then null else $secret end), org_id: $org, items: $items[0]}' >"$work/user$n.json"
  unset KW_SEED_PW
}

seed_user 1 "$KW_TEST_USER1_EMAIL" KW_TEST_USER1_PASSWORD pbkdf2 no yes
seed_user 2 "$KW_TEST_USER2_EMAIL" KW_TEST_USER2_PASSWORD argon2id yes no

jq -n --arg server "$KW_VW_URL" --arg ca "$KW_CA_CERT" --slurpfile u1 "$work/user1.json" --slurpfile u2 "$work/user2.json" \
  '{server: $server, ca_cert: $ca, users: [$u1[0], $u2[0]]}' >"$KW_FIXTURES"
chmod 600 "$KW_FIXTURES"
echo "seed: wrote $KW_FIXTURES and $(ls "$vectors_dir" | wc -l) vector files in $vectors_dir"
