# sangward task runner. All configuration (ports, tokens, paths) comes from
# devenv.nix; run these from inside the devenv shell.

set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Start a throwaway Vaultwarden (TLS, fresh mktemp data dir) and wait for /alive.
harness-up:
    scripts/harness.sh up

# Stop Vaultwarden and delete its data dir.
harness-down:
    scripts/harness.sh down

# Register users with sangward's crypto, create items with the official bw CLI, write fixtures.
seed:
    scripts/seed.sh
    scripts/seed-large.sh

# Unit + integration tests. Uses vectors freshly captured by `seed` when present.
test:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -d target/vectors ]] && compgen -G "target/vectors/*.json" >/dev/null; then
      export SW_VECTORS_DIR="$PWD/target/vectors"
      echo "test: using freshly captured bw vectors from $SW_VECTORS_DIR"
    fi
    cargo test --workspace --all-features

# Promote freshly captured vectors to the committed copies used by plain `cargo test`.
capture-vectors:
    cp target/vectors/*.json crates/sangward-core/tests/vectors/

# End-to-end: agent (in-memory keychain) driven through the CLI against the seeded server.
e2e:
    scripts/e2e.sh

# Launch sangward-gtk headless (Xvfb, private D-Bus) and require it to reach the login screen.
gtk-smoke:
    scripts/gtk-smoke.sh

# In-process GTK UI tests (Xvfb, private D-Bus): real App component, widgets driven
# by name, main-loop stall budget (SW_UI_MAX_STALL_MS) on a large vault.
# Optional arg: a single scenario name.
gtk-ui *scenario:
    scripts/gtk-ui-test.sh {{scenario}}

lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo fmt --all --check

# Full pipeline. Vaultwarden is always stopped, even on failure.
check:
    #!/usr/bin/env bash
    set -euo pipefail
    trap 'just harness-down' EXIT
    just harness-down >/dev/null 2>&1 || true
    # Never let stale fixtures/vectors from a previous run mask a broken seed.
    rm -f -- "$SW_FIXTURES" && rm -rf -- target/vectors target/e2e-logs
    just harness-up
    just seed
    just test
    just e2e
    just gtk-smoke
    just gtk-ui
    just lint
    echo "check: all green"
