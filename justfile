# Default: list available recipes
default:
    @just --list

# Install project tools (clippy, rustfmt, mdbook + gruvbox theme, cargo-edit,
# cargo-audit)
init:
    rustup component add clippy rustfmt
    cargo install mdbook mdbook-gruvbox cargo-edit cargo-audit
    mdbook-gruvbox install docs

# Run all CI checks: the CLAUDE.md pre-push checklist + book + ADR validation
# + dependency audit. This local gate is the source of truth (nothing is
# pushed in park mode).
ci: fmt-check lint test book adr-check crate-audit

# House vocabulary for the full local gate
alias gate := ci

# Format code
fmt:
    cargo fmt

# Check formatting without modifying files
fmt-check:
    cargo fmt --check

# Run clippy on the whole workspace including tests and examples,
# plus the feature-gated simulate binary and its integration tests
lint:
    cargo clippy --workspace --tests --examples -- -D warnings
    cargo clippy -p pulse-test-harness --features reqwest-transport --bins --tests -- -D warnings

# Type-check without building
check:
    cargo check --workspace

# Build in debug mode
build:
    cargo build --workspace

# Run all tests (unit + integration, every crate), then the feature-gated
# simulate-over-HTTP integration tests
test *ARGS:
    cargo test --workspace {{ARGS}}
    cargo test -p pulse-test-harness --features reqwest-transport {{ARGS}}

# Run the server with dev providers (Identity zone :8001, Signal zone :8002)
run:
    cargo run -p pulse-server

# Narrated in-memory walkthrough of the full blind-signature protocol
walkthrough:
    cargo run -p pulse-server --example walkthrough

# Run the protocol simulation (defaults: 1 tenant, 10 employees, concurrency 10)
simulate *ARGS:
    cargo run -p pulse-test-harness --features reqwest-transport --bin pulse-simulate -- {{ARGS}}

# Measure-stage demo: the deterministic multi-tenant protocol simulation
demo: simulate

# Measure-stage dogfood: run the iteration-retro pulse against simulated,
# seeded respondents and write the deterministic Measure artifact.
# Same seed -> byte-identical out/pulse-report.json (prove with two runs + diff).
dogfood:
    cargo run -p pulse-test-harness --features reqwest-transport --bin pulse-simulate -- \
        --batch-file dogfood/iteration-retro.toml --seed 42 --employees 10 --k-threshold 5 \
        --out out/pulse-report.json

# Optional tag pin for the resolver's cached-install leg (always --locked).
# If the remote doesn't have the tag yet, the install fails and the chain
# degrades to the skip notice — it never installs an unpinned build.
adroit_pin := "v0.2.0"

# Resolve the adroit binary per the suite convention (ADR-0011):
# ADROIT_BIN → sibling checkout (${COMO_ADROIT_DIR:-../adroit}, release
# preferred over debug) → adroit on PATH → cached `cargo install --git`
# under .como/tools (gitignored) → unresolved (caller skips with notice).
# NOTE the precedence change: a sibling build now beats a PATH install.
# COMO_OFFLINE=1 skips the network leg; a populated .como/ cache is used
# as-is and never auto-updated (refresh = rm -rf .como/tools).
_adroit-resolve:
    #!/usr/bin/env bash
    set -euo pipefail
    root="{{justfile_directory()}}"
    if [ -n "${ADROIT_BIN:-}" ]; then echo "$ADROIT_BIN"; exit 0; fi
    sibling="${COMO_ADROIT_DIR:-$root/../adroit}"
    for b in "$sibling/target/release/adroit" "$sibling/target/debug/adroit"; do
        if [ -x "$b" ]; then echo "$b"; exit 0; fi
    done
    if command -v adroit >/dev/null 2>&1; then command -v adroit; exit 0; fi
    cached="$root/.como/tools/bin/adroit"
    if [ -x "$cached" ]; then echo "$cached"; exit 0; fi
    if [ "${COMO_OFFLINE:-0}" = "1" ]; then
        echo "adroit resolver: COMO_OFFLINE=1 and no local binary or .como cache" >&2
        exit 0
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        echo "adroit resolver: cargo not found — cannot populate .como/tools" >&2
        exit 0
    fi
    url="${COMO_ADROIT_GIT:-${COMO_GIT_BASE:-https://github.com/como-technologies}/adroit.git}"
    echo "adroit resolver: installing adroit from $url (tag {{adroit_pin}}) into .como/tools ..." >&2
    if cargo install --git "$url" --tag "{{adroit_pin}}" --locked --root "$root/.como/tools" adroit 1>&2 \
        && [ -x "$cached" ]; then
        echo "$cached"; exit 0
    fi
    echo "adroit resolver: install from $url failed — the remote may not have tag {{adroit_pin}} yet (set ADROIT_BIN, build ../adroit, or set COMO_GIT_BASE / check network)" >&2

# Validate the ADR corpus with adroit (resolved per the suite chain).
# Advisory gate: skips gracefully — with the knobs named — if no binary
# resolves.
adr-check:
    #!/usr/bin/env bash
    set -euo pipefail
    adroit="$(just _adroit-resolve)"
    if [ -n "$adroit" ] && [ -x "$adroit" ]; then
        "$adroit" check --dir docs/src/adr
    else
        echo "skip: no adroit binary (set ADROIT_BIN, build ../adroit, install adroit on PATH, or set COMO_GIT_BASE for the .como/tools install)"
    fi

# Build the documentation book (bootstraps the gitignored gruvbox theme)
book:
    @if [ ! -d docs/gruvbox ] && command -v mdbook-gruvbox >/dev/null 2>&1; then mdbook-gruvbox install docs; fi
    mdbook build docs
    @echo "Book built -> docs/book"

# Serve the book locally with live reload
book-serve:
    mdbook serve docs --open

# Upgrade dependencies (including incompatible versions)
crate-upgrade:
    cargo upgrade --incompatible

# Update Cargo.lock to latest compatible versions
crate-update:
    cargo update

# Audit dependencies for known vulnerabilities, honoring the accepted-advisory
# list in .cargo/audit.toml (skipped if cargo-audit isn't installed; `just
# init` installs it and GitHub CI always runs it)
crate-audit:
    @if command -v cargo-audit >/dev/null 2>&1; then cargo audit; else echo "skip: cargo-audit not installed (run 'just init')"; fi

# Upgrade deps, update lockfile, audit, and test
crate-refresh: crate-upgrade crate-update crate-audit test

# Clean build artifacts
clean:
    cargo clean
