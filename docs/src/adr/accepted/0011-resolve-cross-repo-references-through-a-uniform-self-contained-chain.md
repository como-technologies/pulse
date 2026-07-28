# ADR-0011: Resolve cross-repo references through a uniform self-contained chain

> State: Accepted

## Status

Accepted

## Stakeholders

Como Technologies owner (suite maintainer); maintainers of every TAPS repo
that consumes a sibling (assessments, adroit, conduit, tuesday, pulse,
portfolio, general-business, docs).

## Context and Problem Statement

Cross-repo references across the Como TAPS suite assumed a fixed sibling
workspace layout: this repo's `adr-check` probed a PATH-installed adroit
and then fell back to a hardcoded `../adroit/target/debug/adroit`. That
breaks every single-repo clone, hides which binary a gate actually ran,
and behaves differently per repo (some PATH-first, some sibling-only).
Meanwhile some suite repos have no public remote at all (conduit,
docs is local-only by explicit policy) and adroit's public
remote currently lags the local checkout — so any remote-based resolution
must verify what it fetched and degrade cleanly rather than assume the
network has what the workspace has.

## Decision Drivers

- Gates must work in a single-repo clone, not only in the full sibling workspace
- Repos without a public remote today must keep exactly their current skip/notice behavior
- No repo may source resolver code from a sibling — each copy self-contained
- Contract-grade pins stay explicit, reviewed edits (e.g. conduit's adroit.rev)
- Secrets and live-forge artifacts must never resolve via git
- Resolvers must be read-only: no push, no remote registration, no credentials in URLs
- Offline runs (COMO_OFFLINE=1, or any fetch failure) must degrade, not hang or fail advisory gates

## Considered Options

1. **Status quo** — keep the ad-hoc PATH-then-`../sibling` probe; works
   only in the curated workspace, silently skips everywhere else, and
   orders legs differently from the other repos.
2. **Shared resolver helper** — one resolver script maintained in a single
   repo and sourced by the others; creates the very cross-repo bootstrap
   dependency the resolver exists to remove.
3. **Uniform self-contained chain per repo** — every repo embeds the same
   small resolver: env override → sibling → PATH → gitignored clone cache →
   skip/fail with the knobs named.

## Decision Outcome

Chosen: **option 3, the uniform self-contained resolution chain**, because
it keeps the sibling workspace fast while making every repo resolvable (or
honestly degraded) on its own.

Cross-repo references in the Como TAPS suite resolve through one uniform,
self-contained chain instead of assuming sibling checkouts: (1) an explicit
environment override (ADROIT_BIN for the adroit binary, `COMO_<REPO>_DIR`
for a checkout directory), (2) the sibling checkout `../<repo>`, (3) for
binaries, an installed binary on PATH, (4) a gitignored git-clone cache
under `.como/` in the consuming repo, populated read-only from
`${COMO_GIT_BASE:-https://github.com/como-technologies}/<repo>.git`, and
(5) the existing skip-with-notice for advisory gates or an actionable error
naming the knobs for hard dependencies. Each repo embeds its own copy of
the resolver — no repo ever sources helper code from a sibling.
Contract-grade dependencies stay pinned: conduit installs adroit at the
exact rev in adroit.rev (remote URL by default, sibling file:// only as the
local-dev override), and any script that reads another repo's source as a
contract (portfolio's verify-claims) declares the rev it clones and prints
which source it actually resolved. Runtime secrets and live-forge artifacts
are never resolved via git — they are env-first with documented local-path
fallbacks — and the docs evidence repo is local-only by policy, so
references to it stop at skip-with-notice. Resolvers only clone and fetch:
they never push, never add the cache as a remote, and never carry
credentials in URLs. Repos without a public remote today (conduit,
docs) degrade to exactly the skip-with-notice behavior they
produce now, so nothing breaks before the owner pushes them.

### Positive Consequences

- `just adr-check` works in a single-repo clone, an offline workspace, and
  the curated sibling layout alike, with one set of knob names suite-wide
- The notice text names every knob, so a degraded gate tells the operator
  exactly how to un-degrade it
- The clone cache is gitignored and read-only — no new push surface, no
  credential surface

### Negative Consequences

- Several self-contained copies of the same resolver will exist suite-wide
  and can drift; the canonical snippet lives in the suite ADR and drift has
  to be policed by review
- The clone leg is untested-by-default while remotes lag local work
  (adroit's public remote does not yet have the pinned tag) — it must
  verify the install and degrade with a notice, and it can rot silently
  behind the sibling fallback
- The first cache install turns a previously-instant skip into a network
  `cargo install --git` build unless COMO_OFFLINE=1 or a local leg resolves
- Standardizing env → sibling → PATH changes precedence for this repo,
  which was PATH-first: a fresh sibling build now beats a stale installed
  binary

## Implementation

Carried out in this repo by `justfile`: a private `_adroit-resolve` recipe
implements the chain (ADROIT_BIN → `${COMO_ADROIT_DIR:-../adroit}`
release/debug → PATH → tag-pinned `cargo install --git … --locked --root
.como/tools` → unresolved) and `adr-check` skips with the knobs named when
nothing resolves; `.como/` is gitignored. No other pulse reference needed
work — the book and README URLs already point at the canonical remote.
