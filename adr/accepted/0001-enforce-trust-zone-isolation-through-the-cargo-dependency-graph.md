# ADR-0001: Enforce trust-zone isolation through the Cargo dependency graph

> State: Accepted

## Status

Accepted

## Stakeholders

Pulse maintainers (architecture owners). Anyone adding a dependency edge between
workspace crates must respect this decision.

## Context and Problem Statement

Pulse's anonymity guarantee rests on a hard separation between two trust zones:
the Identity zone (knows WHO participated) and the Signal zone (knows WHAT was
said). If code or types leak between the zones, an operator — or a bug — could
correlate identity with responses, and the cryptographic guarantee of the blind
signature protocol becomes a paper promise. We need an enforcement mechanism
that fails loudly during development, not quietly in production.

## Decision Drivers

- The isolation property must be impossible to violate accidentally.
- Enforcement should not depend on reviewer vigilance or runtime checks.
- Shared protocol artifacts (wire types, crypto primitives) must still be usable
  by both zones without weakening the seam.
- The mechanism must be visible and explainable to auditors.

## Considered Options

- Separate crates with no dependency edge between them, so cross-zone imports
  are a compile error.
- A single domain crate with module-level discipline (`identity::` vs
  `signal::`) enforced by convention and code review.
- Runtime separation only (separate processes/services) with shared libraries.

## Decision Outcome

Chosen: **separate crates with no dependency edge**, because the Cargo
dependency graph turns the architectural invariant into a compile error.
`pulse-identity` and `pulse-signal` are intentionally separate crates with no
dependency on each other, and neither may ever gain one. The only shared
artifacts are `pulse-crypto` (primitives), `pulse-protocol` (wire types), and
the Token Issuer's public verification key — which crosses the seam as data,
never as a code dependency.

### Positive Consequences

- Cross-zone imports cannot compile; the invariant is checked on every build.
- The seam is auditable by inspecting `Cargo.toml` files alone.
- Integration tests can assert the property structurally (identity-zone logs
  carry no token values; signal-zone records carry no employee IDs — the fields
  do not exist on the structs).

### Negative Consequences

- Genuinely shared logic must be hoisted into `pulse-crypto` or
  `pulse-protocol`, which takes more design care than a quick cross-import.
- Some duplication between zones is accepted as the price of isolation.
- The workspace has more crates than a naive layout would need.

## Implementation

Already in force across the workspace. `pulse-identity` and `pulse-signal` have
no edge in the Cargo graph; the composition root (`pulse-server`) is the only
crate that sees both zones. The rule is documented as a hard constraint in
CLAUDE.md, and ADR-0002 records the second enforcement layer at the composition
root.
