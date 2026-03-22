# Pulse — Development Guidelines

## Trust Zone Isolation (Critical)

`pulse-identity` and `pulse-signal` are intentionally separate crates with no dependency on each other. This enforces the architectural invariant that the Identity zone (knows WHO) and Signal zone (knows WHAT) cannot share code or types.

**Never add `pulse-identity` as a dependency of `pulse-signal` or vice versa.** The Cargo dependency graph is the enforcement mechanism — cross-zone imports must remain a compile error.

The only shared artifacts between zones are:
- `pulse-crypto` — cryptographic primitives (used by both)
- `pulse-protocol` — wire types (used by both)
- The Token Issuer's public verification key (passed as data, not as a code dependency)

## Newtype Convention

All domain concepts use newtype wrappers. Bare primitives (`u64`, `Vec<u8>`, `String`, `Uuid`) should not appear as struct fields in domain types.

- Shared newtypes live in `pulse-protocol/src/newtypes.rs` (re-exported from `pulse_protocol`)
- Zone-specific newtypes live in their zone crate (e.g., `EmployeeId` in `pulse-identity`)
- All newtypes use `#[serde(transparent)]` for wire-compatible serialization
- All newtypes use `pub` inner fields (matching `TokenHash(pub [u8; 32])`)
- Semantic constructors where invariants exist (e.g., `Nonce::random()`, `UnixTimestamp::now()`)
- When adding a new field: check `pulse-protocol/src/newtypes.rs` first, create a newtype if none exists

## Pre-Push Checklist (Required)

Before every push, run all three checks against the full workspace **including tests and examples**:

```sh
cargo fmt --check
cargo clippy --workspace --tests --examples
cargo test --workspace
```

All three must pass clean. Do not push with formatting diffs, clippy warnings, or test failures.
