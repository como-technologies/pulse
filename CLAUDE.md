# Pulse — Development Guidelines

## Trust Zone Isolation (Critical)

`pulse-identity` and `pulse-signal` are intentionally separate crates with no dependency on each other. This enforces the architectural invariant that the Identity zone (knows WHO) and Signal zone (knows WHAT) cannot share code or types.

**Never add `pulse-identity` as a dependency of `pulse-signal` or vice versa.** The Cargo dependency graph is the enforcement mechanism — cross-zone imports must remain a compile error.

The only shared artifacts between zones are:
- `pulse-crypto` — cryptographic primitives (used by both)
- `pulse-protocol` — wire types (used by both)
- The Token Issuer's public verification key (passed as data, not as a code dependency)
