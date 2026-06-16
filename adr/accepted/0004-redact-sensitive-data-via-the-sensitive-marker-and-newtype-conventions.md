# ADR-0004: Redact sensitive data via the Sensitive marker and newtype conventions

> State: Accepted

## Status

Accepted

## Stakeholders

Pulse maintainers, anyone adding domain types or tracing instrumentation.

## Context and Problem Statement

Pulse logs aggressively (`#[tracing::instrument]` on public entry points), and
a single `Debug`-formatted employee ID or token value in a span would undo the
anonymity guarantee at the observability layer — the protocol can be perfect
and the logs still leak. At the same time, bare primitives (`u64`, `Vec<u8>`,
`String`, `Uuid`) as struct fields make it easy to pass a session token where a
batch ID was meant. Both risks call for conventions enforced by the type
system rather than by reviewer attention.

## Decision Drivers

- PII and linkable cryptographic material must never appear in logs, even via
  `%field` (Display) or `?field` (Debug) interpolation.
- Mixing up domain values of the same primitive type should be a compile error.
- Wire compatibility: the conventions must not change serialized shapes.
- Safe metadata (batch IDs, tenant IDs, key versions) must stay loggable.

## Considered Options

- Newtypes for every domain concept plus a `Sensitive` marker trait whose
  implementors override `Debug`/`Display` to print `[REDACTED]`.
- Discipline-based redaction: `skip` fields manually at every tracing call
  site.
- A logging middleware that scrubs known patterns from emitted records.

## Decision Outcome

Chosen: **newtypes + the `Sensitive` marker trait**, because it makes the safe
path the default. All domain concepts are newtype wrappers (shared ones in
`pulse-protocol`'s newtypes module, zone-specific ones in their zone crate,
`#[serde(transparent)]` for wire compatibility). Types containing PII
(`EmployeeId`, `SessionToken`) or linkable crypto material (`BlindedToken`,
`BlindSig`, `TokenBytes`, `SignatureBytes`, `EncryptedBlob`) implement
`Sensitive` and render as `[REDACTED]` in both `Debug` and `Display`; safe
metadata types keep normal formatting. Inner values stay reachable via `.0`
for database and wire operations.

### Positive Consequences

- Tracing is leak-safe by construction — interpolating a sensitive field
  outputs `[REDACTED]` no matter how it is formatted.
- Type confusion between domain values is a compile error.
- New contributors inherit the convention mechanically: adding a field starts
  with checking the newtypes module.

### Negative Consequences

- Boilerplate: every domain concept needs a wrapper type, and `.0` access is
  mildly noisy at storage/wire boundaries.
- Redacted `Debug` output makes some debugging sessions harder — deliberate
  friction that occasionally costs time.
- The convention must be applied when new types are added; a forgotten
  `Sensitive` impl is still possible (mitigated by review and the documented
  checklist in CLAUDE.md).

## Implementation

In force across all crates: the `Sensitive` trait and shared newtypes live in
`pulse-protocol`, zone-specific newtypes in their zone crates, and the
convention (including which types redact and which stay loggable) is documented
in CLAUDE.md and verified by redaction tests in `pulse-protocol`.
