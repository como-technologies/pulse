# Pulse — Development Guidelines

## Trust Zone Isolation (Critical)

`pulse-identity` and `pulse-signal` are intentionally separate crates with no dependency on each other. This enforces the architectural invariant that the Identity zone (knows WHO) and Signal zone (knows WHAT) cannot share code or types.

**Never add `pulse-identity` as a dependency of `pulse-signal` or vice versa.** The Cargo dependency graph is the enforcement mechanism — cross-zone imports must remain a compile error.

### Composition-Root State Split

In `pulse-server` (the composition root that sees both zones), state is split into two separate types:

- **`IdentityState`** — holds `TokenIssuer`, `Authenticator`, `SessionStore`. Used by identity-zone route handlers.
- **`SignalState`** — holds `ResponseCollector`, `ResponseStore`. Used by signal-zone route handlers.

This prevents auth components from leaking into the Signal zone at the composition-root level. The `AuthenticatedEmployee` extractor compiles only against `IdentityState` — using it in a signal-zone handler is a compile error.

**Never merge these back into a single shared state type.** The split is the second layer of enforcement (after the Cargo graph) that keeps zones isolated.

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

## Sensitive Data Convention

Types containing PII or cryptographic material that could link identity to signal must implement the `Sensitive` marker trait (defined in `pulse-protocol/src/newtypes.rs`) and override `Debug` and `Display` to output `[REDACTED]`.

- **PII types**: `EmployeeId`, `SessionToken` — redact Debug + Display
- **Linkable crypto material**: `BlindedToken`, `BlindSig`, `TokenBytes`, `SignatureBytes`, `EncryptedBlob` — redact Debug + Display
- **Safe metadata** (keep normal Debug/Display): `QuestionBatchId`, `TenantId`, `KeyVersion`, `UnixTimestamp`, `QuestionText`, `SegmentLabel`
- Access inner values via `.0` for database/wire operations
- The type system prevents accidental PII leaks in tracing — both `%field` (Display) and `?field` (Debug) output `[REDACTED]`
- When adding a new type: if it contains PII or cryptographic material, implement `Sensitive` and redact Debug/Display

## Error Handling Convention

### Domain crates (`pulse-identity`, `pulse-signal`, `pulse-crypto`)
- Use `thiserror` enums for typed, matchable errors
- Return `Result<T, CrateError>` from all fallible public functions
- Lock `.expect("...poisoned")` is intentional — mutex poisoning should crash the process

### HTTP layer (`pulse-server`)
- `ApiError` is the server-layer error type (in `pulse-server/src/error.rs`)
- Every error response has the flat shape: `{ "code": "...", "message": "..." }`
- `code` is a stable, SCREAMING_SNAKE_CASE, machine-readable identifier
- `message` is human-readable and may change between versions
- HTTP status code mapping:
  - **400**: Malformed request (bad JSON, missing fields)
  - **401**: Authentication failure
  - **403**: Policy denial (frequency cap, not authorized, batch expired)
  - **422**: Semantically invalid (expired token, duplicate token, bad signature)
  - **500**: Internal server error (crypto failure, unexpected state)
- Domain errors → `ApiError` conversion is explicit via `map_issuer_error()` / `map_collector_error()` — no blanket `From` impls across trust boundaries
- `warn` for 4xx client errors, `error` for 5xx server errors (handled in `ApiError::IntoResponse`)

## Tracing Convention

- All `pulse_*` crates may depend on `tracing` for instrumentation
- Use `#[tracing::instrument]` on public entry-point functions
- `skip(self)` to avoid logging struct internals (especially secret keys)
- Use `fields(key = %value)` to add structured context to spans — only safe metadata (batch_id, tenant_id, key_version)
- Sensitive types have redacted Debug/Display so `skip()` is not needed for them, but `skip(self)` remains necessary for structs containing external types (e.g., `BrssSecretKey`)
- Log levels:
  - **ERROR**: Internal failures (crypto errors, unexpected state)
  - **WARN**: Client-caused rejections (invalid signature, duplicate token, expired token)
  - **INFO**: Successful operations (token issued, response accepted), startup events
  - **DEBUG**: Validation step details inside multi-step operations
- Default log filter: `pulse=info,tower_http=info` — override via `RUST_LOG` env var
- Request IDs: Generated per-request via `x-request-id` header, propagated to response, included in all span context

## Pre-Push Checklist (Required)

Before every push, run all three checks against the full workspace **including tests and examples**:

```sh
cargo fmt --check
cargo clippy --workspace --tests --examples
cargo test --workspace
```

All three must pass clean. Do not push with formatting diffs, clippy warnings, or test failures.
