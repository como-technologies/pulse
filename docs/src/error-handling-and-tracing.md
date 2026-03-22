# Error Handling and Tracing

How Pulse handles errors, logs operations, and prevents accidental PII leaks through the type system.

## The Sensitive trait

Pulse is a privacy-critical system. The Identity zone knows WHO submitted a response; the Signal zone knows WHAT was submitted. Logs that mix these domains break the anonymity guarantee. Even within a single zone, leaking employee IDs or cryptographic material into logs creates an attack surface.

The `Sensitive` marker trait (defined in `pulse-protocol/src/newtypes.rs`) enforces this at the type level:

```rust
{{#include ../../crates/pulse-protocol/src/newtypes.rs:sensitive_trait}}
```

Any type implementing `Sensitive` must override `Debug` and `Display` to output `[REDACTED]`. This means Rust's standard formatting — and by extension, the `tracing` crate — can never accidentally print the inner value.

### Sensitive types

| Type | Crate | Why it's sensitive |
|------|-------|--------------------|
| `EmployeeId` | pulse-identity | PII — directly identifies a person |
| `SessionToken` | pulse-identity | Authentication session token |
| `BlindedToken` | pulse-protocol | Could link identity to signal |
| `BlindSig` | pulse-protocol | Cryptographic material |
| `TokenBytes` | pulse-protocol | Contains full token value |
| `SignatureBytes` | pulse-protocol | Could link identity to signal |
| `EncryptedBlob` | pulse-protocol | Encrypted response content |

### Safe types (normal Debug/Display)

`QuestionBatchId`, `TenantId`, `KeyVersion`, `UnixTimestamp`, `QuestionText`, `SegmentLabel`, `Nonce`

These are metadata that do not identify individuals or link trust zones.

### How it works with tracing

The `tracing` crate formats values using `Display` (via `%`) or `Debug` (via `?`). Because sensitive types redact both, any use in a tracing macro is safe:

```rust
// EmployeeId has redacted Display and Debug
let employee_id = EmployeeId("alice@example.com".into());

// All of these output "[REDACTED]" — no leak possible:
tracing::info!(%employee_id, "processing request");     // Display
tracing::info!(?employee_id, "processing request");     // Debug
tracing::info!(id = %employee_id, "processing request"); // named field
```

The `#[tracing::instrument]` attribute automatically records function parameters in spans. Because sensitive types are redacted, they're safe to include without `skip()`:

```rust
// employee_id and request are safe because EmployeeId and BlindedToken
// both implement Sensitive with redacted Debug. Only skip(self) is
// needed to avoid logging struct internals (e.g., secret keys from
// external crates that we can't control).
#[tracing::instrument(
    skip(self),
    fields(question_batch_id = %request.question_batch_id)
)]
pub fn sign_token(
    &self,
    employee_id: &EmployeeId,
    request: &TokenRequest,
) -> Result<TokenResponse, IssuerError> { ... }
```

### Adding a new sensitive type

1. Define your newtype as usual (with `#[serde(transparent)]`, `pub` inner field)
2. Do **not** derive `Debug` — implement it manually:
   ```rust
   impl fmt::Debug for MyType {
       fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
           f.debug_tuple("MyType").field(&"[REDACTED]").finish()
       }
   }
   ```
3. Implement `Display` similarly:
   ```rust
   impl fmt::Display for MyType {
       fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
           write!(f, "[REDACTED:MyType]")
       }
   }
   ```
4. Implement the marker: `impl Sensitive for MyType {}`
5. Access the inner value via `.0` for database or wire operations

### When to use skip() vs rely on redaction

| Scenario | Approach |
|----------|----------|
| Parameter is a Pulse newtype implementing `Sensitive` | No `skip()` needed — redaction is automatic |
| Parameter is `&self` containing external types (e.g., `BrssSecretKey`) | Use `skip(self)` — we can't control the external type's Debug impl |
| Parameter is a large struct you don't want in span output | Use `skip(param)` for performance/noise, not privacy |

## Error handling

### Domain crates

Each domain crate defines a `thiserror` error enum:

- `pulse-crypto`: `BlindSigError`, `AeadError`
- `pulse-identity`: `IssuerError` (wraps `TokenDeniedReason` and `BlindSigError`), `AuthError` (wraps `InvalidCredentials` and `ProviderError`), `SamplingError` (wraps `NotAssigned`, `FrequencyCapExceeded`, `BatchExpired`)
- `pulse-signal`: `CollectorError` (wraps `RejectReason`)

All public functions return `Result<T, CrateError>`. Domain crates do not log — the caller decides the appropriate log level.

### HTTP layer

`pulse-server/src/error.rs` defines `ApiError`, the server-layer error type. Every error response has a flat JSON shape:

```json
{ "code": "RESPONSE_TOKEN_ALREADY_SPENT", "message": "token has already been used" }
```

- **code**: Stable, SCREAMING_SNAKE_CASE, machine-readable. Clients should switch on this.
- **message**: Human-readable, may change between versions. For developer convenience only.

### Status code mapping

| Status | Meaning | Example codes |
|--------|---------|---------------|
| 400 | Malformed request (bad JSON, missing fields) | `BAD_REQUEST` |
| 401 | Authentication failure | `UNAUTHORIZED` |
| 403 | Policy denial | `TOKEN_DENIED_FREQUENCY_CAP`, `TOKEN_DENIED_NOT_AUTHORIZED`, `TOKEN_DENIED_BATCH_EXPIRED` |
| 422 | Semantically invalid | `RESPONSE_INVALID_SIGNATURE`, `RESPONSE_TOKEN_EXPIRED`, `RESPONSE_TOKEN_ALREADY_SPENT`, `RESPONSE_BATCH_MISMATCH`, `RESPONSE_TENANT_MISMATCH`, `RESPONSE_MALFORMED` |
| 500 | Internal server error | `SIGNING_FAILED` |

### Error mapping

Domain errors are converted to `ApiError` via explicit mapping functions — not blanket `From` impls. This is deliberate: in a security-sensitive system, every error that crosses a trust boundary should be explicitly mapped and auditable.

```rust
// In identity_routes.rs
fn map_issuer_error(e: IssuerError) -> ApiError { ... }

// In signal_routes.rs
fn map_collector_error(e: CollectorError) -> ApiError { ... }
```

## Tracing

### Log levels

| Level | Usage | Example |
|-------|-------|---------|
| ERROR | Internal failures | Crypto operation failed, unexpected state |
| WARN | Client-caused rejections | Invalid signature, duplicate token, expired token |
| INFO | Successful operations, startup | "token issued", "response accepted", "listening on port 8001" |
| DEBUG | Validation step details | "deserializing token payload", "verifying blind signature" |

### Request spans

Every HTTP request gets a span with:

```
request{zone="signal" method=POST path="/response" request_id="a1b2c3d4-..."}
```

- **zone**: "identity" or "signal" — filter logs by trust zone
- **request_id**: UUID generated per-request, propagated in `x-request-id` response header
- All log events within the request inherit this span context

### Controlling log output

Default filter: `pulse=info,tower_http=info`

Override via the `RUST_LOG` environment variable:

```sh
# See validation step details in the signal zone
RUST_LOG=pulse_signal=debug cargo run -p pulse-server

# See everything
RUST_LOG=trace cargo run -p pulse-server

# Quiet — errors only
RUST_LOG=pulse=error cargo run -p pulse-server
```

### Example output

A successful response submission at INFO level:

```
2026-03-21T10:00:00Z  INFO request{zone="signal" method=POST path="/response" request_id="a1b2..."}: ResponseCollector::accept{question_batch_id=f5e6... tenant_id=aabb... key_version=1}: pulse_signal::response_collector: response accepted
```

At DEBUG level, the individual validation steps also appear:

```
2026-03-21T10:00:00Z DEBUG ...: pulse_signal::response_collector: deserializing token payload
2026-03-21T10:00:00Z DEBUG ...: pulse_signal::response_collector: checking token fields
2026-03-21T10:00:00Z DEBUG ...: pulse_signal::response_collector: verifying blind signature
2026-03-21T10:00:00Z DEBUG ...: pulse_signal::response_collector: checking spent-token ledger
2026-03-21T10:00:00Z DEBUG ...: pulse_signal::response_collector: storing encrypted response
2026-03-21T10:00:00Z  INFO ...: pulse_signal::response_collector: response accepted
```

## Tests that verify these guarantees

The test suite includes tests that verify redaction, error structure, and tracing as security invariants — not just functional correctness.

### Redaction tests

These prove that `Debug` and `Display` never leak inner values for sensitive types:

- `sensitive_types_redact_debug` — All 5 protocol sensitive types output `[REDACTED]` via `{:?}`
- `sensitive_types_redact_display` — All 5 protocol sensitive types output `[REDACTED]` via `{}`
- `sensitive_types_still_serialize_to_real_values` — Serde still serializes the real inner value (redaction only affects formatting, not wire protocol)
- `safe_types_show_real_values_in_debug` — Non-sensitive types like `QuestionBatchId` are not accidentally redacted
- `employee_id_redacts_debug_and_display` — `EmployeeId` with value `"alice@example.com"` outputs `[REDACTED]`, never `"alice"`
- `employee_id_inner_value_accessible_via_field` — `.0` still provides the real value for database operations
- `employee_id_equality_works_despite_redacted_debug` — `PartialEq` compares real values, unaffected by redacted Debug

### Error response tests

These prove the HTTP layer returns structured, correctly-coded errors:

- `duplicate_submission_returns_422_with_error_code` — Status 422, code `RESPONSE_TOKEN_ALREADY_SPENT`
- `forged_signature_returns_422` — Status 422, code `RESPONSE_INVALID_SIGNATURE`
- `batch_mismatch_returns_422` — Status 422, code `RESPONSE_BATCH_MISMATCH`
- `empty_api_key_returns_401` — Status 401, code `UNAUTHORIZED`
- `missing_auth_header_returns_401` — Status 401 when no `Authorization` header is sent
- `invalid_session_token_returns_401` — Status 401 when session token is invalid
- `error_response_has_consistent_structure` — Every error response has exactly `code` and `message` fields

### Tracing tests

These prove observability events fire (or don't fire) at the right times:

- `accept_logs_success` — Successful acceptance logs "response accepted" and all debug steps
- `duplicate_submission_does_not_log_success` — Replay rejection doesn't produce a success log
- `forged_signature_logs_no_success` — Invalid signature stops before success, logs verification step

Run all of them:

```sh
cargo test --workspace
```
