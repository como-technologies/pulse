# pulse-identity

Identity zone domain logic. Knows WHO is participating -- never knows WHAT they said.

Has **no dependency** on `pulse-signal`. The Cargo dependency graph enforces this trust zone boundary at compile time.

## Key Types

| Type | Description |
|------|-------------|
| `TokenIssuer` | Blind-signs tokens after authorization. Use `with_sampling()` for production, `new()` for protocol-only tests. |
| `EmployeeId` | Sensitive newtype for employee identity (redacted Debug/Display) |
| `QuestionBatch` | A batch of questions assigned to employees |
| `SamplingDecision` | Result of the sampling engine's assignment logic |
| `IssuanceRecord` | Audit record of token issuance (employee + batch + timestamp) |

## Traits

| Trait | Description | In-memory impl |
|-------|-------------|----------------|
| `Authenticator` | Pluggable credential verification | (see `DevAuthenticator` in pulse-server) |
| `SamplingEngine` | Question assignment, k-anonymity coarsening, frequency caps | `InMemorySamplingEngine` |
| `SessionStore` | Session token management | `InMemorySessionStore` |
| `TenantSigningKeyStore` | Per-tenant blind-signature signing key lookup | (see `InMemoryTenantKeyStore` in pulse-server) |

## Testing

```sh
cargo test -p pulse-identity
```

Tests cover k-anonymity coarsening, frequency cap enforcement, assignment authorization, and TokenIssuer integration with the sampling engine.
