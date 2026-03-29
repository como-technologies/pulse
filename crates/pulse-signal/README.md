# pulse-signal

Signal zone domain logic. Knows WHAT was said -- never knows WHO said it.

Has **no dependency** on `pulse-identity`. The Cargo dependency graph enforces this trust zone boundary at compile time.

## Key Types

| Type | Description |
|------|-------------|
| `ResponseCollector` | Verifies blind signatures, checks spent-token ledger, stores responses |
| `TokenHash` | SHA-256 hash of a spent token (only the hash is stored, not the token itself) |
| `StoredResponse` | An accepted response with encrypted blob, batch ID, tenant ID, and timestamp |
| `SpendResult` | `Accepted` or `AlreadySpent` |

## Traits

| Trait | Description | In-memory impl |
|-------|-------------|----------------|
| `SpentTokenLedger` | Tracks spent tokens to prevent replay | `InMemoryLedger` |
| `ResponseStore` | Stores accepted responses | `InMemoryStore` |
| `TenantVerificationKeyStore` | Per-tenant public key lookup by tenant + key version | (see `InMemoryTenantKeyStore` in pulse-server) |

## Testing

```sh
cargo test -p pulse-signal
```

Tests cover ledger correctness (first spend accepted, duplicate rejected), response collection pipeline, and tracing assertions.
