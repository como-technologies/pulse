# Testing & Simulation

How to verify Pulse's privacy and correctness properties, and run protocol simulations at scale.

## Interactive walkthrough

The `walkthrough` example runs the full blind signature protocol in-memory with step-by-step narration:

```sh
cargo run -p pulse-server --example walkthrough
```

It demonstrates:

- Sampling Engine setup: org hierarchy, roster, question assignment
- K-anonymity coarsening: small segments walk up the hierarchy
- Token creation with coarsened segment_vector, blinding, and blind signing (Phase 1)
- Sampling Engine authorization and frequency cap enforcement
- Unblinding, encryption, and anonymous submission (Phase 2)
- What each trust zone sees — and what it cannot see
- Replay prevention (duplicate token rejection)
- Forged signature rejection

No running server required. Read the output to build intuition about how the protocol enforces verified anonymity.

## Running the server

Start the server with default dev providers:

```sh
cargo run
```

The dev configuration uses:

| Variable | Default | Effect |
|----------|---------|--------|
| `PULSE_AUTH_PROVIDER` | `dev` | Accepts any non-empty credential as employee ID |
| `PULSE_SAMPLING_PROVIDER` | `dev` | Returns a default question for any employee |
| `PULSE_DB_URL` | `memory` | In-memory storage (no persistence) |
| `PULSE_K_THRESHOLD` | `5` | K-anonymity threshold |
| `PULSE_MAX_TOKENS_PER_BATCH` | `1` | Max tokens per employee per batch |
| `PULSE_KEY_PATH` | `pulse-signing-key.pem` | Signing key file (auto-generated) |
| `PULSE_KEY_VERSION` | `1` | Signing key version |

Test the full flow:

```sh
# Authenticate (JSON endpoint)
curl -s -X POST localhost:8001/auth \
  -H 'Content-Type: application/json' \
  -d '{"api_key":"alice"}' | jq .

# Get assigned questions — returns postcard binary (not JSON).
# Protocol endpoints use postcard binary wire format; use the
# walkthrough example or integration tests to exercise the full flow.
```

See [Authentication Providers](authentication.md), [Sampling Engine Providers](sampling-providers.md), and [Storage Providers](storage-providers.md) for implementing production backends.

## Test suite

Run the full suite across all crates:

```sh
cargo test --workspace
```

### By crate

```sh
cargo test -p pulse-crypto         # blind sigs + AEAD + proptest
cargo test -p pulse-protocol       # wire types, token serialization, sensitive redaction
cargo test -p pulse-identity       # sampling engine, k-anonymity, frequency caps, sessions, token issuer
cargo test -p pulse-signal         # spent-token ledger, response collector, tracing assertions
cargo test -p pulse-server         # protocol flow, HTTP e2e, error responses, SQLite storage, key persistence
cargo test -p pulse-client         # ProtocolEngine sync logic, typestate lifecycle, integration tests
cargo test -p pulse-test-harness   # harness self-tests (if any)
```

### By topic

```sh
cargo test coarsen                      # k-anonymity segment coarsening
cargo test frequency_cap                # issuance frequency caps
cargo test sign_token_denied            # sampling engine denial via TokenIssuer
cargo test full_protocol_flow           # 14-step in-memory protocol flow
cargo test full_http_flow               # HTTP round-trip across both zones
cargo test duplicate_submission         # replay prevention
cargo test forged_signature             # signature forgery rejection
```

### Integration tests only

```sh
cargo test --test protocol_flow    # in-memory protocol flow
cargo test --test e2e              # HTTP round-trip + sampling enforcement
cargo test --test error_responses  # structured error responses
```

## What each layer proves

### Unit tests (pulse-crypto, pulse-protocol, pulse-signal)

**Crypto correctness** — Blind signature round-trips produce verifiable signatures. Wrong keys and wrong messages fail verification. AES-256-GCM encrypts and decrypts correctly; wrong keys and tampered ciphertext fail. Property-based tests (proptest) verify these hold for arbitrary inputs.

**Wire type integrity** — `TokenPayload`, `TokenRequest`, `ResponseSubmit`, `QuestionDelivery` serialize and deserialize correctly. Expiry checks work at boundary values.

**Ledger correctness** — First spend accepted, duplicate spend rejected, distinct tokens independently accepted.

### Sampling engine tests (pulse-identity)

**K-anonymity coarsening** — Large segments (>= k members) keep their label. Small segments walk up the hierarchy to the nearest ancestor with >= k members. Multi-level walks and root fallback are tested. Multiple segments coarsen independently.

**Frequency cap enforcement** — First token issuance succeeds, second issuance for the same batch is denied. Authorization check and count increment are atomic (single lock).

**Assignment authorization** — Unassigned employees are denied. Expired batches are denied. Assignment queries exclude already-issued and expired batches.

**TokenIssuer integration** — `TokenIssuer::with_sampling()` routes authorization through the sampling engine. Denial reasons (`NotAuthorized`, `FrequencyCap`, `BatchExpired`) map to correct `IssuerError` variants.

### Integration tests (protocol_flow.rs)

**Full protocol flow** — 14-step blind signature lifecycle from token creation through response storage, all in-memory.

**Trust zone isolation** — Identity zone issuance log contains employee ID but no token value. Signal zone stored responses contain encrypted blob but no employee ID. Enforced by the type system — the fields do not exist on the structs.

**Replay prevention** — Same valid token submitted twice; second submission rejected.

**Forged signature rejection** — Fabricated signature bytes rejected.

**Batch/tenant validation** — Mismatched batch ID or tenant ID rejected.

### End-to-end test (e2e.rs)

**HTTP round-trip** — Full flow over HTTP with separate Identity and Signal zone routers on random ports. Exercises serialization, routing, and status codes. Duplicate submission returns HTTP 422 with structured error code.

**Segment vector delivery** — `GET /question` returns an array of question assignments, each with a `segment_vector` field containing coarsened org segments for k-anonymity.

**Frequency cap via HTTP** — Second token signing request for the same batch returns HTTP 403 with `TOKEN_DENIED_FREQUENCY_CAP` error code.

### Error response tests (error_responses.rs)

**Structured error format** — All error responses follow the `{ "code": "...", "message": "..." }` shape with exactly two fields.

**HTTP status codes** — Duplicate token → 422, forged signature → 422, batch mismatch → 422, empty API key → 401, invalid session → 401.

**Machine-readable codes** — Error codes like `RESPONSE_TOKEN_ALREADY_SPENT`, `RESPONSE_INVALID_SIGNATURE`, `UNAUTHORIZED` are stable and suitable for programmatic consumption.

### Multi-tenancy tests (multi_tenancy.rs, unit tests)

**Per-tenant keypair isolation** — Tokens signed by Tenant A's key are rejected when verified against Tenant B's key. Cross-tenant token reuse is cryptographically impossible.

**Envelope encryption** — Response blobs are encrypted under the tenant's DEK before storage. The inner store holds ciphertext different from the original blob. Decryption via `list()` returns the original.

**Crypto-shredding** — Deleting a tenant's wrapped DEKs makes stored response blobs permanently unreadable. The `EncryptingResponseStore` returns them as-is (still encrypted) rather than crashing.

**Tenant provisioning** — `TenantProvisioner` generates DEKs, wraps them under the CMK, generates blind-sig keypairs, and registers everything atomically.

### Tracing tests (response_collector)

**Observability verification** — Successful response acceptance logs "response accepted". Forged signatures do not log success. Debug-level validation steps are emitted for each stage of the pipeline.

## Testing strategy

### Layered testing

Protocol correctness is tested at two levels:

1. **In-memory** (`protocol_flow.rs`) — exercises the full blind signature lifecycle without HTTP serialization or routing. Fast, deterministic, isolates domain logic from transport concerns.
2. **Over HTTP** (`e2e.rs`) — exercises the same flow through real Axum routers on random ports. Catches serialization bugs, routing misconfigurations, and status code mapping issues that in-memory tests miss.

Both levels run on every `cargo test`. If a protocol-level test passes but an HTTP-level test fails, the bug is in the transport layer, not the domain logic.

### Backward compatibility via `TokenIssuer::new()`

Tests that verify core protocol properties (blind signature round-trip, replay prevention, forged signature rejection) use `TokenIssuer::new()` — no sampling engine attached. This ensures the protocol works independently of the sampling layer, which is important for isolating regressions. Tests that specifically exercise sampling authorization use `TokenIssuer::with_sampling()`.

### Property-based testing for crypto

`pulse-crypto` uses `proptest` to verify cryptographic operations hold for arbitrary inputs, not just known-good test vectors. This catches edge cases in key generation, blinding, signing, verification, and AEAD encryption that example-based tests miss.

### Dev providers in integration tests

E2E and error response tests use `DevSamplingEngine` (accepts any employee) rather than `InMemorySamplingEngine` (requires explicit roster setup). This mirrors the actual composition used when running `cargo run` with default config, ensuring the dev experience itself is tested.

### Test harness (`pulse-test-harness`)

Shared test infrastructure lives in the `pulse-test-harness` crate, used as a dev-dependency by `pulse-client` and `pulse-server`.

**`start_test_servers(with_analytics)`** — spins up ephemeral Identity and Signal zone servers on random ports with in-memory storage, dev providers, and optionally analytics. Replaces the previously duplicated `tests/common/mod.rs` files. Includes the `/config` endpoint for testing `PulseClient::connect()`.

```rust
use pulse_test_harness::start_test_servers;

#[tokio::test]
async fn my_test() {
    let servers = start_test_servers(false).await;
    // servers.identity_url, servers.signal_url, servers.pk, servers.tenant_id, etc.
}
```

**`MockTransport`** — in-memory `HttpTransport` for testing without network I/O. Routes are matched by HTTP method + URL substring. Records all requests for assertion.

```rust
use pulse_test_harness::{MockTransport, HttpMethod};
use pulse_client::TransportResponse;

let transport = MockTransport::new()
    .on(HttpMethod::PostJson, "/auth", TransportResponse {
        status: 200,
        body: br#"{"session_token":"tok-123"}"#.to_vec(),
    });

// Use transport with ProtocolEngine or ConnectedClient...
transport.assert_request_count("/auth", 1);
```

## Simulation framework

The `pulse-test-harness` crate includes a multi-tenant concurrent protocol simulation framework for load testing and correctness validation at scale.

### Running simulations

```sh
# Quick smoke test: 1 tenant, 10 employees, concurrency 10
cargo run -p pulse-test-harness --bin pulse-simulate

# Stress test: 3 tenants, 500 employees each, concurrency 200
cargo run -p pulse-test-harness --bin pulse-simulate -- --stress

# Custom configuration
cargo run -p pulse-test-harness --bin pulse-simulate -- \
    --tenants 5 --employees 100 --concurrency 50
```

### What it does

For each simulated tenant, the framework:

1. Generates a blind-signature keypair and provisions in-memory storage
2. Starts a pair of Identity + Signal zone servers on ephemeral ports
3. Creates the configured number of simulated employees (each with a unique ID and persistent secret)
4. Runs the full protocol flow for each employee concurrently, bounded by a semaphore

Each employee flow exercises the complete protocol: authenticate, fetch questions, blind token, request signature, finalize token, encrypt response, submit anonymously.

### What it reports

Per-operation timing at p50/p90/p99/max, aggregated across all flows and broken down per tenant:

```
============================================================
  Pulse Protocol Simulation Report
============================================================

  Total flows: 10  |  Passed: 10  |  Failed: 0
  Wall-clock time: 312.36ms

  Aggregate Timings (successful flows):
    authenticate     p50=1.38ms   p90=1.52ms   p99=1.52ms   max=1.52ms
    fetch_questions  p50=621.40us p90=680.67us p99=680.67us max=680.67us
    blind_and_sign   p50=30.48ms  p90=35.81ms  p99=35.81ms  max=35.81ms
    encrypt_submit   p50=2.05ms   p90=2.64ms   p99=2.64ms   max=2.64ms
    total_flow       p50=35.02ms  p90=39.49ms  p99=39.49ms  max=39.49ms

  Tenant 'Tenant-0': 10 flows (10 passed, 0 failed)
    total_flow       p50=35.02ms  p90=39.49ms  p99=39.49ms  max=39.49ms
```

Failed flows include the step that failed and the error message. The binary exits with code 0 if all flows pass, 1 if any fail.

### Programmatic use

The simulation framework can also be used from Rust code for custom scenarios:

```rust
use pulse_test_harness::simulation::*;

let config = SimulationConfig {
    tenants: vec![TenantSetup {
        name: "Acme Corp".into(),
        employee_count: 100,
        question_batches: vec![QuestionBatchSetup { /* ... */ }],
        max_tokens_per_batch: 1,
    }],
    concurrency: 50,
    with_analytics: true,
};

let cluster = SimulationCluster::start(&config).await;
let runner = SimulationRunner::new(cluster, config.concurrency);
let report = runner.run().await;
assert_eq!(report.failed, 0);
```
