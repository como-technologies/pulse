# pulse-client

Platform-agnostic protocol client for Pulse anonymous polling.

Implements the complete client-side protocol state machine for the Pulse blind signature flow. Depends only on `pulse-protocol` (wire types) and `pulse-crypto` (cryptographic primitives) — never on server-side crates.

## Architecture

- **`transport`** — `HttpTransport` trait with a `ReqwestTransport` implementation (feature-gated behind `reqwest-transport`)
- **`token_state`** — Typestate pattern for the token lifecycle: `BlindedTokenState` -> `SignedTokenState` -> `ReadyToken`
- **`protocol`** — Stateless helpers: pseudonym derivation, response encryption, epoch computation
- **`flow`** — `PulseClient<T>` orchestrator tying transport + token state + protocol together

## Usage

```rust
use pulse_client::{PulseClient, ReqwestTransport};

let client = PulseClient::new(
    ReqwestTransport::new(),
    "http://localhost:3000".into(), // identity zone
    "http://localhost:3001".into(), // signal zone
    public_key,
    tenant_id,
);

// Phase 1: Authenticated (Identity Zone)
let session = client.authenticate("employee-42").await?;
let questions = client.fetch_questions(&session).await?;
let blinded = client.blind_token(&questions[0], AttestationClass::Personal, KeyVersion(1))?;
let signed = client.request_signature(&session, blinded).await?;
let ready = client.finalize_token(signed)?;

// Phase 2: Anonymous (Signal Zone)
let blob = encrypt_response(&dek, pseudonym, epoch_id, ...)?;
client.submit_response(&ready, blob).await?;
```

## Transport Abstraction

The `HttpTransport` trait allows platform-specific implementations:

| Platform     | Transport              |
| ------------ | ---------------------- |
| Desktop      | `ReqwestTransport`     |
| WASM         | `fetch`-based (future) |
| Mobile       | Platform HTTP (future) |
| Embedded/IoT | Custom (future)        |

Disable the default `reqwest-transport` feature to compile without reqwest for alternative transports.

## Testing

Unit tests cover the typestate lifecycle and protocol helpers. Integration tests in `tests/against_server.rs` drive the full flow against real HTTP servers.

```sh
cargo test -p pulse-client
```
