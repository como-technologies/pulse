# pulse-client

Platform-agnostic protocol client for Pulse anonymous polling.

Implements the complete client-side protocol state machine for the Pulse blind signature flow. Depends only on `pulse-protocol` (wire types) and `pulse-crypto` (cryptographic primitives) -- never on server-side crates.

## Architecture

- **`engine`** -- Sync `ProtocolEngine`: message building, response parsing, and crypto operations. No I/O, no async. The future `no_std` extraction point.
- **`flow`** -- `PulseClient<T>` (disconnected) and `ConnectedClient<T>` (connected) typestate orchestrators
- **`transport`** -- `HttpTransport` trait with `ReqwestTransport` (feature-gated behind `reqwest-transport`)
- **`token_state`** -- Typestate pattern: `BlindedTokenState` -> `SignedTokenState` -> `ReadyToken`
- **`protocol`** -- Stateless helpers: pseudonym derivation, response encryption, epoch computation

## Typestate Flow

Protocol progression is enforced at compile time at three levels:

**Connection state:** `PulseClient<T>` can only `connect()` or `authenticate()`. Calling `blind_token()` on a disconnected client is a compile error.

```
PulseClient<T>  --connect()--> ConnectedClient<T>
```

**Data-flow ordering:** Each method returns the type required by the next step.

```
authenticate()      -> SessionContext
fetch_questions()   -> Vec<QuestionDelivery>
blind_token()       -> BlindedTokenState
request_signature() -> SignedTokenState
finalize_token()    -> ReadyToken
submit_response()   -> ()
```

**Token lifecycle:** `BlindedTokenState` -> `SignedTokenState` -> `ReadyToken`. Each transition consumes the previous state.

## Usage

### With server config discovery

```rust
use pulse_client::{PulseClient, ReqwestTransport};

let client = PulseClient::new(
    ReqwestTransport::new(),
    "http://localhost:8001".into(),
    "http://localhost:8002".into(),
);
let (client, _config) = client.connect().await?;

// client is now a ConnectedClient -- full protocol available
let session = client.authenticate("employee-42").await?;
let questions = client.fetch_questions(&session).await?;
// ...
```

### With pre-loaded config (tests, cached config)

```rust
use pulse_client::{ConnectedClient, ReqwestTransport};

let client = ConnectedClient::with_config(
    ReqwestTransport::new(),
    identity_url,
    signal_url,
    public_key,
    tenant_id,
    KeyVersion(1),
);
```

### Sync-only via ProtocolEngine

For embedded or test scenarios that don't need async:

```rust
use pulse_client::ProtocolEngine;

let engine = ProtocolEngine::new(public_key, tenant_id, KeyVersion(1));

// Build request bytes (sync)
let body = ProtocolEngine::build_auth_request("employee-42")?;
// ... send via your own transport ...
// Parse response bytes (sync)
let session = ProtocolEngine::parse_auth_response(&response)?;
```

## Transport Abstraction

The `HttpTransport` trait allows platform-specific implementations:

| Platform        | Transport          |
|-----------------|--------------------|
| Desktop, Mobile | `ReqwestTransport` |
| Embedded / IoT  | Custom (future)    |

Disable the default `reqwest-transport` feature to compile without reqwest.

## Testing

```sh
cargo test -p pulse-client
```

Unit tests cover the `ProtocolEngine` sync logic and typestate lifecycle. Integration tests in `tests/against_server.rs` drive the full flow against real HTTP servers via `pulse-test-harness`.
