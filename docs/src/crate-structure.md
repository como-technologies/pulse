# Crate Structure

Pulse is a Cargo workspace with six crates, layered by responsibility.

```
crates/
  pulse-crypto/      Cryptographic primitives
  pulse-protocol/    Wire types and message definitions
  pulse-identity/    Identity zone domain logic
  pulse-signal/      Signal zone domain logic
  pulse-server/      HTTP layer (Axum) — composition root
  pulse-relay/       Anonymizing relay (standalone binary)
```

## pulse-crypto

Low-level cryptographic operations. Blind signatures (RSA, per RFC 9474), AES-256-GCM authenticated encryption, and re-exports of underlying crypto crates. No domain logic -- just crypto building blocks.

## pulse-protocol

Shared wire types: `TokenPayload`, Phase 1 and Phase 2 message types. Serde-serializable. Defines the contract between client and server without coupling to either side.

## pulse-identity

Identity zone domain logic. Defines traits and core types for the identity zone:

- `TokenIssuer` — blind signature issuance with optional sampling engine authorization
- `SamplingEngine` trait — question assignment, k-anonymity coarsening, frequency caps
- `Authenticator` trait — pluggable credential verification
- `SessionStore` trait — session token management
- `InMemorySamplingEngine` — full in-memory implementation for tests and examples

## pulse-signal

Signal zone domain logic. `ResponseCollector`: signature verification, spent-token ledger, response storage.

Domain logic depends on trait abstractions (e.g., `Arc<dyn SpentTokenLedger>`, `Arc<dyn ResponseStore>`), not concrete storage -- swap the adapter without touching domain code.

## Trust zone isolation

`pulse-identity` and `pulse-signal` are separate crates with no dependency on each other. The Cargo dependency graph makes cross-zone imports a compile error -- the [trust zone boundary](architecture.md) is enforced by the compiler, not by convention.

## pulse-server

Axum HTTP server and composition root. Exposes the Identity zone (port 8001) and Signal zone (port 8002) on separate listeners. Provides concrete implementations of domain traits:

- Dev providers: `DevAuthenticator`, `DevSamplingEngine` (for local development)
- SQLite adapters: `SqliteLedger`, `SqliteStore` (for persistent storage)
- Config-driven provider selection via environment variables
- Auth extractor, error mapping, request tracing

## pulse-relay

Standalone anonymizing relay binary. Transport-level anonymizer between clients and the Signal zone. Strips source IP, timing metadata, and client-fingerprinting headers. Batches and shuffles requests for timing decorrelation.

No domain crate dependencies -- treats all payloads as opaque bytes. See the [Anonymizing Relay](relay.md) guide.

## Dependency Graph

```
pulse-server                 pulse-relay (standalone, no domain deps)
  -> pulse-identity
  |    -> pulse-protocol
  |    -> pulse-crypto
  -> pulse-signal
       -> pulse-protocol
       -> pulse-crypto
```
