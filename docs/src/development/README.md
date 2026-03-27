# Crate Structure

Pulse is a Cargo workspace with crates layered by responsibility.

```
crates/
  pulse-crypto/      Cryptographic primitives
  pulse-protocol/    Wire types and message definitions
  pulse-identity/    Identity zone domain logic
  pulse-signal/      Signal zone domain logic
  pulse-client/      Client-side protocol library
  pulse-tui/         Interactive terminal client (ratatui)
  pulse-server/      HTTP layer (Axum) — composition root
  pulse-relay/       Anonymizing relay (standalone binary)
```

## pulse-crypto

Low-level cryptographic operations. Blind signatures (RSA, per RFC 9474), AES-256-GCM authenticated encryption, and re-exports of underlying crypto crates. No domain logic -- just crypto building blocks.

## pulse-protocol

Shared wire types: `TokenPayload`, Phase 1 and Phase 2 message types. Serialized with [postcard](https://docs.rs/postcard) binary format via serde. Defines the contract between client and server without coupling to either side.

## pulse-identity

Identity zone domain logic. Defines traits and core types for the identity zone:

- `TokenIssuer` — blind signature issuance with optional sampling engine authorization
- `SamplingEngine` trait — question assignment, k-anonymity coarsening, frequency caps
- `Authenticator` trait — pluggable credential verification
- `SessionStore` trait — session token management
- `TenantSigningKeyStore` trait — per-tenant blind-signature signing key lookup
- `InMemorySamplingEngine` — full in-memory implementation for tests and examples

## pulse-signal

Signal zone domain logic. `ResponseCollector`: signature verification, spent-token ledger, response storage.

- `TenantVerificationKeyStore` trait — per-tenant blind-signature verification key lookup (by tenant + key version)

Domain logic depends on trait abstractions (e.g., `Arc<dyn SpentTokenLedger>`, `Arc<dyn ResponseStore>`), not concrete storage -- swap the adapter without touching domain code.

## pulse-client

Client-side protocol state machine. Platform-agnostic — no I/O, no UI, no platform-specific code.

- `HttpTransport` trait — pluggable HTTP transport (ships with `ReqwestTransport` behind a feature flag)
- `BlindedTokenState` → `SignedTokenState` → `ReadyToken` — typestate pattern enforcing the token lifecycle at compile time
- `PulseClient<T>` — high-level orchestrator: authenticate, fetch questions, blind/sign/unblind tokens, submit responses
- Protocol helpers — pseudonym derivation, response encryption, epoch computation

Depends on `pulse-crypto` and `pulse-protocol` only. See [Client Architecture](client-architecture.md) for the full design.

## pulse-tui

Interactive terminal client built with [ratatui](https://ratatui.rs/). Exercises the complete protocol flow end-to-end in a fully interactive TUI: connect, authenticate, browse questions, acquire a blind-signed token, enter a response, and submit anonymously. Includes a color-coded protocol log panel showing what each trust zone sees.

Depends on `pulse-client` for all protocol operations — no server-side crate dependencies.

## Trust zone isolation

`pulse-identity` and `pulse-signal` are separate crates with no dependency on each other. The Cargo dependency graph makes cross-zone imports a compile error -- the [trust zone boundary](../design/README.md) is enforced by the compiler, not by convention.

## pulse-server

Axum HTTP server and composition root. Exposes the Identity zone (port 8001) and Signal zone (port 8002) on separate listeners. Provides concrete implementations of domain traits:

- Dev providers: `DevAuthenticator`, `DevSamplingEngine`, `DevCmkProvider`, `InMemoryTenantKeyStore` (for local development)
- SQLite adapters: `SqliteLedger`, `SqliteStore` (for persistent storage)
- Multi-tenancy infrastructure: `CmkProvider` trait, `DekStore` trait, `EncryptingResponseStore` decorator, `TenantProvisioner`
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

pulse-client
  -> pulse-protocol
  -> pulse-crypto

pulse-tui
  -> pulse-client
  -> pulse-protocol
  -> pulse-crypto
```

## Technology Stack

| Layer                | Choice            | Notes                                                                  |
| -------------------- | ----------------- | ---------------------------------------------------------------------- |
| Language             | Rust              | End-to-end: server, client, WASM, mobile (UniFFI), embedded (`no_std`) |
| HTTP framework       | Axum + Tokio      | Server composition root                                                |
| Blind signatures     | RSA per RFC 9474  | EC-based schemes as future option for constrained devices              |
| Wire format          | Postcard (binary) | Compact, serde-native, `no_std`-compatible across all targets          |
| Pseudonym derivation | HMAC-SHA256       | Client-side, epoch-rotated                                             |
| Encryption           | AES-256-GCM       | Two-tier envelope: tenant CMK + Pulse-generated DEKs                   |
| Storage              | SQLite (current)  | Behind traits; production backends via adapter pattern                 |
| Property testing     | Proptest          | Cryptographic operations verified for arbitrary inputs                 |
