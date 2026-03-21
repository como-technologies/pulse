# Crate Structure

Pulse is a Cargo workspace with four crates, layered by responsibility.

```
crates/
  pulse-crypto/      Cryptographic primitives
  pulse-protocol/    Wire types and message definitions
  pulse-core/        Domain logic (Identity and Signal zones)
  pulse-server/      HTTP layer (Axum)
```

## pulse-crypto

Low-level cryptographic operations. Blind signatures (RSA, per RFC 9474), AES-256-GCM authenticated encryption, and re-exports of underlying crypto crates. No domain logic -- just crypto building blocks.

## pulse-protocol

Shared wire types: `TokenPayload`, Phase 1 and Phase 2 message types. Serde-serializable. Defines the contract between client and server without coupling to either side.

## pulse-core

Domain logic, split into two modules that mirror the trust zone separation:

- **`identity`** -- `TokenIssuer`: blind signature issuance, token validation, frequency bookkeeping
- **`signal`** -- `ResponseCollector`: signature verification, spent-token ledger, response storage

Hexagonal architecture: domain traits (`SpentTokenLedger`, `ResponseStore`) with in-memory implementations for testing. No cross-imports between `identity` and `signal` modules.

## pulse-server

Axum HTTP server exposing the Identity zone (port 8001) and Signal zone (port 8002) on separate listeners. Thin adapter layer -- delegates all logic to `pulse-core`.

## Dependency Graph

```
pulse-server
  -> pulse-core
       -> pulse-protocol
       -> pulse-crypto
```
