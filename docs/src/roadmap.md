# Roadmap

*Project milestones and phasing. Updated as decisions are made and work completes.*

---

## Milestone Structure

Development is organized in three tiers, reflecting increasing operational maturity:

| Tier | Milestone | Focus | Status |
|------|-----------|-------|--------|
| Day-0 | Server-Side Infrastructure | Working system for demos and soft pilots | **Complete** (Issues #1--#7) |
| Day-1 | Production Readiness | What's needed for real production deployments | In progress |
| Day-1 | Client-Side (phased) | Client SDK and device integration | Not started |
| Day-2 | Operations & Fleet Management | Post-launch operational maturity | Not started |

---

## Day-0: Server-Side Infrastructure (Complete)

The foundational server-side stack, from blind signature protocol through analytics:

- **Blind signature protocol** -- full RSA blind signature flow (RFC 9474) with token issuance, unblinding, and verification
- **Trust zone isolation** -- Cargo dependency graph enforces Identity/Signal separation at compile time
- **Sampling engine** -- question assignment, k-anonymity segment coarsening, frequency cap enforcement
- **Anonymizing relay** -- standalone binary with batching, shuffling, timing decorrelation, no domain dependencies
- **Multi-tenancy** -- per-tenant keys, two-tier envelope encryption (CMK + DEK), crypto-shredding
- **Analytics engine** -- pseudonym-based aggregation, segment grouping, k-anonymity suppression at query time
- **Binary wire format** -- postcard serialization for all protocol messages with `Binary<T>` extractor

---

## Day-1: Production Readiness (In Progress)

Capabilities needed for real deployments with actual customers. Not needed for demos but required before launch.

### KMS Integration (#8--#10)

Replace development key management with production infrastructure:

- **KMS-backed CMK provider** -- delegate wrap/unwrap to the tenant's cloud KMS (AWS KMS first). Pulse never holds the CMK.
- **DEK caching** -- in-memory DEK cache with configurable TTL to reduce KMS round-trips while limiting the plaintext-in-memory window.
- **Tenant-managed provisioning** -- tenants provide their own CMK reference (KMS ARN) during onboarding. Validation, rotation, and offboarding flows.

### Control Plane (#11--#14)

Authenticated management channel for client lifecycle:

- **Architecture** (#11) -- define the control plane / data plane split as an ADR. Control plane lives in the Identity zone; data plane is the existing two-phase protocol.
- **Protocol version negotiation** (#12) -- clients declare protocol version at auth time. Server gates token issuance on minimum supported version. Platform-aware update hints.
- **Desktop client updates** (#13) -- UEM integration patterns for managed desktops. Self-update fallback for unmanaged environments.
- **Mobile client updates** (#14) -- app store deeplinks, grace period vs. hard cutoff semantics.

### Client-Side (Phased)

The actual client applications, developed in phases:

- **Day-0 (Demo)** -- WASM or simple Dioxus app. Proves the protocol end-to-end in a browser or desktop window.
- **Day-1 (Launch)** -- Production mobile apps (first), desktop system-tray app (fast follower). Store-and-forward, timing delays, protocol client library.
- **Day-2 (Full Suite)** -- Embedded/IoT clients, device attestation, advanced capability negotiation.

---

## Day-2: Operations & Fleet Management (Future)

Post-launch operational maturity. Builds on the control plane foundation.

- **Embedded/IoT OTA** (#15) -- over-the-air firmware delivery with embassy-boot partition swap, SUIT manifests (RFC 9019/9124), rollback safety
- **Control plane expansion** -- configuration delivery, fleet health dashboards, poll scheduling
- **Advanced analytics** -- trend detection, anomaly detection, cross-epoch analysis
- **Observability** -- production monitoring, alerting, incident response playbooks

---

## Client Platform Strategy

| Platform | Timeline | Update Mechanism | Notes |
|----------|----------|-----------------|-------|
| Native desktop | Day-1 | Enterprise UEM (Intune, SCCM, Jamf) | System tray app. Primary target. |
| Mobile | Day-1 | App stores (iOS, Android) | Fast follower after desktop. |
| WASM / Dioxus | Day-0 | Deploy-at-once (web asset) | Demo and proof-of-concept only. |
| Embedded / IoT | Day-2 | OTA firmware (embassy-boot) | Kiosks, breakroom buttons, wearables. |

All clients are built in Rust: native via direct compilation, mobile via UniFFI, WASM via wasm-bindgen, embedded via `no_std`. The postcard wire format is `no_std`-compatible across all targets.

---

## Technology Stack

| Layer | Choice | Notes |
|-------|--------|-------|
| Language | Rust | End-to-end: server, client, WASM, mobile (UniFFI), embedded (`no_std`) |
| HTTP framework | Axum + Tokio | Composition root in `pulse-server` |
| Blind signatures | RSA per RFC 9474 | `blind-rsa-signatures` crate. EC-based schemes as future option for constrained devices. |
| Wire format | Postcard (binary) | Compact, serde-native, `no_std`. JSON retained for auth/debug/analytics/errors. |
| Pseudonym derivation | HMAC-SHA256 | Client-side, epoch-rotated. Anonymous credentials (DAA/Idemix) as future evolution. |
| Encryption | AES-256-GCM | Two-tier envelope: CMK (tenant KMS) + DEKs (Pulse-generated, wrapped). |
| Storage | SQLite (current) | Behind traits. Production backends (Postgres, etc.) via adapter pattern. |
| Property testing | Proptest | Cryptographic operations verified for arbitrary inputs. |
