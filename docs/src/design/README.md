# Pulse — System Architecture

*Living document. Technology-agnostic. Describes the high-level architecture of the Pulse platform.*

*Companion documents: [Anonymity Protocol](anonymity-protocol.md) | [Device Attestation](device-attestation.md) | [Key Management](key-management.md) | [Threat Model](threat-model.md)*

---

## 1. Foundational Principle

> **No component in the system can simultaneously access both employee identity and response content.**

This single constraint drives the entire architecture. The system is split into two cryptographically separated trust zones. The client device is the only place where identity and response coexist — and the client deliberately does not persist the correlation.

---

## 2. Trust Zones

```
IDENTITY ZONE                        SIGNAL ZONE
Knows WHO people are.                Knows WHAT was answered.
Never sees responses.                Never knows WHO answered.

+---------------------+              +---------------------+
| Identity Gateway    |              | Response Collector  |
| (SSO/IdP, sessions) |              | (validates tokens,  |
+---------------------+              |  stores responses)  |
| Sampling Engine     |              +---------------------+
| (who gets what Q)   |              | Response Store      |
+---------------------+              | (encrypted, no PII) |
| Token Issuer        |              +---------------------+
| (blind signatures)  |              | Analytics Engine    |
+----------+----------+              | (aggregation, k-anon|
           |                         |  trends, anomalies) |
           | blinded tokens          +----------+----------+
           v                                    ^
    +------+------+                             |
    |   CLIENT    +-----> [Anonymizing Relay] --+
    | (unblinds   |       (strips IP, timing,
    |  token,     |        shuffles batches)
    |  submits)   |
    +-------------+
```

**The Token Issuer and Response Collector NEVER communicate directly.** The only shared artifact is the Token Issuer's public verification key.

### 2.1 Identity Zone

Components that know who employees are. These services handle authentication, workforce management, and sampling decisions. They never see response content.

### 2.2 Signal Zone

Components that handle response data. These services validate tokens, store encrypted responses, and produce analytics. They never know who submitted a response.

### 2.3 Management Zone

Components that manage questions, campaigns, org structure, and access control policies. These do not handle identity or response data directly.

### 2.4 Tenant Envelope

The Tenant Key Gateway wraps all zones, providing cryptographic isolation between tenants via customer-managed keys.

### 2.5 Trust Boundary Summary

| Boundary | Between | What Crosses | What NEVER Crosses |
|----------|---------|-------------|-------------------|
| Identity → Client | Identity services → Client | Auth sessions, blinded token signatures, question content | Unblinded tokens never flow back to Identity |
| Client → Relay → Signal | Client → Signal services | Unblinded tokens, response blobs (via anonymizing relay) | Employee identity, auth sessions, device fingerprints, IP addresses |
| Identity ↔ Signal (PROHIBITED) | Token Issuer ↔ Response Collector | Token Issuer's public key (published, read-only) | Everything else. No direct communication channel. |
| Mgmt → Identity | Management → Identity | Workforce roster requests, campaign audience definitions | Raw response data |
| Mgmt → Signal | Management → Signal | Question definitions (for interpreting responses), k-anon thresholds | Employee identity |
| Envelope → All | Tenant Key Gateway → Everything | Wrapped/unwrapped DEKs on demand | CMKs never stored by Pulse |

---

## 3. Component Inventory

| Component | Zone | Knows Identity? | Sees Responses? | Purpose |
|-----------|------|----------------|-----------------|---------|
| Identity Gateway | Identity | Yes | No | Authenticate employees via external IdP, manage sessions, maintain user directory |
| Sampling Engine | Identity | Yes | No | Decide who gets which question, when. Enforce frequency caps, balance across segments, maintain statistical significance |
| Token Issuer | Identity | Who requested (yes) | No | Issue blind-signed tokens proving "a valid employee is authorized to answer this question" |
| Anonymizing Relay | Between | No (strips it) | No (encrypted blobs) | Strip network-level identity (IP, timing, headers) from anonymous submissions |
| Response Collector | Signal | No | Encrypted blobs | Accept and validate anonymous responses, manage spent-token ledger |
| Response Store | Signal | No | Encrypted at rest | Persist anonymous response data under tenant DEKs |
| Analytics Engine | Signal | No | Decrypted for aggregation | Produce insights, enforce k-anonymity, detect trends and anomalies |
| Question Registry | Mgmt | No | No | Manage curated and custom question libraries, versioning, categorization |
| Campaign Manager | Mgmt | Audience definitions only | No | Campaign lifecycle, scheduling, audience targeting |
| Org Structure Service | Mgmt | Structural metadata | No | Model org hierarchy, metadata tags, k-anonymity thresholds |
| Policy Engine | Mgmt | Role assignments | No | RBAC/ABAC for administrative actions |
| Tenant Key Gateway | Envelope | No | No | CMK integration, DEK wrapping/unwrapping, crypto-shredding lifecycle |

---

## 4. Anonymity Mechanism

The anonymity system serves two goals in tension:

1. **Per-response unlinkability** — responses cannot be traced to real identities
2. **Longitudinal pseudonymous tracking** — the same anonymous individual's sentiment can be tracked over time

This is achieved with a **two-layer credential scheme**. See [Anonymity Protocol](anonymity-protocol.md) for the full specification.

### 4.1 Layer 1 — Blind Signatures

Blind signatures let the Token Issuer sign a token without seeing its actual value:

1. Employee authenticates normally (SSO)
2. Client generates a random token nonce and **blinds** it
3. Client presents the blinded token to the Token Issuer
4. Token Issuer verifies authorization and frequency caps, signs the blinded value, returns it
5. Token Issuer records "Employee X got a token for batch Y" (frequency bookkeeping) — but never sees the actual token value
6. Client **unblinds** the signed token locally
7. Client submits `{unblinded_token, signature, response_blob}` to the Response Collector via the Anonymizing Relay — with no auth session, no cookies, no identity
8. Response Collector verifies the signature, checks the spent-token ledger, accepts or rejects

**Key property:** Even if the Token Issuer and Response Collector are both compromised and collude, they cannot correlate tokens to identities.

**Token scoping:** Each token is scoped to `{question_batch_id, tenant_id, expiry}`.

### 4.2 Layer 2 — Stable Anonymous Pseudonyms

To enable longitudinal tracking without breaking anonymity:

- The client derives a **stable pseudonym** — a deterministic, one-way function of the employee's identity and a tenant-specific secret. Computed locally, never sent to Identity.
- The pseudonym is included in the response blob (encrypted, readable only by the Analytics Engine after DEK decryption).
- The Analytics Engine groups responses by pseudonym to detect individual sentiment trajectories — without knowing which employee a pseudonym represents.
- **Epoch rotation:** Pseudonyms rotate on a configurable epoch (e.g., quarterly) to limit the correlation window and reduce behavioral fingerprinting risk.

**Privacy properties:**
- Identity never sees the pseudonym
- Signal sees the pseudonym but cannot reverse it to an identity
- Even if both zones are compromised, the pseudonym cannot be linked to an employee without the client's derivation secret
- Epoch rotation bounds the longitudinal window

---

## 5. Device Attestation Spectrum

Devices exist on a spectrum of identity confidence. The architecture models what a signal from each device class *means*. See [Device Attestation](device-attestation.md) for details.

| Device Class | Identity Confidence | Attestation Model | Example |
|---|---|---|---|
| Personal, authenticated | High | Full blind signature flow (SSO + token issuance) | Phone, laptop |
| Shared, group-scoped | Medium | Device registered to a team/project. Token issued to group identity. | Team room tablet |
| Shared, location-scoped | Low | Device registered to a location. Responses attributed to location segment. | Cafeteria kiosk, breakroom button |
| Hybrid (phone handoff) | High | Device presents pairing code/QR. Employee's phone handles auth + token flow. | Wall display + phone scan |

**Key principle:** The system never inflates confidence. A cafeteria button signal is valuable location-level context but is never treated as equivalent to a verified individual response for statistical significance.

---

## 6. Anonymizing Relay

All anonymous submissions (Phase 2 of the protocol) are routed through a mandatory anonymizing relay:

- Terminates the client's TLS connection
- Strips source IP, request timing metadata, and client fingerprinting headers
- Opens a new connection to the Response Collector with a shared/rotated source address
- Batches and shuffles responses with configurable delay windows to defeat timing correlation
- Does NOT inspect or log payload content — transport-level anonymizer only
- Designed to resist insider threats: operators with relay access see only encrypted blobs with no correlation to identities

**Why mandatory:** Network metadata (IP, TLS fingerprint, timing) is an unintentional identity leak. The relay closes this gap architecturally rather than relying on policy.

---

## 7. Multi-Tenancy and Customer-Managed Keys

See [Key Management](key-management.md) for the full specification.

### Summary

**Two-tier envelope encryption:**

- **Tier 1: CMK** — Held exclusively by the tenant. Never stored by Pulse. Used only to wrap/unwrap Tier 2 keys.
- **Tier 2: DEKs** — Generated by Pulse, per data domain per tenant. Stored in wrapped form only.

**Operator zero-knowledge:** The operator sees only encrypted ciphertext. Cannot access tenant data under any circumstance — by design, not policy.

**Crypto-shredding:** Tenant deletes their CMK → all wrapped DEKs become permanently un-unwrappable → all data is cryptographic garbage.

**Per-tenant blind signature keys:** Each tenant has its own signing key pair (encrypted under the tenant's DEK). Tokens from Tenant A cannot work against Tenant B.

**Key loss = data loss.** Irrecoverable by design. This is the price of true zero-knowledge.

---

## 8. Client Protocol

### 8.1 Two-Phase Interaction

The protocol has two strictly separated phases over separate connections and network paths:

**Phase 1 — Identity-Aware (Identity)**
- Client authenticates via SSO
- Receives question deliveries (push or pull)
- Requests and receives blinded token signatures

**Phase 2 — Anonymous (via Relay → Signal)**
- Client submits responses with unblinded tokens
- No authentication, no cookies, no identity information
- Routed through the anonymizing relay

### 8.2 Delivery Models

| Model | Mechanism | Use Case |
|-------|-----------|----------|
| Push | Persistent connection to Identity Gateway | Always-connected desktop/mobile clients |
| Pull | Periodic poll for pending questions | Firewalled environments, constrained devices |
| Hybrid | Push with pull fallback | Clients that may lose persistent connections |

### 8.3 Store-and-Forward

For intermittently connected clients:

1. Client receives question and token while online
2. Client unblinds token, stores in local encrypted queue
3. Employee responds while offline
4. Client constructs response message, enqueues it
5. On reconnect, client drains queue, submitting each response
6. Spent-token ledger makes retries idempotent (duplicate submissions are safely rejected)

### 8.4 Control Plane and Capability Negotiation

The protocol separates two communication planes:

**Data plane** — the existing two-phase protocol (token issuance and anonymous response submission). Carries application data. Serialized with [postcard](https://docs.rs/postcard) binary format.

**Control plane** — an authenticated management channel in the Identity zone for client lifecycle operations. The control plane knows WHO the client is and can deliver platform-specific instructions.

**Version negotiation.** On authentication, clients declare their protocol version. The server checks against a minimum supported version and rejects outdated clients with an update hint. This gates token issuance — if a client passes the version check, any token it holds is from a compatible version. The Signal zone never needs version negotiation; a valid token means the client already passed the gate.

**Platform-aware update signaling.** Clients report platform metadata (OS, device class) during authentication. When the server rejects a client for version mismatch, the update hint is platform-specific: a UEM push command for managed desktops, an app store deeplink for mobile, or a firmware OTA URL for embedded devices.

**Capability advertisement.** Beyond versioning, clients declare: push/pull preference, supported response types, max payload size, store-and-forward support, and attestation class. The server tailors question delivery accordingly — it will not send a free-text question to a 5-button IoT device.

**Extensibility.** The control plane uses typed messages with a discriminant, so future capabilities (configuration delivery, fleet health reporting, poll scheduling) can be added without protocol changes. Version negotiation is the first capability; the envelope is designed for growth.

**Trust zone mapping.** The control plane lives entirely in the Identity zone — it requires authentication and is identity-aware. The data plane spans both zones (Phase 1 in Identity, Phase 2 in Signal via the relay). The relay remains fully opaque and has no control plane awareness.

### 8.5 Protocol Characteristics

- **Postcard binary format** — protocol messages are serialized with [postcard](https://docs.rs/postcard), a compact `no_std`-compatible binary format via serde. JSON is retained for auth, debug, analytics, and error responses.
- **Self-describing version envelope** — every postcard message carries a version byte prefix (`[major | minor | payload]`) so receivers can dispatch to the correct deserializer without out-of-band context.
- **Opaque payloads** — the protocol transports bytes; interpretation lives at the edges
- **Response-type-agnostic** — adding a new response type requires no protocol changes
- **IoT-ready** — the compact binary format and `no_std` compatibility make it suitable for constrained devices

---

## 9. Sampling and the Identity/Anonymity Tension

The Sampling Engine (Identity) knows **who** is assigned to each question. The Response Collector (Signal) knows **what** was answered. Neither knows both. The client bridges the gap.

### 9.1 How the Client Bridges Trust Zones

```
Identity                         Client                        Signal
(identity-aware)               (trust bridge)                (anonymous)

Sampling Engine:          -->  Client receives question
"Employee X gets Q42"          and initiates token flow

Token Issuer verifies     -->  Client blinds token,
Employee X, signs              unblinds signature
blinded token
                               Employee answers

                               Client submits response  -->  Anonymizing Relay
                               with unblinded token     -->  Response Collector
                               (NO identity info)            verifies, stores
```

### 9.2 Consequence: No Individual Response Tracking

The system **cannot track per-individual response status.** It cannot send "you haven't answered yet" reminders — only broadcast reminders to all assigned employees. This is an intentional privacy trade-off.

**Compensating strategies:**
- Over-sampling: issue more tokens than needed, anticipating non-response
- Adaptive top-up: if aggregate response rates are low, issue additional tokens to new employees in subsequent waves
- Confidence reporting: analytics prominently display confidence intervals and margins of error

### 9.3 Sampling Engine Inputs

- Workforce roster (from Identity Gateway)
- Org structure and metadata tags (from Org Structure Service)
- Active questions and campaigns (from Question Registry / Campaign Manager)
- Historical issuance records: "Employee X was last issued a token on date D" (from Token Issuer logs)
- Aggregate response counts per batch (from Analytics Engine — counts only, no identity linkage)

---

## 10. K-Anonymity

Segment identifiers are embedded in the token scope at **issuance time**, not derived from identity at response time. For groups below the k-anonymity threshold, the Sampling Engine **coarsens the segment label** before embedding it.

**Example:** If Team Alpha has 3 people and k=5, the Sampling Engine encodes the segment as "Engineering > Backend" (the parent), not "Team Alpha". The Response Collector never receives sub-threshold segment labels.

This enforces k-anonymity **architecturally** — at the data level, not the UI level. The Analytics Engine cannot accidentally expose small-group data because it never receives it.

---

## 11. Key Data Flows

### 11.1 Continuous Monitoring: Question → Response → Insight

1. **Question creation:** Org admin creates/selects questions in the Question Registry
2. **Sampling:** Sampling Engine reads roster, org structure, active questions. Produces assignment list `[(employee_id, question_batch_id)]` with frequency caps, segment balancing, significance targets
3. **Delivery + token issuance:** Client receives question (push/pull), authenticates, blinds a nonce, gets it signed by the Token Issuer, unblinds locally
4. **Response submission:** Client submits `{unblinded_token, signature, response_blob}` via the anonymizing relay to the Response Collector. No identity info.
5. **Validation + storage:** Response Collector verifies signature, checks spent-token ledger, encrypts response with tenant DEK, stores
6. **Analytics:** Analytics Engine decrypts responses, interprets by response type, aggregates, enforces k-anonymity, detects trends/anomalies, publishes to dashboards

### 11.2 Campaign Lifecycle

Same as continuous monitoring, with additions:
- Campaign Manager defines audience, questions, dates, targets
- Sampling Engine coordinates with continuous monitoring to avoid over-polling
- Analytics reports campaign results separately and compares against the continuous baseline

### 11.3 Offline / Store-and-Forward

1. Client receives question + token while online
2. Employee responds while offline; response queued locally (encrypted)
3. On reconnect, client drains queue via the anonymizing relay
4. Spent-token ledger ensures idempotent retries

---

## 12. Architectural Invariants

These properties must hold regardless of implementation choices:

1. **No component simultaneously accesses identity AND response content**
2. **Token Issuer and Response Collector never communicate directly**
3. **All tenant data at rest is encrypted under keys the operator does not possess**
4. **K-anonymity is enforced at the data level, not the UI level**
5. **The protocol is payload-agnostic** — new response types require no protocol changes
6. **Token validity is finite and scoped** — no indefinite or universal tokens
7. **Every response is verified (valid signature) and unique (spent-token check)**
8. **Network-level identity is stripped by the anonymizing relay before reaching Signal**
9. **The system never inflates device attestation confidence**

---

## 13. Decisions Made

| Question | Decision | Rationale |
|----------|----------|-----------|
| Longitudinal tracking | Stable anonymous pseudonyms with epoch rotation | Key differentiator. Pseudonyms derived client-side, never seen by Identity. |
| IoT identity model | Device attestation spectrum with confidence levels | Devices range from personal (high) to location (low). System models what each signal means. |
| Network anonymity | Mandatory anonymizing relay | Signals must be completely anonymous. Insider threat resistance required. |
| Blind signature scheme | RSA Blind Signatures per RFC 9474 | Well-studied, information-theoretic blindness, standardized. Partially blind sigs remain a future option for constrained devices. |
| Pseudonym derivation | HMAC-SHA256 | Simple, deterministic, one-way. Anonymous credentials (DAA/Idemix) noted as future evolution. |
| Pseudonym epoch duration | 90 days (configurable per tenant) | Balances longitudinal analysis against re-identification risk from behavioral fingerprinting. |
| Wire format | Postcard binary with version byte prefix | Compact, `no_std`-friendly, serde-native. Version prefix enables protocol evolution. JSON retained for auth, debug, analytics, errors. |
| Relay architecture | Single relay with batching and shuffling | Relay network remains a future option. Current design is sufficient for production launch. |
| Client lifecycle management | Control plane in Identity zone | Authenticated management channel for version negotiation and update signaling. Extensible for config delivery, fleet health. |
| Client architecture | Core library + platform shells | Platform-agnostic `pulse-client` crate with thin shells (WASM, desktop, mobile, embedded). Shell priority adapts to market signals. See [Client Architecture](../development/client-architecture.md). |
| Project phasing | Four outcome-oriented milestones (M0–M3) | M0 = protocol proof. M1 = first pilot. M2 = general availability. M3 = full suite. See [Roadmap](../roadmap.md). |

---

## 14. Open Design Areas

| Area | Status | Notes |
|------|--------|-------|
| Token batch pre-issuance | Open | Batch size for offline devices. Revocation on employee departure. |
| Anonymous channel abuse mitigation | Open | DoS on the relay/collector. Proof-of-work? Rate limiting? |
| Response type catalog | Partially resolved | Protocol transports opaque bytes via postcard. `ResponseType` enum exists (`Scale5`, `Binary`, `Emoji`, `FreeText`). Full catalog of validated response types TBD. |
| Key re-encryption on rotation | Partially resolved | `KeyVersion` tracking and per-tenant keys exist. Re-encryption of stored data under new keys TBD. |
| Attestation confidence weighting | Open | How low-confidence location signals factor into aggregate statistics. |
| Control plane message catalog | Open | Version negotiation is first capability. Config delivery, fleet health, poll scheduling are future extensions. |
| Relay network topology | Open | Current: single relay. Multi-relay network for high availability and geographic distribution is a future option. |
