# Pulse — Anonymity Protocol

*Deep dive into the cryptographic mechanisms that guarantee verified-anonymous response collection.*

*Parent document: [Architecture](architecture.md)*

---

## 1. Goals

The anonymity protocol must satisfy all of the following simultaneously:

| Goal | Description |
|------|-------------|
| **Verified origin** | Every response provably originates from a valid, authorized employee (or device) |
| **Unlinkability** | No party — including the platform operator — can link a response to the individual who submitted it |
| **Replay prevention** | A captured response cannot be resubmitted |
| **Forgery prevention** | An attacker cannot fabricate valid responses without the Token Issuer's signing key |
| **Duplicate prevention** | An employee cannot submit multiple responses for the same question batch |
| **Longitudinal pseudonymity** | The same anonymous individual's responses can be correlated over time without revealing identity |
| **Auditability** | The system can prove response legitimacy (valid signatures, consistent counts) without revealing identity |

---

## 2. Layer 1 — Blind Signatures

### 2.1 Concept

A blind signature scheme allows a signer to produce a valid signature on a message **without ever seeing the message content.** The signature can later be verified by anyone using the signer's public key.

In Pulse, the Token Issuer signs tokens without seeing their actual values. The client unblinds the signature locally. The Response Collector verifies the signature. The Token Issuer cannot correlate what it signed to what the Response Collector accepted — even if both are compromised simultaneously.

### 2.2 Protocol Flow

```
  Employee/Client                Token Issuer               Response Collector
  ───────────────                ────────────               ──────────────────

  1. Authenticate (SSO)
     ─────────────────────>
                                 2. Verify identity
                                    Check frequency cap
                                    Check question assignment

  3. Generate random nonce (n)
     Construct token payload:
       T = {n, question_batch_id,
            tenant_id, expiry,
            segment_vector,
            attestation_class,
            key_version}

  4. Blind the token:
       T_blind = Blind(T, r)
     where r is a random
     blinding factor

  5. Send T_blind
     ─────────────────────>
                                 6. Sign the blinded token:
                                      S_blind = Sign(T_blind, sk)

                                 7. Record issuance:
                                      "Employee X received a
                                       token for batch Y"
                                    (frequency bookkeeping)

                                 8. Return S_blind
     <─────────────────────

  9. Unblind the signature:
       S = Unblind(S_blind, r)

     Now holds (T, S) — a valid
     token with a valid signature
     that the Token Issuer
     produced but has never seen.

     --- Time passes. Random delay. ---

  10. Submit via Anonymizing Relay:
        {T, S, response_blob}
      No auth session, no cookies,
      no identity.
                                                            11. Verify signature:
      ──────────────────────────────────────────────>           Verify(T, S, pk)
                                                            12. Check token fields:
                                                                - question_batch_id valid?
                                                                - tenant_id matches?
                                                                - Not expired?
                                                            13. Check spent-token ledger:
                                                                - Hash(T) already spent?
                                                                - If yes: REJECT (duplicate)
                                                                - If no: record Hash(T), ACCEPT
                                                            14. Encrypt and store response.
                                                                No identity info retained.
```

### 2.3 Unlinkability Argument

The security of blind signatures rests on the mathematical properties of the blinding operation:

- The Token Issuer sees `T_blind = Blind(T, r)` but not `T` or `r`
- The Response Collector sees `T` and `S` but not `T_blind` or which employee submitted it
- Even with access to both `T_blind` (from Token Issuer logs) and `T` (from Response Collector records), correlating them requires knowing the blinding factor `r`, which exists only in the client's memory during the protocol and is discarded after unblinding
- This property holds **information-theoretically** for certain schemes (e.g., Chaum's RSA blind signatures) — it is not merely computationally hard; it is mathematically impossible without `r`

### 2.4 Token Structure

The token payload `T` is defined in `pulse-protocol`:

```rust
{{#include ../../crates/pulse-protocol/src/token.rs:token_payload}}
```

### 2.5 Spent-Token Ledger

The Response Collector maintains a ledger of spent token hashes:

- On acceptance, `Hash(T)` is added to the ledger
- On submission, the ledger is checked before acceptance
- The ledger stores only hashes — the full token `T` is not retained after validation
- Ledger entries can be pruned after the token's expiry timestamp (expired tokens would fail the expiry check regardless)
- The ledger must be strongly consistent — concurrent submissions of the same token must not both succeed

### 2.6 Scheme Selection (Open)

Several blind signature schemes exist. The choice has significant implications:

| Scheme | Pros | Cons | Notes |
|--------|------|------|-------|
| **RSA Blind Signatures (Chaum)** | Well-studied, simple, information-theoretic blindness | Large key sizes (2048+ bits), large signatures. Heavier computation. | RFC 9474 standardizes RSA blind signatures. Mature. |
| **EC-based Blind Signatures** | Smaller keys and signatures. Faster on constrained devices. | Less mature standardization. Scheme-specific security proofs. | Good fit for IoT/wearable clients. |
| **Partially Blind Signatures** | Signer sees some metadata (e.g., batch ID) while nonce remains hidden. Enables scoping without separate metadata. | More complex protocols. Fewer standard implementations. | Ideal for token scoping — the Token Issuer can verify batch_id without seeing the nonce. |

**Recommendation direction:** Partially blind signatures are the most natural fit for Pulse (scope metadata is visible to the signer, identity-bearing nonce is hidden). EC-based schemes are preferred for constrained device support. The specific scheme requires a dedicated cryptographic design review.

---

## 3. Layer 2 — Stable Anonymous Pseudonyms

### 3.1 Purpose

Layer 1 provides per-response anonymity: each token is independent and unlinkable. But Pulse also needs to track **individual sentiment trajectories over time** — "this anonymous person's mood has shifted over the past quarter."

Layer 2 adds a **stable pseudonym** that links responses from the same individual across time, without revealing who that individual is.

### 3.2 Derivation

The pseudonym is derived **entirely on the client**:

```
pseudonym = PRF(employee_secret, tenant_id || epoch_id)
```

Where:
- `PRF` is a pseudorandom function (e.g., HMAC-SHA256)
- `employee_secret` is a stable secret derived from the employee's identity credentials, stored locally on the client
- `tenant_id` prevents cross-tenant pseudonym correlation
- `epoch_id` is a time-based epoch identifier (e.g., "2026-Q1") that rotates the pseudonym periodically

**Properties:**
- Deterministic: same employee + same tenant + same epoch = same pseudonym
- One-way: pseudonym cannot be reversed to employee identity without `employee_secret`
- Epoch-scoped: pseudonym changes each epoch, bounding the longitudinal window
- Tenant-scoped: same employee in different tenants (if somehow possible) gets different pseudonyms

### 3.3 Inclusion in Response

The pseudonym is embedded **inside** the encrypted response blob:

```
response_blob = Encrypt(DEK, {
    response_type,
    response_data,
    pseudonym,
    epoch_id
})
```

This means:
- The Response Collector sees only the encrypted blob — it cannot read the pseudonym
- The Analytics Engine decrypts the blob using the tenant's DEK and can group by pseudonym
- Identity services never see the pseudonym at all (it is computed client-side and submitted via the anonymous channel)

### 3.4 Epoch Rotation

Pseudonyms rotate on a configurable epoch to limit re-identification risk from behavioral patterns:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `epoch_duration` | How long a pseudonym is stable | 90 days (quarterly) |
| `epoch_id_format` | How the epoch is identified | "2026-Q1", "2026-Q2", ... |

**Cross-epoch analysis:** When a pseudonym rotates, the Analytics Engine can no longer link responses across epochs for a given individual. Aggregate trends still work (they don't depend on individual linkage). Individual trajectories are visible within an epoch but not across epochs.

**Trade-off:** Shorter epochs = stronger privacy, weaker longitudinal analysis. Longer epochs = richer trajectories, higher re-identification risk from behavioral fingerprinting. The epoch duration should be configurable per tenant based on their privacy posture.

### 3.5 Employee Secret Lifecycle

The `employee_secret` is the linchpin of pseudonym derivation:

- **Generation:** Derived during client enrollment/onboarding. Could be derived from the employee's SSO credentials via a KDF, or generated randomly and stored in the client's secure storage.
- **Storage:** Exists only on the client device(s). Never transmitted to any server.
- **Multi-device:** If an employee uses multiple devices, the secret must be synchronized across them (or pseudonyms will differ per device). Options: derive from SSO credential material (deterministic), or use a secure sync mechanism.
- **Device loss:** If the secret is lost and cannot be recovered, the employee gets a new pseudonym. This appears as a "new anonymous individual" to the Analytics Engine — a clean break, not an identity leak.
- **Employee departure:** The secret is destroyed with the client state. The pseudonym becomes an orphan in the Analytics Engine — unlinked from any active identity.

### 3.6 Advanced: Anonymous Credentials with Native Pseudonym Support (Future)

The HMAC-based pseudonym derivation described above is simple and effective but relies on the client to honestly include the pseudonym. A more sophisticated approach uses **anonymous credential schemes** (e.g., DAA — Direct Anonymous Attestation, or Idemix) that embed pseudonym derivation into the cryptographic protocol itself:

- The credential scheme generates pseudonyms as a mathematical byproduct of the anonymous authentication
- The pseudonym is verifiably derived from the credential — a client cannot forge a different pseudonym
- Cross-epoch unlinkability is a built-in property, not a client-enforced behavior

This is significantly more complex to implement and is noted as a potential future evolution, not a launch requirement.

---

## 4. Segment Vector Embedding

### 4.1 Problem

Analytics needs to aggregate responses by org segment (team, location, etc.). But including segment identifiers in responses creates a correlation vector — especially for small segments.

### 4.2 Solution: Issuance-Time Coarsening

The Sampling Engine (Identity) determines the appropriate segment granularity **at token issuance time**:

1. For each employee assignment, the Sampling Engine checks: does this employee's most specific segment have >= k members? (Where k is the k-anonymity threshold.)
2. If yes: embed the specific segment identifier in the token payload.
3. If no: walk up the hierarchy until a segment with >= k members is found. Embed that instead.
4. The segment identifiers are abstract IDs (hashes or opaque codes), not human-readable names.

The segment vector is part of the token payload `T` and ends up in the stored response. The Analytics Engine receives abstract segment IDs and maps them to human-readable names using the Org Structure Service (Management Zone) at dashboard rendering time.

### 4.3 Privacy Property

The Response Collector and Analytics Engine never receive segment labels that could identify groups smaller than k. This is enforced **at the data level** — it is not a UI filter that could be bypassed.

---

## 5. Audit and Reconciliation

The system provides an audit trail without compromising anonymity:

| Source | What It Records |
|--------|----------------|
| Token Issuer logs | "N tokens issued for batch Y. Specific employees: [X1, X2, ...]" (Identity, identity-aware) |
| Response Collector logs | "M responses received for batch Y with valid signatures" (Signal, anonymous) |
| Reconciliation | If M <= N, the system is consistent. If M > N, something is wrong (forged tokens, ledger failure). |

**What reconciliation cannot reveal:** Which specific employees responded and which didn't. Only aggregate counts can be compared. This is by design.

---

## 6. Timing and Decorrelation

Even with cryptographic unlinkability, **timing** is a correlation vector: if an employee obtains a token at 10:03 and a response appears at 10:04, an observer with access to both zones' logs could correlate by timestamp.

**Mitigations:**

1. **Client-side random delay:** Clients introduce a random delay between token acquisition and response submission. The delay is drawn from a configurable distribution (e.g., uniform between 5 minutes and 2 hours).
2. **Anonymizing relay batching:** The relay accumulates responses and forwards them in shuffled batches at regular intervals, decoupling submission timing from arrival timing at the Response Collector.
3. **Store-and-forward as a natural decorrelator:** Offline clients inherently introduce large, variable delays.
4. **Phase separation:** Token acquisition (Phase 1) and response submission (Phase 2) use different network connections and different server endpoints. An observer would need access to both network paths simultaneously.

---

## 7. Protocol Message Summary

### Phase 1 — Identity-Aware Channel (Client ↔ Identity)

| Direction | Message | Payload |
|-----------|---------|---------|
| Client → Server | `AUTH_HELLO` | IdP assertion (SSO token) |
| Server → Client | `AUTH_OK` | Session established |
| Server → Client | `QUESTION_DELIVERY` | question_batch_id, question content, response type, expiry, metadata |
| Client → Server | `TOKEN_REQUEST` | blinded_token, question_batch_id |
| Server → Client | `TOKEN_RESPONSE` | signed_blinded_token, key_version |
| Server → Client | `TOKEN_DENIED` | reason (frequency cap, not authorized, etc.) |

### Phase 2 — Anonymous Channel (Client → Relay → Signal)

| Direction | Message | Payload |
|-----------|---------|---------|
| Client → Relay | `RESPONSE_SUBMIT` | unblinded_token, signature, key_version, question_batch_id, tenant_id, response_blob |
| Relay → Collector | (same, stripped) | Same payload, source identity removed |
| Collector → Relay → Client | `RESPONSE_ACK` | Accepted |
| Collector → Relay → Client | `RESPONSE_REJECT` | reason (invalid_sig, expired, already_spent, malformed) |

---

## 8. Security Summary

| Threat | Mitigation |
|--------|-----------|
| Compromised Token Issuer | Sees who requested tokens but cannot link to responses (never sees unblinded values). Damage limited to frequency cap data exposure. |
| Compromised Response Collector | Sees all responses but has no identity info. Responses encrypted per tenant CMK. |
| Both compromised + colluding | Still cannot correlate — mathematical property of blind signatures. |
| Rogue employee mass-generating tokens | Frequency caps + token scoping + one-token-per-assignment. |
| Network traffic analysis (timing) | Random client delays + relay batching/shuffling + separate network paths. |
| Client device compromise | The client is the one place where identity and token coexist. Inherent to any anonymous credential system. Device-level security is the employee's responsibility. |
| Behavioral fingerprinting via pseudonym | Epoch rotation bounds the correlation window. |
| Relay operator snooping | Relay sees only encrypted blobs. Cannot read content or correlate to identities. |
