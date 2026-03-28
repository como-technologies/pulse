# Pulse — Threat Model

*Systematic analysis of attack surfaces, threats, and mitigations across all trust boundaries.*

*Parent document: [Architecture](README.md)*

---

## 1. Scope

This threat model covers the Pulse platform's core security properties:

1. **Anonymity** — Can an attacker link a response to an individual?
2. **Integrity** — Can an attacker forge, replay, or tamper with responses?
3. **Confidentiality** — Can an attacker read response content or org data?
4. **Availability** — Can an attacker disrupt the system?

Each threat is assessed against a set of attacker profiles with varying capabilities.

---

## 2. Attacker Profiles

| Profile | Description | Capabilities |
|---------|-------------|-------------|
| **External attacker** | No legitimate access to the system | Network interception, public endpoint probing, social engineering |
| **Malicious employee** | Authenticated user of the system | Valid SSO credentials, ability to obtain tokens, knowledge of org structure |
| **Compromised Identity** | Attacker has full access to Identity zone services | Token Issuer logs, Sampling Engine data, employee roster, issuance records |
| **Compromised Signal** | Attacker has full access to Signal zone services | Response Collector data, spent-token ledger, encrypted response store, analytics results |
| **Compromised Relay** | Attacker controls the anonymizing relay | Network traffic through the relay (encrypted payloads, source IPs, timing) |
| **Compromised Identity+Signal** | Attacker has access to both trust zones | Everything from both zones simultaneously |
| **Platform operator (insider)** | Legitimate system administrator | Infrastructure access, deployment access, log access. Does NOT have tenant CMKs. |
| **Compromised tenant admin** | Org admin with malicious intent | Campaign creation, question management, org structure changes, analytics access |

---

## 3. Threat Analysis

### 3.1 Anonymity Threats

#### T1: Deanonymization via Token Issuer + Response Collector Correlation

| | |
|---|---|
| **Attacker** | Compromised Identity+Signal |
| **Attack** | Correlate Token Issuer logs (employee → blinded token) with Response Collector records (unblinded token → response) to link identities to responses |
| **Mitigation** | Blind signatures make this mathematically impossible. The blinding factor `r` exists only in the client's memory and is discarded after unblinding. Without `r`, the correlation cannot be computed. This property holds even against an adversary with unlimited computational power (information-theoretic security for RSA blind signatures). |
| **Residual risk** | None (assuming correct implementation of the blind signature scheme) |

#### T2: Timing Correlation

| | |
|---|---|
| **Attacker** | Compromised Identity+Signal, or compromised relay + Identity |
| **Attack** | Correlate the timestamp of token issuance (Identity logs) with the timestamp of response submission (Signal or relay logs) to link identity to response |
| **Mitigation** | (1) Client-side random delay between token acquisition and submission. (2) Anonymizing relay batches and shuffles responses before forwarding. (3) Store-and-forward clients introduce natural variable delays. (4) Token acquisition and response submission use separate network connections and endpoints. |
| **Residual risk** | Low. An attacker with access to both zone logs and precise timing could attempt statistical correlation if many users are active simultaneously. Batching/shuffling at the relay significantly reduces this. Risk increases for very small orgs with few active users at any given time. |

#### T3: Network Traffic Analysis (IP Correlation)

| | |
|---|---|
| **Attacker** | Compromised relay, or network-level observer |
| **Attack** | Correlate source IP of Phase 1 (token acquisition) with source IP of Phase 2 (response submission) |
| **Mitigation** | (1) The anonymizing relay strips source IP before forwarding to the Response Collector. (2) Phase 1 and Phase 2 use separate endpoints and connections. (3) The relay does not log source IPs. (4) In typical enterprise deployments, corporate NAT, VPN concentrators, and mobile CGNAT mean the relay sees a shared gateway IP, not individual employee IPs — see T17 for detailed analysis. |
| **Residual risk** | Low in theory, but **near-zero in practice** for most enterprise deployments. Corporate NAT/VPN means the relay sees the company's exit IP, not individual employees. The edge case is a remote worker on a residential connection outside VPN — even then, correlating IP to identity requires compromising both the relay and the Identity zone. |

#### T4: Behavioral Fingerprinting via Pseudonym

| | |
|---|---|
| **Attacker** | Compromised Signal or compromised tenant admin |
| **Attack** | Use patterns in an anonymous pseudonym's responses over time (response timing, sentiment patterns, writing style in free-text) to infer identity |
| **Mitigation** | (1) Pseudonym epoch rotation limits the correlation window. (2) K-anonymity enforcement prevents small-group isolation. (3) Free-text responses carry inherent fingerprinting risk — tenants should be advised of this when enabling free-text response types. |
| **Residual risk** | Medium for free-text responses. Low for structured response types (scale, emoji). Epoch rotation is the primary control. |

#### T5: Small Group Deanonymization

| | |
|---|---|
| **Attacker** | Compromised tenant admin or analytics viewer |
| **Attack** | View results for a very small team/segment and infer who said what (e.g., a 3-person team where 2 responses are positive and 1 is negative) |
| **Mitigation** | (1) K-anonymity: segment labels are coarsened at issuance time for groups below the k threshold. The Analytics Engine never receives sub-threshold segment labels. (2) This is enforced at the data level, not the UI level — there is no bypass. |
| **Residual risk** | None for groups below k (data never exists in disaggregated form). For groups at exactly k, an attacker with knowledge of who is in the group and who likely responded could still make probabilistic inferences. Higher k values reduce this risk at the cost of analytics granularity. |

#### T6: Tenant Admin Manipulating Org Structure to Deanonymize

| | |
|---|---|
| **Attacker** | Compromised tenant admin |
| **Attack** | Reorganize the org structure to create a segment containing exactly one person, then view that segment's results |
| **Mitigation** | (1) K-anonymity thresholds are enforced at issuance time based on the segment membership count at that moment. (2) Segment coarsening uses the live org structure when tokens are issued. (3) Audit logging of org structure changes, especially near campaign/polling periods. (4) Policy controls: org structure changes could require multi-party approval or impose a cooling-off period before taking effect for sampling purposes. |
| **Residual risk** | Low with appropriate policy controls. The attack requires advance planning (changing org structure before the next sampling round) and is detectable via audit logs. |

### 3.2 Integrity Threats

#### T7: Token Forgery

| | |
|---|---|
| **Attacker** | External attacker or malicious employee |
| **Attack** | Fabricate a valid token without going through the Token Issuer |
| **Mitigation** | Tokens require a valid blind signature from the Token Issuer's private key. Forging a signature requires the private key, which is encrypted under the tenant's DEK (itself wrapped by the tenant's CMK). |
| **Residual risk** | None (assuming the signing key is not compromised and the blind signature scheme is secure) |

#### T8: Token Replay

| | |
|---|---|
| **Attacker** | Network attacker or malicious employee |
| **Attack** | Capture a valid response submission and replay it |
| **Mitigation** | The spent-token ledger records `Hash(T)` on first acceptance. Replayed submissions are rejected (token already spent). The ledger must be strongly consistent. |
| **Residual risk** | None (assuming correct ledger implementation) |

#### T9: Duplicate Responses (One Employee, Multiple Submissions)

| | |
|---|---|
| **Attacker** | Malicious employee |
| **Attack** | Submit multiple responses for the same question batch |
| **Mitigation** | (1) The Sampling Engine assigns one token per employee per question batch. (2) The Token Issuer enforces: one token issuance per employee per batch. (3) The spent-token ledger ensures each token is used exactly once. (4) An employee would need to compromise the Token Issuer to obtain additional tokens. |
| **Residual risk** | None under normal operation. If the Token Issuer is compromised, an attacker could issue additional tokens — but this would be detectable via reconciliation (more responses than tokens issued). |

#### T10: Response Tampering in Transit

| | |
|---|---|
| **Attacker** | Network attacker or compromised relay |
| **Attack** | Modify a response payload in transit |
| **Mitigation** | (1) The response blob is integrity-protected: the blind signature covers the full token payload, and the response blob could additionally be authenticated (e.g., via AEAD encryption). (2) TLS protects the connection between client and relay, and between relay and Response Collector. (3) The relay does not inspect or modify payloads. |
| **Residual risk** | The relay is a TLS termination point and theoretically could modify payloads. Mitigation: end-to-end integrity protection (the response blob is authenticated under a key the relay does not possess, e.g., the tenant's public key). |

### 3.3 Confidentiality Threats

#### T11: Operator Accessing Tenant Data

| | |
|---|---|
| **Attacker** | Platform operator (insider) |
| **Attack** | Read tenant response content, employee data, or analytics results |
| **Mitigation** | All tenant data is encrypted under tenant-managed keys (CMK → DEK envelope encryption). The operator never possesses tenant CMKs. Data at rest is ciphertext. The operator sees only encrypted blobs and operational metadata (tenant ID, data volume, request rates). |
| **Residual risk** | The operator can see encrypted data volume and access patterns (metadata). In theory, a sophisticated operator could infer some information from traffic patterns (e.g., "this tenant has high response volume on Mondays"). This is inherent to any hosted service and is generally acceptable. |

#### T12: Cross-Tenant Data Leakage

| | |
|---|---|
| **Attacker** | Compromised tenant admin, or external attacker |
| **Attack** | Access another tenant's data |
| **Mitigation** | (1) Cryptographic isolation: each tenant has separate DEKs wrapped by their own CMK. Decrypting Tenant A's data requires Tenant A's CMK. (2) Per-tenant blind signature keys: tokens from Tenant A are invalid for Tenant B. (3) Logical isolation in all services (tenant_id scoping). |
| **Residual risk** | A software bug in tenant_id scoping could theoretically leak data across tenants at the application layer, but the data would still be encrypted under the wrong DEK (unreadable). The cryptographic isolation is the final backstop. |

#### T13: Response Content Exposure via Analytics

| | |
|---|---|
| **Attacker** | Compromised tenant admin or analytics viewer |
| **Attack** | Access individual response content rather than aggregated results |
| **Mitigation** | (1) The Analytics Engine operates on decrypted data to compute aggregates, but exposes only aggregated results through dashboards. (2) Raw response access is restricted by the Policy Engine (configurable, but default roles should not include raw response access). (3) K-anonymity prevents disaggregation below threshold. |
| **Residual risk** | A tenant admin with sufficient permissions could potentially configure a policy that grants raw response access. This is a tenant-level decision — the platform provides the controls but cannot prevent a tenant from weakening their own privacy guarantees. The platform should clearly document the implications. |

### 3.4 Availability Threats

#### T14: DoS on the Anonymous Channel

| | |
|---|---|
| **Attacker** | External attacker |
| **Attack** | Flood the anonymizing relay or Response Collector with invalid submissions, consuming resources |
| **Mitigation** | (1) The relay can apply rate limiting by source IP (imperfect but raises the cost). (2) Submissions with invalid signatures are rejected early (signature verification is the first check). (3) Proof-of-work: require a computational puzzle in the submission to raise the cost of flooding. (4) The relay can absorb bursts via queuing without passing them to the Response Collector. |
| **Residual risk** | Medium. The anonymous channel is inherently unauthenticated (by design). There is a tension between anonymity (no identity required) and abuse resistance (identity helps filter). Proof-of-work is the primary mitigation that doesn't compromise anonymity, but it increases client-side cost for legitimate submissions on constrained devices. |

#### T15: Token Issuance Flood

| | |
|---|---|
| **Attacker** | Malicious employee or compromised account |
| **Attack** | Request a large number of tokens to exhaust system resources |
| **Mitigation** | (1) Frequency caps per employee. (2) Rate limiting on the Token Issuer. (3) Token requests require valid authentication — no anonymous flooding. |
| **Residual risk** | Low. Authenticated endpoints are standard to defend. |

#### T16: Spent-Token Ledger Corruption

| | |
|---|---|
| **Attacker** | Infrastructure-level attacker |
| **Attack** | Delete or corrupt the spent-token ledger, allowing token replay |
| **Mitigation** | (1) The ledger should be stored in a durable, replicated data store with integrity guarantees. (2) Append-only design (entries are added, never deleted except for expired-token pruning). (3) Regular integrity checksums. |
| **Residual risk** | Low with standard infrastructure practices. Ledger corruption would allow replay but not forgery (still requires valid signatures). |

### 3.5 Relay Trust Threats

#### T17: Compromised Relay Operator (Surveillance)

| | |
|---|---|
| **Attacker** | Compromised Relay |
| **Attack** | Log source IPs and submission timestamps to learn which network locations are submitting, and when |
| **What the relay can see** | Source IP address (usually a NAT gateway, not an individual), encrypted payload size, submission timing |
| **What the relay cannot see** | Response content (encrypted), employee identity, which question was answered, segment labels, pseudonym |
| **Mitigation** | (1) **Corporate NAT**: enterprise desktops share a NAT gateway IP — the relay sees the company, not the individual. (2) **VPN**: remote workers route through a VPN concentrator — same exit IP as office workers. (3) **Mobile CGNAT**: carrier-grade NAT shares IPs across thousands of subscribers with frequent rotation. (4) **Batch-and-shuffle**: the relay's own batching breaks timing correlation between individual arrivals and Signal zone delivery. (5) **No auth context**: the relay has no authentication data — it cannot map an IP to an employee without compromising the Identity zone as well. |
| **Residual risk** | **Near-zero for corporate deployments** (NAT/VPN covers virtually all employees). **Low for edge cases** (remote worker on residential IP outside VPN). Even in the edge case, deanonymization requires compromising both the relay AND the Identity zone — a cross-zone attack that violates the trust model. |

#### T18: Compromised Relay Operator (Selective Denial)

| | |
|---|---|
| **Attacker** | Compromised Relay |
| **Attack** | Selectively drop or delay submissions from specific source IPs to suppress responses, skew results, or silence targeted individuals |
| **Mitigation** | (1) **Analytics anomaly detection**: unexpected drops in response rates for segments or time windows surface as statistical anomalies in the Analytics Engine. (2) **Client-side ack verification**: the client expects a `ResponseAck` — a missing ack signals a dropped submission, enabling retry or alerting. (3) **Issuance/submission reconciliation**: comparing tokens issued (Identity zone count) vs responses received (Signal zone count) reveals suppression — a significant gap is an operational red flag. (4) **Multi-relay deployment**: deploying multiple relay instances operated by different parties, with clients selecting randomly, prevents any single operator from suppressing all submissions from a target. |
| **Residual risk** | Low. Selective suppression is detectable through multiple independent channels (analytics anomalies, ack failures, issuance/submission reconciliation). A brief suppression window may go unnoticed, but sustained suppression will surface. |

---

## 4. Trust Boundary Diagram with Threats

```
                    T15: Token flood
                    T6: Org manipulation
                          |
                          v
+========================[Identity]========================+
|                                                         |
|  Identity Gateway  --  Sampling Engine  --  Token Issuer|
|       |                                        |        |
|       | T1: If compromised, has identity data  |        |
|       | but no responses                       |        |
+=============================|======================+=====+
                              |                      |
                   blinded tokens              public key
                              |                      |
                              v                      |
                     +-- [CLIENT] --+                |
                     |              |                |
                     | T4: Device   |                |
                     | compromise   |                |
                     +--------------+                |
                              |                      |
                    T2: Timing correlation            |
                    T3: IP correlation               |
                              |                      |
                              v                      |
                    +--- [RELAY] ---+                  |
                    | T14: DoS      |                  |
                    | T10: Tamper   |                  |
                    | T17: Surveil  |                  |
                    | T18: Suppress |                  |
                    +---------------+                  |
                              |                      |
                              v                      v
+========================[Signal]========================+
|                                                         |
|  Response Collector  --  Response Store  --  Analytics  |
|       |                       |                  |      |
|       | T8: Replay            | T11: Operator    |      |
|       | T9: Duplicate         |   access         |      |
|       | T16: Ledger           | T12: Cross-tenant|      |
|       |   corruption          |                  |      |
|       |                       |            T5: Small     |
|       |                       |              group      |
|       |                       |            T13: Raw     |
|       |                       |              access     |
+=========================================================+
```

---

## 5. Risk Summary

| Threat | Severity | Likelihood | Residual Risk | Primary Mitigation |
|--------|----------|-----------|---------------|-------------------|
| T1: Token/response correlation | Critical | Low | None | Blind signatures (mathematical) |
| T2: Timing correlation | High | Medium | Low | Random delays + relay batching |
| T3: IP correlation | High | Medium | Near-zero (enterprise) | Relay + NAT/VPN/CGNAT |
| T4: Behavioral fingerprinting | Medium | Medium | Medium (free-text) | Epoch rotation + k-anonymity |
| T5: Small group deanon | High | Medium | None (below k) | Issuance-time segment coarsening |
| T6: Org structure manipulation | High | Low | Low | Audit logging + policy controls |
| T7: Token forgery | Critical | Very low | None | Blind signature security |
| T8: Token replay | High | Low | None | Spent-token ledger |
| T9: Duplicate responses | Medium | Low | None | One token per assignment |
| T10: Response tampering | High | Low | Low | End-to-end integrity protection |
| T11: Operator data access | High | Medium | None | CMK envelope encryption |
| T12: Cross-tenant leakage | Critical | Very low | None | Cryptographic isolation |
| T13: Raw response exposure | Medium | Low | Tenant-configurable | Policy engine + default restrictions |
| T14: Anonymous channel DoS | Medium | Medium | Medium | Rate limiting + proof-of-work |
| T15: Token issuance flood | Low | Low | Low | Auth + rate limiting |
| T16: Ledger corruption | High | Very low | Low | Durable storage + integrity checks |
| T17: Relay operator surveillance | Medium | Medium | Near-zero (enterprise) | NAT/VPN/CGNAT + no auth context |
| T18: Relay operator selective denial | Medium | Low | Low | Analytics anomalies + ack verification + reconciliation |

---

## 6. Recommendations

1. **Cryptographic review:** The blind signature scheme selection and implementation require a dedicated security review by a cryptographer. Implementation bugs could undermine T1 mitigation.
2. **Relay hardening:** The anonymizing relay is a critical component. It should be minimal (small codebase, limited functionality), independently auditable, and operate with minimal privileges.
3. **Free-text risk advisory:** Tenants enabling free-text response types should be explicitly warned about behavioral fingerprinting risk (T4). Consider offering optional response anonymization (e.g., stripping writing style markers) as a future enhancement.
4. **K-anonymity threshold guidance:** Provide tenants with guidance on setting k values. Higher k = stronger privacy but coarser analytics. Default recommendation: k >= 5 for most organizations, k >= 10 for sensitive contexts.
5. **Audit logging:** All administrative actions (org structure changes, policy changes, campaign creation) should be immutably logged for forensic analysis of T6-type attacks.
6. **Proof-of-work calibration:** If proof-of-work is adopted for DoS mitigation (T14), the difficulty must be calibrated for the weakest supported client (IoT button). This may limit its effectiveness or require per-device-class difficulty levels.
7. **Transport tier options (future):** For high-sensitivity deployments where even the residual relay trust (T17) is unacceptable, consider optional transport tiers: multi-relay deployments (different operators, client-selected), relay chains (2+ hops), I2P garlic routing (via embeddable Rust router [emissary-core](https://github.com/altonen/emissary)), Tor hidden services (via [arti](https://gitlab.torproject.org/tpo/core/arti)), or TEE-based relay enclaves. The `pulse-client` transport trait (`HttpTransport`) is designed for this pluggability. These are defense-in-depth enhancements, not urgent — the blind signature protocol provides the primary anonymity guarantee independent of transport.
